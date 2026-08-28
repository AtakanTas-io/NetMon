"""Kimlik doğrulama, oturum ve kullanıcı yönetimi uçları."""

import re
import secrets
import sqlite3
import time

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str
    remember: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    role: str | None = None
    active: bool | None = None
    new_password: str | None = None


def _valid_username(value: str) -> bool:
    return bool(re.fullmatch(r"[\w.@\\-]{3,64}", (value or "").strip(), re.UNICODE))


def _check_login_lock(conn, username: str) -> float | None:
    row = conn.execute(
        "SELECT fail_count, locked_until FROM login_attempts WHERE username=?", (username,)
    ).fetchone()
    if row is None:
        return None
    _, locked_until = row
    if locked_until and time.time() < locked_until:
        return locked_until - time.time()
    return None


def _register_login_failure(ctx, conn, username: str):
    row = conn.execute(
        "SELECT fail_count FROM login_attempts WHERE username=?", (username,)
    ).fetchone()
    fail_count = (row[0] if row else 0) + 1
    locked_until = time.time() + ctx.LOGIN_LOCKOUT_SECONDS if fail_count >= ctx.LOGIN_MAX_ATTEMPTS else None
    conn.execute(
        "INSERT INTO login_attempts (username, fail_count, last_attempt, locked_until) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET fail_count=excluded.fail_count, "
        "last_attempt=excluded.last_attempt, locked_until=excluded.locked_until",
        (username, fail_count, time.time(), locked_until),
    )
    conn.commit()


def _clear_login_failures(conn, username: str):
    conn.execute("DELETE FROM login_attempts WHERE username=?", (username,))
    conn.commit()


def create_auth_router(ctx) -> APIRouter:
    """Geçiş sürecinde ortak servisleri ana modülden alan auth router'ını kur."""
    router = APIRouter()

    @router.post("/api/auth/login")
    def api_login(body: LoginRequest):
        if not _valid_username(body.username) or not body.password or len(body.password) > 512:
            return JSONResponse(status_code=401, content={"error": "Kullanıcı adı veya şifre hatalı."})
        body.username = body.username.strip()
        conn = ctx.db_conn()

        remaining = _check_login_lock(conn, body.username)
        if remaining is not None:
            conn.close()
            ctx._audit(body.username, "login", "kilitli hesapla giriş denemesi", success=False)
            return JSONResponse(
                status_code=429,
                content={"error": f"Çok fazla başarısız deneme. {int(remaining // 60) + 1} dakika sonra tekrar deneyin."},
            )

        row = conn.execute(
            "SELECT id, username, password_hash, salt, role, active, must_change_password FROM users WHERE username=?",
            (body.username,),
        ).fetchone()

        ad_success = False
        ad_server = None
        try:
            settings = dict(conn.execute("SELECT key, value FROM settings").fetchall())
            ad_server = settings.get("ad_server")
            ad_domain = settings.get("ad_domain")
            if ad_server and ad_domain:
                from ldap3 import ALL, Connection, Server

                if "\\" in body.username:
                    u_clean = body.username.split("\\", 1)[1]
                    user_dn = f"{u_clean}@{ad_domain}"
                elif "@" in body.username:
                    user_dn = body.username
                else:
                    user_dn = f"{body.username}@{ad_domain}"
                directory_server = Server(ad_server, get_info=ALL, connect_timeout=2)
                connection = Connection(directory_server, user=user_dn, password=body.password, auto_bind=True)
                connection.unbind()
                ad_success = True
                if row is None:
                    new_salt = secrets.token_urlsafe(16)
                    new_hash = ctx._hash_password(secrets.token_urlsafe(32), new_salt)
                    conn.execute(
                        "INSERT INTO users (username, password_hash, salt, role, created_at, must_change_password) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (body.username, new_hash, new_salt, "viewer", time.time(), 0),
                    )
                    conn.commit()
                    row = conn.execute(
                        "SELECT id, username, password_hash, salt, role, active, must_change_password "
                        "FROM users WHERE username=?",
                        (body.username,),
                    ).fetchone()
        except Exception as exc:
            ctx.logger.warning(
                "AD girişi denendi, başarısız; sunucu=%s hata_türü=%s",
                ad_server or "yapılandırılmadı",
                type(exc).__name__,
            )

        if row is None:
            _register_login_failure(ctx, conn, body.username)
            conn.close()
            ctx._audit(body.username, "login", "kullanıcı bulunamadı", success=False)
            return JSONResponse(status_code=401, content={"error": "Kullanıcı adı veya şifre hatalı."})

        uid, username, pw_hash, salt, role, active, must_change_password = row
        if not active:
            conn.close()
            ctx._audit(username, "login", "devre dışı hesap", success=False)
            return JSONResponse(status_code=403, content={"error": "Bu hesap devre dışı bırakılmış."})
        if not ad_success and not ctx._verify_password(body.password, salt, pw_hash):
            _register_login_failure(ctx, conn, body.username)
            conn.close()
            ctx._audit(username, "login", "yanlış şifre", success=False)
            return JSONResponse(status_code=401, content={"error": "Kullanıcı adı veya şifre hatalı."})

        _clear_login_failures(conn, username)
        token = secrets.token_urlsafe(32)
        created_at = time.time()
        ttl = 30 * 24 * 3600 if body.remember else ctx.SESSION_TTL_SECONDS
        expires_at = created_at + ttl
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, uid, created_at, expires_at),
        )
        conn.commit()
        conn.close()
        ctx._audit(username, "login", "başarılı giriş", success=True)
        return {
            "ok": True,
            "token": token,
            "user": {
                "username": username,
                "role": role,
                "role_label": ctx._role_definition(role)["label"],
                "permissions": ctx._role_permissions(role),
                "must_change_password": bool(must_change_password),
            },
        }

    @router.post("/api/auth/logout")
    def api_logout(authorization: str | None = Header(default=None)):
        if authorization and authorization.startswith("Bearer "):
            token = authorization.removeprefix("Bearer ").strip()
            conn = ctx.db_conn()
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            conn.commit()
            conn.close()
        return {"ok": True}

    @router.get("/api/auth/me")
    def api_me(user: dict = Depends(ctx.get_current_user)):
        return {
            "username": user["username"],
            "role": user["role"],
            "role_label": user.get("role_label"),
            "permissions": user.get("permissions", []),
            "must_change_password": user.get("must_change_password", False),
        }

    @router.post("/api/auth/change-password")
    def api_change_password(body: ChangePasswordRequest, user: dict = Depends(ctx.get_current_user)):
        if not 12 <= len(body.new_password) <= 512:
            return JSONResponse(status_code=400, content={"error": "Yeni parola 12-512 karakter arasında olmalıdır."})
        if body.new_password == body.current_password:
            return JSONResponse(status_code=400, content={"error": "Yeni parola mevcut paroladan farklı olmalıdır."})
        conn = ctx.db_conn()
        row = conn.execute("SELECT password_hash, salt FROM users WHERE id=?", (user["id"],)).fetchone()
        if not row or not ctx._verify_password(body.current_password, row[1], row[0]):
            conn.close()
            ctx._audit(user["username"], "password_change", "mevcut parola yanlış", success=False)
            return JSONResponse(status_code=401, content={"error": "Mevcut parola yanlış."})
        salt, password_hash = ctx._hash_password(body.new_password)
        conn.execute(
            "UPDATE users SET password_hash=?, salt=?, must_change_password=0 WHERE id=?",
            (password_hash, salt, user["id"]),
        )
        conn.execute("DELETE FROM sessions WHERE user_id=? AND token<>?", (user["id"], user["token"]))
        conn.commit()
        conn.close()
        try:
            if ctx.INITIAL_PASSWORD_PATH.exists():
                ctx.INITIAL_PASSWORD_PATH.unlink()
        except OSError:
            ctx.logger.warning("İlk kurulum parola dosyası silinemedi: %s", ctx.INITIAL_PASSWORD_PATH)
        ctx._audit(user["username"], "password_change", "parola değiştirildi", success=True)
        return {"ok": True}

    @router.get("/api/admin/roles")
    def api_list_roles(user: dict = Depends(ctx.require_permission("users.manage"))):
        order = ("admin", "noc_operator", "inventory_specialist", "security_analyst", "viewer")
        return {
            "roles": [
                {"id": role, "label": ctx.ROLE_DEFINITIONS[role]["label"], "permissions": ctx._role_permissions(role)}
                for role in order
            ]
        }

    @router.get("/api/admin/users")
    def api_list_users(user: dict = Depends(ctx.require_permission("users.manage"))):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT id, username, role, active, must_change_password FROM users ORDER BY id"
        ).fetchall()
        conn.close()
        return {"users": [ctx._row_to_user(row) for row in rows]}

    @router.post("/api/admin/users")
    def api_create_user(body: CreateUserRequest, user: dict = Depends(ctx.require_permission("users.manage"))):
        body.username = body.username.strip()
        if not _valid_username(body.username):
            return JSONResponse(status_code=400, content={"error": "Kullanıcı adı 3-64 karakter olmalı; harf, sayı, nokta, @, _ veya - içerebilir."})
        if body.role not in ctx.ROLE_DEFINITIONS:
            return JSONResponse(status_code=400, content={"error": "Geçersiz rol."})
        if not 12 <= len(body.password) <= 512:
            return JSONResponse(status_code=400, content={"error": "Şifre 12-512 karakter arasında olmalı."})

        salt, pw_hash = ctx._hash_password(body.password)
        conn = ctx.db_conn()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, active, must_change_password, created_at) "
                "VALUES (?, ?, ?, ?, 1, 1, ?)",
                (body.username, pw_hash, salt, body.role, time.time()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return JSONResponse(status_code=409, content={"error": "Bu kullanıcı adı zaten var."})
        conn.close()
        ctx._audit(user["username"], "user_create", f"yeni kullanıcı: {body.username} ({body.role})")
        return {"ok": True}

    @router.post("/api/admin/users/{user_id}")
    def api_update_user(user_id: int, body: UpdateUserRequest, user: dict = Depends(ctx.require_permission("users.manage"))):
        conn = ctx.db_conn()
        target = conn.execute("SELECT id, role, active FROM users WHERE id=?", (user_id,)).fetchone()
        if target is None:
            conn.close()
            return JSONResponse(status_code=404, content={"error": "Kullanıcı bulunamadı."})
        if ((body.role is not None and body.role != "admin") or body.active is False) and target[1] == "admin" and bool(target[2]):
            admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
            if admin_count <= 1:
                conn.close()
                return JSONResponse(status_code=400, content={"error": "Son admin hesabı devre dışı bırakılamaz veya rütbesi düşürülemez."})
        if body.role is not None:
            if body.role not in ctx.ROLE_DEFINITIONS:
                conn.close()
                return JSONResponse(status_code=400, content={"error": "Geçersiz rol."})
            conn.execute("UPDATE users SET role=? WHERE id=?", (body.role, user_id))
        if body.active is not None:
            conn.execute("UPDATE users SET active=? WHERE id=?", (1 if body.active else 0, user_id))
            if not body.active:
                conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        if body.new_password is not None:
            if not 12 <= len(body.new_password) <= 512:
                conn.close()
                return JSONResponse(status_code=400, content={"error": "Şifre 12-512 karakter arasında olmalı."})
            salt, pw_hash = ctx._hash_password(body.new_password)
            conn.execute(
                "UPDATE users SET password_hash=?, salt=?, must_change_password=1 WHERE id=?",
                (pw_hash, salt, user_id),
            )
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()
        audit_changes = body.model_dump(exclude_none=True)
        if "new_password" in audit_changes:
            audit_changes["new_password"] = "***"
        ctx._audit(user["username"], "user_update", f"user_id={user_id}: {audit_changes}")
        return {"ok": True}

    @router.delete("/api/admin/users/{user_id}")
    def api_delete_user(user_id: int, user: dict = Depends(ctx.require_permission("users.manage"))):
        conn = ctx.db_conn()
        target = conn.execute("SELECT role, active FROM users WHERE id=?", (user_id,)).fetchone()
        if target is None:
            conn.close()
            return JSONResponse(status_code=404, content={"error": "Kullanıcı bulunamadı."})
        if target[0] == "admin" and bool(target[1]):
            admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
            if admin_count <= 1:
                conn.close()
                return JSONResponse(status_code=400, content={"error": "Son admin hesabı silinemez."})
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        ctx._audit(user["username"], "user_delete", f"user_id={user_id}")
        return {"ok": True}

    @router.get("/api/admin/audit-log")
    def api_audit_log(limit: int = 200, user: dict = Depends(ctx.require_permission("users.manage"))):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT ts, username, action, detail, success FROM audit_log ORDER BY ts DESC LIMIT ?",
            (min(max(limit, 1), 1000),),
        ).fetchall()
        conn.close()
        return {
            "entries": [
                {"ts": row[0], "username": row[1], "action": row[2], "detail": row[3], "success": bool(row[4])}
                for row in rows
            ]
        }

    return router
