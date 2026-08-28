import "./api.js";

function openModal(html) {
  const back = $("modalBack");
  const box = $("modalBox");
  if (!back || !box) return;
  box.innerHTML = html;
  back.classList.remove("open");
  back.classList.add("show");
}

function closeModal(event) {
  closeModalForce();
}
function closeModalForce() {
  const back = $("modalBack");
  if (back?.dataset?.locked === "1") return;
  if (back) {
    back.classList.remove("show");
    back.classList.remove("open");
  }
}

/* ---------- Giriş / Çıkış ---------- */
function showLogin() {
  const screen = $("loginScreen");
  const app = $("app");
  if (screen) screen.style.display = "grid";
  if (app) app.classList.add("auth-hidden");
}

function hideLogin() {
  const screen = $("loginScreen");
  const app = $("app");
  if (screen) screen.style.display = "none";
  if (app) app.classList.remove("auth-hidden");
}

async function logout() {
  try {
    await post("/api/auth/logout", {});
  } catch (e) {}
  clearToken();
  S.user = null;
  try {
    if (typeof stopAutoRefresh === "function") stopAutoRefresh();
    if (networkSocket) networkSocket.close();
  } catch (e) {}
  const modalBack = $("modalBack");
  if (modalBack) modalBack.dataset.locked = "0";
  closeModalForce();
  showLogin();
}

function openProfile() {
  if (!S.user) return;
  const isAdmin = S.user.role === "admin";
  const permissionCount = (S.user.permissions || []).includes("*") ? "Tüm" : (S.user.permissions || []).length;
  openModal(`
    <h3>${esc(S.user.username || "Kullanıcı")}</h3>
    <div class="sub">${esc(currentRoleLabel())}</div>
    <div style="display:flex;gap:9px;align-items:flex-start;margin-top:12px;padding:10px 11px;border:1px solid ${isAdmin ? "rgba(139,92,246,.4)" : "var(--line)"};border-radius:9px;background:${isAdmin ? "rgba(91,33,182,.1)" : "var(--panel-2)"}">
      <span style="color:${isAdmin ? "#a78bfa" : "var(--blue)"}">${ico(isAdmin ? "shield" : "users", 17)}</span>
      <div><b style="display:block;font-size:10px">${isAdmin ? "Yönetici modu etkin" : `${esc(currentRoleLabel())} rolü etkin`}</b><span style="display:block;color:var(--muted);font-size:9px;margin-top:2px;line-height:1.4">Bu oturumda ${permissionCount} operasyon izni tanımlı. Backend her hassas işlemde izni ayrıca doğrular.</span></div>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:18px;">
      <button class="mini-btn" onclick="closeModalForce()">Kapat</button>
      <button class="mini-btn" onclick="openPasswordChangeModal(false)">Parolayı Değiştir</button>
      <button class="mini-btn blue" onclick="logout()">${ico("logout", 14)} Çıkış Yap</button>
    </div>
  `);
}

function openPasswordChangeModal(forced = false) {
  openModal(`
    <h3>${forced ? "Güvenlik için parola değişikliği gerekli" : "Parolayı Değiştir"}</h3>
    <div class="sub">Yeni parola en az 12 karakter olmalıdır.</div>
    <div class="field-label" style="margin-top:12px">Mevcut Parola</div>
    <input id="currentPassword" type="password" autocomplete="current-password" />
    <div class="field-label" style="margin-top:10px">Yeni Parola</div>
    <input id="newPassword" type="password" autocomplete="new-password" />
    <div class="field-label" style="margin-top:10px">Yeni Parola (Tekrar)</div>
    <input id="newPasswordAgain" type="password" autocomplete="new-password" />
    <div id="passwordChangeError" class="hint c-red" style="margin-top:8px"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
      ${forced ? "" : '<button class="mini-btn" onclick="closeModalForce()">İptal</button>'}
      <button class="mini-btn blue" onclick="submitPasswordChange()">Parolayı Kaydet</button>
    </div>
  `);
  const back = $("modalBack");
  if (back) back.dataset.locked = forced ? "1" : "0";
}

async function submitPasswordChange() {
  const currentPassword = $("currentPassword")?.value || "";
  const newPassword = $("newPassword")?.value || "";
  const again = $("newPasswordAgain")?.value || "";
  const error = $("passwordChangeError");
  if (newPassword.length < 12) {
    if (error) error.textContent = "Yeni parola en az 12 karakter olmalıdır.";
    return;
  }
  if (newPassword !== again) {
    if (error) error.textContent = "Yeni parolalar eşleşmiyor.";
    return;
  }
  try {
    await post("/api/auth/change-password", { current_password: currentPassword, new_password: newPassword });
    if (S.user) S.user.must_change_password = false;
    const back = $("modalBack");
    if (back) back.dataset.locked = "0";
    closeModalForce();
    toast("Parola güvenli biçimde değiştirildi.", "success");
    boot();
  } catch (e) {
    if (error) error.textContent = e.message || "Parola değiştirilemedi.";
  }
}

function applyRolePermissions() {
  const isAdmin = S.user && S.user.role === "admin";
  const app = $("app");
  if (app) {
    app.classList.toggle("admin-mode", Boolean(isAdmin));
    app.dataset.role = isAdmin ? "admin" : "user";
  }
  document.querySelectorAll(".admin-only").forEach((el) => {
    el.style.display = isAdmin ? "" : "none";
  });
  document.querySelectorAll("[data-permission]").forEach((el) => {
    el.style.display = hasPermission(el.dataset.permission) ? "" : "none";
  });
  const nameEl = $("userName");
  const roleEl = $("userRole");
  if (nameEl) nameEl.textContent = S.user ? S.user.username : "-";
  if (roleEl) roleEl.textContent = currentRoleLabel();
  const adminBadge = $("adminModeBadge");
  const adminIcon = $("adminModeIcon");
  if (adminBadge) adminBadge.setAttribute("aria-label", isAdmin ? `${S.user?.username || ""} yönetici modunda` : "Standart kullanıcı modu");
  if (adminIcon) adminIcon.innerHTML = ico("shield", 12);
}

function renderLoadError(targetOrId, title, error, retryCall = "") {
  const target = typeof targetOrId === "string" ? $(targetOrId) : targetOrId;
  if (!target) return;
  const message = error?.message || String(error || "Bilinmeyen hata");
  target.innerHTML = `<div class="load-state error" role="alert">
    <b>${esc(title || "Veri alınamadı")}</b>
    <span>${esc(message)}</span>
    ${retryCall ? `<button class="mini-btn" onclick="${retryCall}">Tekrar Dene</button>` : ""}
  </div>`;
}

const ROLE_LABELS = {
  admin: "Sistem Yöneticisi",
  noc_operator: "NOC Operatörü",
  inventory_specialist: "Envanter Uzmanı",
  security_analyst: "Güvenlik Analisti",
  viewer: "Salt Okunur",
  user: "Standart Kullanıcı",
};

function hasPermission(permission) {
  const permissions = Array.isArray(S.user?.permissions) ? S.user.permissions : [];
  return S.user?.role === "admin" || permissions.includes("*") || permissions.includes(permission);
}

function currentRoleLabel() {
  return S.user?.role_label || ROLE_LABELS[S.user?.role] || "Kullanıcı";
}

/* ---------- Navigasyon ---------- */

Object.assign(globalThis, {
  openModal,
  closeModal,
  closeModalForce,
  showLogin,
  hideLogin,
  logout,
  openProfile,
  openPasswordChangeModal,
  submitPasswordChange,
  applyRolePermissions,
  renderLoadError,
  ROLE_LABELS,
  hasPermission,
  currentRoleLabel,
});
