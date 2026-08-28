import "./core.js";

const TOKEN_KEY = "netmon_token";

function getToken() {
  try {
    return (
      localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY) || ""
    );
  } catch (e) {
    return "";
  }
}

function setToken(token, remember) {
  try {
    if (remember === false) {
      sessionStorage.setItem(TOKEN_KEY, token || "");
      localStorage.removeItem(TOKEN_KEY);
    } else {
      localStorage.setItem(TOKEN_KEY, token || "");
    }
  } catch (e) {}
}

function clearToken() {
  try {
    localStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(TOKEN_KEY);
  } catch (e) {}
}

/* ---------- fetch yardımcıları ---------- */
async function apiFetch(path, options) {
  const opts = Object.assign({}, options);
  opts.headers = Object.assign({}, opts.headers);

  const token = getToken();
  if (token) opts.headers["Authorization"] = "Bearer " + token;

  if (opts.body && typeof opts.body !== "string") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }

  const res = await fetch(path, opts);
  if (res.status === 401) {
    clearToken();
    S.user = null;
    showLogin();
    throw new Error("Oturum sona erdi, lütfen tekrar giriş yapın.");
  }

  let data = null;
  try {
    data = await res.json();
  } catch (e) {}
  if (!res.ok)
    throw new Error(
      (data && (data.error || data.detail)) || "İstek başarısız oldu.",
    );
  return data;
}

function get(path) {
  return apiFetch(path, { method: "GET" });
}
function post(path, body) {
  return apiFetch(path, { method: "POST", body: body || {} });
}
function del(path) {
  return apiFetch(path, { method: "DELETE" });
}

/* ---------- Toast ve Modal ---------- */
function toast(message, kind) {
  const wrap = $("toasts");
  if (!wrap) return;
  const el = document.createElement("div");
  el.className = "toast " + (kind || "info");
  el.textContent = message;
  wrap.appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 300);
  }, 3200);
}

Object.assign(globalThis, {
  TOKEN_KEY,
  getToken,
  setToken,
  clearToken,
  apiFetch,
  get,
  post,
  del,
  toast,
});
