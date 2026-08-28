import "./traffic.js";

function renderNcmPage() {
  const el = $("page-ncm");
  if (!el.dataset.built) {
    el.dataset.built = "1";
    el.innerHTML = `
      <div class="panel">
        <div class="panel-head" style="flex-wrap:wrap; gap:12px;">
          <div style="display:flex;align-items:center;gap:10px">
            <span style="font-size:20px; color:#818cf8">📜</span>
            <div>
              <h2 style="margin:0">Ağ Cihazı Konfigürasyon Yedeği & Diff (NCM)</h2>
              <small style="color:var(--txt-2)">Switch & Router running-config yedekleme, sürüm geçmişi ve GitHub tarzı satır satır karşılaştırma</small>
            </div>
          </div>
          <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center;">
            <select id="ncmDeviceSelect" onchange="loadNcmDeviceVersions(this.value)" style="min-width:180px;">
              <option value="">Cihaz seçin...</option>
            </select>
            <button class="mini-btn blue" data-permission="ncm.manage" onclick="takeNcmBackup()" id="ncmBackupBtn">⚡ Şimdi Yedek Al</button>
          </div>
        </div>
        <div class="panel-body">
          <div id="ncmStatusCard" style="padding:12px 16px;border:1px solid var(--line-soft);border-radius:10px;background:var(--panel-2);margin-bottom:14px"><span class="hint">Otomatik yedekleme durumu yükleniyor…</span></div>
          <div data-permission="ncm.manage" style="background:var(--panel-2); border:1px solid var(--line-soft); border-radius:10px; padding:12px 16px; margin-bottom:16px;">
            <div style="display:grid;grid-template-columns:minmax(180px,.35fr) minmax(260px,1fr);gap:10px;align-items:start">
              <div>
                <label style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">Sürüm etiketi (isteğe bağlı)</label>
                <input id="ncmVersionLabel" placeholder="Örn. Değişiklik öncesi" style="width:100%" />
                <small style="display:block;color:var(--muted);margin-top:8px">Konfigürasyon alanı boşsa Ayarlar'daki SSH hesabı ve sistemde doğrulanmış host anahtarı kullanılır.</small>
              </div>
              <div>
                <label style="display:block;font-size:11px;color:var(--muted);margin-bottom:4px">Gerçek konfigürasyonu elle yapıştır (isteğe bağlı)</label>
                <textarea id="ncmManualConfig" rows="4" placeholder="show running-config çıktısını buraya yapıştırabilirsiniz" style="width:100%;resize:vertical"></textarea>
              </div>
            </div>
          </div>
          <div style="display:flex; flex-wrap:wrap; gap:12px; align-items:center; background:var(--panel-2); border:1px solid var(--line-soft); border-radius:10px; padding:12px 16px; margin-bottom:16px;">
            <div style="flex:1; min-width:200px">
              <label style="display:block; font-size:11px; color:var(--muted); margin-bottom:4px">1. Sürüm (Sol / Önceki)</label>
              <select id="ncmVer1Select" style="width:100%"><option value="">Yedek seçin...</option></select>
            </div>
            <div style="font-size:18px; color:var(--cyan); margin-top:14px">⇄</div>
            <div style="flex:1; min-width:200px">
              <label style="display:block; font-size:11px; color:var(--muted); margin-bottom:4px">2. Sürüm (Sağ / Sonraki)</label>
              <select id="ncmVer2Select" style="width:100%"><option value="">Yedek seçin...</option></select>
            </div>
            <button class="mini-btn blue" style="margin-top:16px; height:36px; padding:0 18px" onclick="compareNcmDiff()">🔍 Farkları Karşılaştır</button>
          </div>

          <div id="ncmDiffViewerArea">
            <div style="text-align:center; padding:40px 20px; color:var(--muted); border:1px dashed var(--line-soft); border-radius:10px">
              Yukarıdaki açılır menüden bir ağ cihazı ve karşılaştırmak istediğiniz iki konfigürasyon sürümünü seçin.
            </div>
          </div>
        </div>
      </div>
    `;
  }
}

let _ncmConfigsCache = [];
async function refreshNcm() {
  try {
    const status = await get("/api/ncm/status");
    const statusCard = $("ncmStatusCard");
    if (statusCard) statusCard.innerHTML = `<div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap"><div><b>Otomatik Konfigürasyon Yedeği</b> <span class="badge ${status.enabled&&status.ssh_account_configured?'ok':'warn'}">${status.enabled?'ETKİN':'KAPALI'}</span><div class="hint">Her ${Math.round(status.interval_seconds/3600)} saat · Son kontrolde ${status.checked||0} cihaz · ${status.changed||0} değişiklik</div></div><div><b>${status.ssh_account_configured?'SSH hesabı hazır':'SSH salt-okuma hesabı eksik'}</b><div class="hint">${esc(status.least_privilege_note)}</div>${status.can_manage?'<button class="mini-btn" onclick="go(\'settings\')">Ayarları Aç</button>':'<button class="mini-btn" onclick="go(\'access\')">Gerekli Yetkiyi Gör</button>'}</div></div>`;
    const devSelect = $("ncmDeviceSelect");
    if (devSelect) {
      const devices = S.devices || [];
      const netDevs = devices.filter(d => ["switch", "router", "firewall", "server", "access_point"].includes(d.type) || d.is_gateway);

      const currentVal = devSelect.value;
      devSelect.innerHTML = `<option value="">Cihaz seçin (${netDevs.length} Ağ Cihazı)</option>` +
        netDevs.map(d => `<option value="${esc(d.ip)}" ${d.ip === currentVal ? "selected" : ""}>${esc(d.hostname || d.friendly_name || d.ip)} (${esc(d.ip)})</option>`).join("");

      if (!currentVal && netDevs.length > 0) {
        devSelect.value = netDevs[0].ip;
        loadNcmDeviceVersions(netDevs[0].ip);
      }
    }
  } catch (e) {
    console.error("NCM refresh error:", e);
  }
}

async function loadNcmDeviceVersions(ip) {
  if (!ip) return;
  try {
    const data = await get(`/api/ncm/configs?ip=${encodeURIComponent(ip)}`);
    _ncmConfigsCache = data?.configs || [];

    const v1 = $("ncmVer1Select");
    const v2 = $("ncmVer2Select");
    if (v1 && v2) {
      if (!_ncmConfigsCache.length) {
        v1.innerHTML = `<option value="">Yedek bulunamadı (İlk yedeği alın)</option>`;
        v2.innerHTML = `<option value="">Yedek bulunamadı</option>`;
      } else {
        const opts = _ncmConfigsCache.map((c, i) =>
          `<option value="${c.id}">${esc(c.version_label)} (${esc(c.created_at_fmt)}) [${c.size_bytes} bayt]</option>`
        ).join("");
        v1.innerHTML = opts;
        v2.innerHTML = opts;

        if (_ncmConfigsCache.length >= 2) {
          v1.selectedIndex = 1;
          v2.selectedIndex = 0;
          compareNcmDiff();
        } else if (_ncmConfigsCache.length === 1) {
          v1.selectedIndex = 0;
          v2.selectedIndex = 0;
          compareNcmDiff();
        }
      }
    }
  } catch (err) {
    console.error("NCM load versions error:", err);
  }
}

async function takeNcmBackup() {
  const ipSelect = $("ncmDeviceSelect");
  const ip = ipSelect ? ipSelect.value : "";
  if (!ip) {
    toast("Lütfen önce yedek alınacak cihazı seçin.", "warn");
    return;
  }

  const btn = $("ncmBackupBtn");
  if (btn) { btn.disabled = true; btn.textContent = "Yedek Alınıyor..."; }

  try {
    const manualConfig = $("ncmManualConfig")?.value || "";
    const versionLabel = $("ncmVersionLabel")?.value || "";
    const res = await post("/api/ncm/backup", {
      ip,
      manual_config: manualConfig.trim() || null,
      version_label: versionLabel.trim() || null,
    });
    toast(`✅ ${ip} için ${res.source === "ssh" ? "SSH'den alınan" : "elle doğrulanan"} konfigürasyon kaydedildi.`, "ok");
    if ($("ncmManualConfig")) $("ncmManualConfig").value = "";
    await loadNcmDeviceVersions(ip);
  } catch (err) {
    toast(`Yedek alma başarısız: ${err.message}`, "fail");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "⚡ Şimdi Yedek Al"; }
  }
}

async function compareNcmDiff() {
  const ip = $("ncmDeviceSelect")?.value;
  const v1 = $("ncmVer1Select")?.value;
  const v2 = $("ncmVer2Select")?.value;
  const container = $("ncmDiffViewerArea");
  if (!container) return;

  if (!ip || !v1 || !v2) {
    container.innerHTML = `<div style="text-align:center; padding:20px; color:var(--muted)">Lütfen karşılaştırma için cihaz ve iki sürüm seçin.</div>`;
    return;
  }

  container.innerHTML = `<div class="skeleton-box" style="height:160px; width:100%"></div>`;

  try {
    const diffData = await get(`/api/ncm/diff?ip=${encodeURIComponent(ip)}&v1_id=${v1}&v2_id=${v2}`);
    const stats = diffData?.stats || { additions: 0, deletions: 0 };
    const lines = diffData?.diff_lines || [];

    if (!lines.length) {
      container.innerHTML = `
        <div style="text-align:center; padding:30px; background:var(--panel-2); border-radius:10px; border:1px solid var(--line-soft)">
          <span style="font-size:24px; color:#34d399">✔</span>
          <h3 style="margin:6px 0; color:#34d399">Konfigürasyonlar Birebir Aynı</h3>
          <p style="color:var(--muted); font-size:12px; margin:0">Seçilen iki sürüm arasında hiçbir fark (eklenen/çıkarılan satır) bulunmuyor.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = `
      <div class="diff-container">
        <div class="diff-header-bar">
          <div style="display:flex; align-items:center; gap:10px">
            <span style="font-weight:700; color:var(--txt)">${esc(diffData.v1?.label)} ➔ ${esc(diffData.v2?.label)}</span>
            <div class="diff-stats">
              <span class="diff-badge-add">+${stats.additions} satır eklendi</span>
              <span class="diff-badge-del">-${stats.deletions} satır çıkarıldı</span>
            </div>
          </div>
          <button class="mini-btn" onclick="copyDiffToClipboard()">📋 Farkları Kopyala</button>
        </div>
        <div style="max-height:480px; overflow-y:auto; padding:4px 0" id="ncmDiffLinesWrap">
          ${lines.map(l => {
            let cls = "";
            let prefix = " ";
            if (l.type === "add") { cls = "diff-add"; prefix = "+"; }
            else if (l.type === "delete") { cls = "diff-del"; prefix = "-"; }
            else if (l.type === "chunk_header") { cls = "diff-hunk"; }

            return `
              <div class="diff-line ${cls}">
                <span class="diff-num">${l.old_ln || ""}</span>
                <span class="diff-num">${l.new_ln || ""}</span>
                <span class="diff-content">${prefix} ${esc(l.content)}</span>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div style="text-align:center; padding:20px; color:#f87171">Diff karşılaştırması alınamadı: ${esc(err.message)}</div>`;
  }
}

function copyDiffToClipboard() {
  const wrap = $("ncmDiffLinesWrap");
  if (wrap) {
    copyText(wrap.innerText);
  }
}

Object.assign(globalThis, {
  renderNcmPage,
  _ncmConfigsCache,
  refreshNcm,
  loadNcmDeviceVersions,
  takeNcmBackup,
  compareNcmDiff,
  copyDiffToClipboard,
});
