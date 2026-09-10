import "./administration.js";

let _trafficChartInstance = null;
let _networkQualityChartInstance = null;
S.visibilityRange = S.visibilityRange || "24h";

function drawTrafficChart() {
  const canvas = $("trafficChart");
  if (!canvas || typeof Chart === "undefined") return;

  const hasSamples = S.sparkUp.length > 1 || S.sparkDown.length > 1;
  let empty = $("trafficEmptyState");
  if (!hasSamples) {
    canvas.style.display = "none";
    if (!empty) {
      empty = document.createElement("div");
      empty.id = "trafficEmptyState";
      empty.className = "hint";
      empty.style.cssText = "height:150px;display:grid;place-items:center;text-align:center;border:1px dashed var(--line-soft);border-radius:10px";
      empty.innerHTML = "Trafik örneği henüz oluşmadı.<br><small>İlk iki telemetri ölçümünden sonra grafik otomatik görüntülenecek.</small>";
      canvas.parentNode.insertBefore(empty, canvas.nextSibling);
    }
    return;
  }
  canvas.style.display = "block";
  if (empty) empty.remove();

  const labels = S.sparkUp.map((_, i) => {
    const ts = Number(S.sparkTs[i] || 0);
    return ts ? new Date(ts * 1000).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
  });

  if (_trafficChartInstance) {
    _trafficChartInstance.data.labels = labels;
    _trafficChartInstance.data.datasets[0].data = S.sparkUp;
    _trafficChartInstance.data.datasets[1].data = S.sparkDown;
    _trafficChartInstance.update("none");
    return;
  }

  const ctx = canvas.getContext("2d");
  const gradUp = ctx.createLinearGradient(0, 0, 0, 150);
  gradUp.addColorStop(0, "rgba(61, 220, 132, 0.4)");
  gradUp.addColorStop(1, "rgba(61, 220, 132, 0.05)");

  const gradDown = ctx.createLinearGradient(0, 0, 0, 150);
  gradDown.addColorStop(0, "rgba(59, 155, 255, 0.4)");
  gradDown.addColorStop(1, "rgba(59, 155, 255, 0.05)");

  _trafficChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Upload (Mbps)",
          data: S.sparkUp,
          borderColor: "#3ddc84",
          backgroundColor: gradUp,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        },
        {
          label: "Download (Mbps)",
          data: S.sparkDown,
          borderColor: "#3b9bff",
          backgroundColor: gradDown,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: {
          display: true,
          grid: { display: false },
          ticks: { color: "#64748b", maxTicksLimit: 6, maxRotation: 0 },
        },
        y: {
          beginAtZero: true,
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#93a4bd" },
        },
      },
      plugins: {
        legend: { labels: { color: "#e7eefb" } },
        tooltip: { backgroundColor: "rgba(13, 22, 38, 0.95)" },
      },
    },
  });
}

function visibilityValue(value, suffix, digits = 1) {
  if (value == null || Number.isNaN(Number(value))) return "Ölçülmedi";
  return `${Number(value).toFixed(digits)}${suffix}`;
}

function drawNetworkQualityChart(points) {
  const canvas = $("networkQualityChart");
  if (!canvas || typeof Chart === "undefined") return;
  let empty = $("networkQualityEmptyState");
  if (!points.length) {
    canvas.style.display = "none";
    if (!empty) {
      empty = document.createElement("div");
      empty.id = "networkQualityEmptyState";
      empty.className = "load-state";
      empty.innerHTML = "<b>Henüz kalite trendi yok</b><span>Periyodik tanı görevi en az bir gerçek ölçüm kaydettiğinde grafik oluşacak.</span>";
      canvas.parentNode.appendChild(empty);
    }
    if (_networkQualityChartInstance) {
      _networkQualityChartInstance.destroy();
      _networkQualityChartInstance = null;
    }
    return;
  }
  canvas.style.display = "block";
  if (empty) empty.remove();
  const labels = points.map((point) => new Date(Number(point.ts) * 1000).toLocaleString("tr-TR", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }));
  const data = {
    labels,
    datasets: [
      {
        label: "İnternet RTT (ms)",
        data: points.map((point) => point.internet_latency_ms),
        borderColor: "#8b5cf6",
        backgroundColor: "rgba(139,92,246,.12)",
        yAxisID: "latency",
        fill: true,
        tension: 0.25,
        pointRadius: 0,
        borderWidth: 2,
      },
      {
        label: "Gateway RTT (ms)",
        data: points.map((point) => point.gateway_latency_ms),
        borderColor: "#38bdf8",
        yAxisID: "latency",
        tension: 0.25,
        pointRadius: 0,
        borderWidth: 1.5,
      },
      {
        label: "Paket kaybı (%)",
        data: points.map((point) => point.packet_loss_pct),
        borderColor: "#ef4444",
        backgroundColor: "rgba(239,68,68,.08)",
        yAxisID: "loss",
        tension: 0.2,
        pointRadius: 0,
        borderWidth: 1.5,
      },
    ],
  };
  if (_networkQualityChartInstance) {
    _networkQualityChartInstance.data = data;
    _networkQualityChartInstance.update("none");
    return;
  }
  _networkQualityChartInstance = new Chart(canvas.getContext("2d"), {
    type: "line",
    data,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: { grid: { display: false }, ticks: { color: "#64748b", maxTicksLimit: 8, maxRotation: 0 } },
        latency: {
          beginAtZero: true,
          position: "left",
          title: { display: true, text: "ms", color: "#94a3b8" },
          grid: { color: "rgba(255,255,255,.05)" },
          ticks: { color: "#94a3b8" },
        },
        loss: {
          beginAtZero: true,
          suggestedMax: 100,
          position: "right",
          title: { display: true, text: "% kayıp", color: "#f87171" },
          grid: { drawOnChartArea: false },
          ticks: { color: "#f87171" },
        },
      },
      plugins: { legend: { labels: { color: "#e7eefb" } } },
    },
  });
}

function renderSecurityScore(security) {
  const container = $("dashboardSecurityScore");
  if (!container) return;
  const score = Math.max(0, Math.min(100, Number(security.score || 0)));
  const color = score >= 85 ? "var(--green)" : score >= 65 ? "var(--orange)" : "var(--red)";
  const deductions = security.deductions || [];
  container.innerHTML = `<div class="score-layout">
    <div class="security-score-ring" style="--score:${score};--score-color:${color}"><div><b style="color:${color}">${score}</b><span>${esc(security.label || "-")}</span></div></div>
    <div class="score-deductions">
      ${deductions.slice(0, 4).map((item) => `<div class="score-deduction"><span>${esc(item.label)} <small>(${Number(item.count || 0)})</small></span><b>-${Number(item.points || 0)}</b></div>`).join("") || '<div class="hint">Skoru düşüren doğrulanmış bir kanıt bulunmadı.</div>'}
      <div class="hint">${Number(security.assets_evaluated || 0)} cihaz · ${Number(security.findings_count || 0)} bulgu</div>
    </div>
  </div>`;
}

function renderCertificateDhcp(certificates, dhcp) {
  const container = $("dashboardCertificateDhcp");
  if (!container) return;
  const attention = certificates.attention || [];
  const dhcpState = dhcp.error ? "Hata" : dhcp.running ? "Dinliyor" : "Çalışmıyor";
  const dhcpColor = dhcp.error || !dhcp.running ? "var(--orange)" : dhcp.rogue_detected_count ? "var(--red)" : "var(--green)";
  container.innerHTML = `<div class="attention-grid">
    <section class="attention-card">
      <header><b>SSL Sertifikaları</b><span>${Number(certificates.total || 0)} kayıt</span></header>
      <div class="hint" style="margin-bottom:6px"><b style="color:var(--red)">${Number(certificates.expired || 0)} süresi dolmuş</b> · ${Number(certificates.expiring_30d || 0)} yakında dolacak</div>
      ${attention.slice(0, 3).map((cert) => `<div class="attention-item"><span>${esc(cert.hostname || cert.ip || "Bilinmeyen")}</span><b style="color:${Number(cert.days_left) < 0 ? "var(--red)" : "var(--orange)"}">${Number(cert.days_left)} gün</b></div>`).join("") || '<div class="hint">30 gün içinde sona erecek sertifika yok.</div>'}
    </section>
    <section class="attention-card">
      <header><b>DHCP İzleyicisi</b><span style="color:${dhcpColor}">${dhcpState}</span></header>
      <div class="attention-item"><span>Yetkili sunucu</span><b>${Number(dhcp.authorized_server_count || 0)}</b></div>
      <div class="attention-item"><span>Rogue teklif</span><b style="color:${dhcp.rogue_detected_count ? "var(--red)" : "var(--green)"}">${Number(dhcp.rogue_detected_count || 0)}</b></div>
      ${dhcp.last_rogue_source ? `<div class="hint">Son yetkisiz kaynak: <b>${esc(dhcp.last_rogue_source)}</b></div>` : `<div class="hint">${esc(dhcp.pool_note || "DHCP olayı bekleniyor.")}</div>`}
    </section>
  </div>`;
}

async function refreshPhase2Visibility() {
  const container = $("networkQualitySummary");
  if (!container) return;
  try {
    const data = await get(`/api/visibility/summary?range=${encodeURIComponent(S.visibilityRange || "24h")}`);
    S.visibilitySummary = data;
    const quality = data.network_quality || {};
    const stats = quality.stats || {};
    container.innerHTML = [
      ["Ortalama RTT", visibilityValue(stats.average_latency_ms, " ms")],
      ["Jitter", visibilityValue(stats.jitter_ms, " ms")],
      ["Paket kaybı", visibilityValue(stats.average_packet_loss_pct, "%")],
      ["Örnek", String(Number(stats.samples || 0))],
    ].map(([label, value]) => `<div><span>${label}</span><b>${value}</b></div>`).join("");
    const source = $("networkQualitySource");
    if (source) source.textContent = `${quality.source || "Tanı snapshot'ları"} · en fazla 240 nokta`;
    drawNetworkQualityChart(quality.points || []);
    renderSecurityScore(data.security || {});
    renderCertificateDhcp(data.certificates || {}, data.dhcp || {});
  } catch (error) {
    renderLoadError(container, "Faz 2 görünürlük verisi yüklenemedi", error, "refreshPhase2Visibility()");
  }
}

function setVisibilityRange(range) {
  if (!["1h", "24h", "7d"].includes(range)) return;
  S.visibilityRange = range;
  document.querySelectorAll("#networkQualityRange button").forEach((button) => {
    button.classList.toggle("blue", button.getAttribute("onclick")?.includes(`'${range}'`));
  });
  refreshPhase2Visibility();
}

S.deviceTab = S.deviceTab || "all";
S.deviceViewMode = S.deviceViewMode || "table";

function copyToClipboard(text, btn) {
  if (!text) return;
  const doCopy = () => {
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
      btn.style.borderColor = "var(--green)";
      btn.style.color = "var(--green)";
      setTimeout(() => {
        btn.innerHTML = orig;
        btn.style.borderColor = "";
        btn.style.color = "";
      }, 1500);
    }
    toast(`Kopyalandı: ${text}`, "success");
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(doCopy).catch(doCopy);
  } else {
    doCopy();
  }
}

function copyBtnHtml(text) {
  if (!text) return "";
  return `<button class="copy-btn" onclick="copyToClipboard('${esc(text)}', this)" title="Kopyala: ${esc(text)}">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
  </button>`;
}

function handleGlobalSearch(query) {
  const q = (query || "").trim();
  if (S.page !== "devices") {
    go("devices");
  }
  const filter = $("devFilter");
  if (filter) {
    filter.value = q;
    renderDeviceTable();
  }
}

function setDeviceSearch(ip) {
  if (!ip) return;
  inspectDevice(ip);
}
window.setDeviceSearch = setDeviceSearch;

function setDeviceViewMode(mode) {
  S.deviceViewMode = mode;
  const page = $("page-devices");
  if (page) page.dataset.built = "";
  renderDevicesPage();
}

function setDeviceTab(tab) {
  S.deviceTab = tab;
  const page = $("page-devices");
  if (page) page.dataset.built = "";
  renderDevicesPage();
}


window.downloadRdp = async function(ip) {
    if(!ip) return toast("IP adresi bulunamadı", "error");
    try {
        const res = await fetch(`/api/tools/rdp?ip=${encodeURIComponent(ip)}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${S.token}` }
        });
        const data = await res.json();
        if(!res.ok) throw new Error(data.error || "RDP başlatılamadı.");
        toast(data.message || "RDP Başlatıldı.", "success");
    } catch(err) {
        toast(err.message, "error");
    }
};

window.exportDevicesExcel = async function() {
    try {
        const token = getToken();
        if (!token) throw new Error("Oturum bulunamadı. Yeniden giriş yapın.");
        const saveRes = await fetch("/api/export/devices/save", {
            method: "POST",
            headers: {"Authorization": `Bearer ${token}`}
        });
        const saveResult = await saveRes.json().catch(() => ({}));
        if (!saveRes.ok || !saveResult.ok || !saveResult.saved_path) {
            throw new Error(saveResult.message || saveResult.error || "Excel dosyası kaydedilemedi.");
        }
        recordDownload(saveResult);
        toast(`Excel kaydedildi: ${saveResult.saved_path} · ${saveResult.count} cihaz`, "ok");
    } catch(err) {
        toast("Dışa aktarma hatası: " + err.message, "err");
    }
};

window.openDownloadsFolder = async function() {
    try {
        const token = getToken();
        if (!token) throw new Error("Oturum bulunamadı. Yeniden giriş yapın.");
        const res = await fetch("/api/tools/open-downloads", {
            method: "POST",
            headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        if (res.ok) {
            toast("📁 İndirilenler klasörü açıldı.", "ok");
        } else {
            toast("Klasör açılamadı.", "err");
        }
    } catch(e) {
        toast("Hata: " + e.message, "err");
    }
};

Object.assign(globalThis, {
  _trafficChartInstance,
  _networkQualityChartInstance,
  drawTrafficChart,
  drawNetworkQualityChart,
  refreshPhase2Visibility,
  setVisibilityRange,
  copyToClipboard,
  copyBtnHtml,
  handleGlobalSearch,
  setDeviceSearch,
  setDeviceViewMode,
  setDeviceTab,
});
