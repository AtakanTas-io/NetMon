import "./administration.js";

let _trafficChartInstance = null;

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
        const token = S.token || localStorage.getItem("token") || "";

        // 1. Try direct disk save to Downloads / Desktop & open in Windows Explorer
        let saveResult = null;
        try {
            const saveRes = await fetch("/api/export/devices/save", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    ...(token ? { "Authorization": `Bearer ${token}` } : {})
                }
            });
            if (saveRes.ok) {
                saveResult = await saveRes.json();
            }
        } catch(e) {
            console.debug("Direct save fallback:", e);
        }

        // 2. Also trigger standard browser Blob download
        try {
            const res = await fetch(`/api/export/devices?token=${encodeURIComponent(token)}`, {
                headers: token ? { "Authorization": `Bearer ${token}` } : {}
            });
            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                const nowStr = new Date().toISOString().slice(0,10);
                a.download = `netmon_envanter_${nowStr}.csv`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            }
        } catch(e) {}

        if (saveResult && saveResult.ok) {
            toast(`✅ Excel dosyası kaydedildi: ${saveResult.saved_path} (Dosya Gezgini'nde açıldı)`, "ok");
        } else {
            toast("Envanter Excel/CSV dosyası İndirilenler klasörünüze kaydedildi.", "ok");
        }
    } catch(err) {
        toast("Dışa aktarma hatası: " + err.message, "err");
    }
};

window.openDownloadsFolder = async function() {
    try {
        const token = S.token || localStorage.getItem("token") || "";
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
  drawTrafficChart,
  copyToClipboard,
  copyBtnHtml,
  handleGlobalSearch,
  setDeviceSearch,
  setDeviceViewMode,
  setDeviceTab,
});
