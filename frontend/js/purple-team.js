import "./academy.js";

let _purpleSimTimer = null;

function renderPurpleTeamPage() {
  const el = $("page-purpleteam");
  if (!el) return;
  if (el.dataset.built) return;
  el.dataset.built = "1";

  el.innerHTML = `
    <!-- HEADER & SKOR PANELERİ -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:12px;margin-bottom:14px">

      <!-- NOC PANELS -->
      <div class="panel" style="border-left:4px solid var(--blue)">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:20px">📡</span>
            <div>
              <h3 style="margin:0;font-size:14px;color:var(--blue)">NOC (Ağ Operasyon Merkezi)</h3>
              <div style="font-size:10.5px;color:var(--muted)">Network Operations Center — Trafik & Performans</div>
            </div>
          </div>
          <span class="badge info" id="nocStatusBadge">Aktif İzleme</span>
        </div>
        <div class="panel-body" style="font-size:12px">
          <div class="kv"><span>Aktif Bağlantı Hızı</span><b id="nocBwVal">Ölçüm bekleniyor</b></div>
          <div class="kv"><span>24 Saat Erişilebilirlik</span><b id="nocAvailabilityVal">Yeterli örnek yok</b></div>
          <div class="kv"><span>Router / Switch / AP</span><b id="nocNodesVal">Ölçüm bekleniyor</b></div>
        </div>
      </div>

      <!-- SOC PANELS -->
      <div class="panel" style="border-left:4px solid var(--red)">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:20px">🛡️</span>
            <div>
              <h3 style="margin:0;font-size:14px;color:var(--red)">SOC (Güvenlik Operasyon Merkezi)</h3>
              <div style="font-size:10.5px;color:var(--muted)">Yerel güvenlik durumu ve operasyon kayıtları</div>
            </div>
          </div>
          <span class="badge warn" id="socAlertBadge">0 Anomali</span>
        </div>
        <div class="panel-body" style="font-size:12px">
          <div class="kv"><span>Yerel Güvenlik Duvarı</span><b id="socFirewallVal">Ölçüm bekleniyor</b></div>
          <div class="kv"><span>SIEM / Otomatik Engelleme</span><b id="socEngineVal" style="color:var(--muted)">Bu sürümde yok</b></div>
          <div class="kv"><span>Son 24 Saatlik Alarmlar</span><b id="socAlertsVal">Ölçüm bekleniyor</b></div>
        </div>
      </div>

      <!-- XOC / ISOC BÜTÜNLEŞİK MOR TAKIM PANELS -->
      <div class="panel" style="border-left:4px solid var(--purple)">
        <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:20px">🟣</span>
            <div>
              <h3 style="margin:0;font-size:14px;color:var(--purple)">XOC / ISOC (Bütünleşik Mor Takım)</h3>
              <div style="font-size:10.5px;color:var(--muted)">Integrated Security & Ops Center — Red + Blue Synergy</div>
            </div>
          </div>
          <span class="badge warn" style="background:rgba(168,85,247,0.15);color:var(--purple);border-color:rgba(168,85,247,0.3)">Eğitim / Simülasyon</span>
        </div>
        <div class="panel-body" style="font-size:12px">
          <div class="kv"><span>Kırmızı Takım Senaryoları</span><b style="color:var(--orange)">Yalnız görsel demo</b></div>
          <div class="kv"><span>Mavi Takım Yakalama</span><b style="color:var(--muted)">Gerçek SIEM bağlantısı yok</b></div>
          <div class="kv"><span>Mor Takım Doğrulama</span><b style="color:var(--muted)">Gerçek güvenlik kontrolü yapmaz</b></div>
        </div>
      </div>
    </div>

    <!-- İNTERAKTİF SİMÜLATÖR EKRANI -->
    <div class="panel">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
        <h2>🟣 Mor Takım (Purple Team) Saldırı & Savunma Canlı Doğrulayıcı</h2>
      </div>
      <div class="panel-body">
        <div class="device-learning warning" style="margin-bottom:14px"><b>Simülasyon laboratuvarı</b><div>Bu bölüm gerçek saldırı üretmez, SIEM alarmı açmaz, ağa paket göndermez ve firewall kuralı uygulamaz. Gösterilen saldırı/savunma adımları yalnız eğitim amaçlıdır; her senaryo gerçek MITRE ATT&amp;CK taktik kodlarıyla etiketlenmiştir ama tekniklerin uygulama detayını içermez — amaç "bu saldırı nasıl görünür, hangi savunma onu durdurur" farkındalığını öğretmektir.</div></div>

        <!-- KATEGORİ FİLTRESİ -->
        <div id="purpleCategoryChips" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px"></div>

        <!-- SENARYO KARTLARI -->
        <div id="purpleScenarioGrid" style="display:grid;grid-template-columns:repeat(auto-fill, minmax(240px, 1fr));gap:8px;margin-bottom:16px"></div>

        <!-- ANİMASYONLU XOC AKIŞ BARI -->
        <div style="position:relative;background:#050811;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:16px;overflow:hidden">

          <div style="display:flex;justify-content:space-between;align-items:center;position:relative;z-index:2;flex-wrap:wrap;gap:12px">

            <!-- RED TEAM -->
            <div style="text-align:center;background:rgba(242,88,91,0.1);border:1px solid rgba(242,88,91,0.3);padding:14px;border-radius:10px;min-width:140px">
              <div style="font-size:28px">🔴</div>
              <strong style="color:var(--red);font-size:12px">RED TEAM</strong>
              <div style="font-size:10px;color:var(--muted)">Saldırı & BAS Simülasyonu</div>
              <div id="redTeamState" class="badge fail" style="margin-top:6px;font-size:9.5px">Beklemede</div>
            </div>

            <!-- PURPLE MATCHING ENGINE -->
            <div style="text-align:center;background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.3);padding:14px;border-radius:10px;min-width:160px">
              <div style="font-size:28px">🟣</div>
              <strong style="color:var(--purple);font-size:12px">XOC PURPLE ENGINE</strong>
              <div style="font-size:10px;color:var(--muted)">Korelasyon & Doğrulama</div>
              <div id="purpleEngineState" class="badge gray" style="margin-top:6px;font-size:9.5px">Hazır</div>
            </div>

            <!-- BLUE TEAM -->
            <div style="text-align:center;background:rgba(59,155,255,0.1);border:1px solid rgba(59,155,255,0.3);padding:14px;border-radius:10px;min-width:140px">
              <div style="font-size:28px">🔵</div>
              <strong style="color:var(--blue);font-size:12px">BLUE TEAM</strong>
              <div style="font-size:10px;color:var(--muted)">Simüle SIEM / Log Adımı</div>
              <div id="blueTeamState" class="badge info" style="margin-top:6px;font-size:9.5px">İzlemede</div>
            </div>

          </div>

          <!-- ANIMATED PULSE WAVE -->
          <div style="position:relative;height:6px;background:var(--line);margin:20px 0 14px;border-radius:3px">
            <div id="purplePulseAnim" style="position:absolute;width:18px;height:18px;border-radius:50%;background:var(--purple);top:-6px;left:0%;opacity:0;transition:left 1.8s ease-in-out, opacity 0.3s;box-shadow:0 0 14px currentColor"></div>
          </div>

          <!-- LIVE SIMULATION CONSOLE LOG -->
          <div id="purpleConsole" style="background:#020408;border:1px solid var(--line);border-radius:8px;padding:12px;font-family:Consolas, monospace;font-size:11px;color:var(--txt-2);min-height:90px">
            <span style="color:var(--muted)">[XOC PURPLE TEAM] Simülasyon başlatmak için yukarıdaki butonlardan birine tıklayın...</span>
          </div>

        </div>

        <!-- ADMIN XOC LIVE NOC/SOC & PENTEST SIMULATOR -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px">

          <!-- ANOMALİ VE SALDIRI TESPİTİ (BLACKING / SOC) -->
          <div class="panel">
            <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
              <h2>🛡️ IP İzleme Listesi (Firewall Engeli Değildir)</h2>
            </div>
            <div class="panel-body">
              <div style="display:flex;gap:8px;margin-bottom:12px">
                <input type="text" id="xocBlacklistIp" placeholder="Şüpheli IP (örn: 192.168.1.150)" style="flex:1" />
                <button class="mini-btn" onclick="addXocBlacklist()">👁 İzleme Listesine Ekle</button>
              </div>
              <div id="xocBlacklistContainer" style="background:var(--panel-2);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:11.5px">
                <div class="hint">İzleme listesinde IP yok. Liste yalnız bu çalışma süresince tutulur.</div>
              </div>
            </div>
          </div>

          <!-- SİMÜLE EDİLMİŞ DOS TEST MODÜLÜ (PENTEST) -->
          <div class="panel">
            <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
              <h2>💥 DoS Eğitim Senaryosu (Paket Göndermez)</h2>
            </div>
            <div class="panel-body">
              <div style="display:flex;gap:8px;margin-bottom:12px">
                <input type="text" id="xocDosTargetIp" placeholder="Hedef IP / Kullanıcı (örn: 10.33.254.12)" style="flex:1" />
                <button class="mini-btn blue" onclick="startXocDosSimulation()">🚀 Simülasyonu Başlat</button>
              </div>
              <div id="xocDosResultBox" style="background:var(--panel-2);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:11.5px;min-height:48px">
                <span class="hint">Kontrollü stres testi simülasyonu başlatmak için hedef IP girin.</span>
              </div>
            </div>
          </div>

        </div>

      </div>
    </div>
  `;

  renderPurpleCategoryChips();
  renderPurpleScenarioGrid();
  loadAdminXocMetrics();
}

async function loadAdminXocMetrics() {
  try {
    const data = await get("/api/admin/xoc/metrics");
    if (data.ok) {
      const setText = (id, value) => { const el = $(id); if (el) el.textContent = value; };
      const noc = data.noc || {};
      const soc = data.soc || {};
      setText("nocBwVal", noc.link_speed_mbps == null ? "Ölçülemedi" : `${noc.link_speed_mbps} Mbps`);
      setText("nocAvailabilityVal", noc.availability_24h == null ? "Yeterli örnek yok" : `%${noc.availability_24h}`);
      setText("nocNodesVal", `${noc.infrastructure_online ?? 0} erişilebilir altyapı cihazı`);
      const firewallState = soc.firewall?.state || "unknown";
      setText("socFirewallVal", firewallState === "enabled" ? "Açık" : firewallState === "disabled" ? "Kapalı" : "Doğrulanamadı");
      setText("socEngineVal", soc.siem_enabled ? "Bağlı" : "Bu sürümde yok");
      const alertCounts = soc.alert_counts_24h || {};
      setText("socAlertsVal", `${alertCounts.critical || 0} kritik / ${alertCounts.warning || 0} uyarı`);
      setText("socAlertBadge", `${Object.values(alertCounts).reduce((sum, count) => sum + Number(count || 0), 0)} alarm`);
      const container = $("xocBlacklistContainer");
      const watchlist = soc.watchlist_ips || soc.blacklisted_ips || [];
      if (container) {
        if (watchlist.length === 0) {
          container.innerHTML = `<div class="hint">İzleme listesinde IP yok. Firewall engeli uygulanmaz.</div>`;
        } else {
          container.innerHTML = watchlist.map(ip => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid var(--line-soft)">
              <span style="font-weight:bold">👁 ${esc(ip)}</span>
              <button class="mini-btn" onclick="removeXocBlacklist('${esc(ip)}')">Listeden Çıkar</button>
            </div>
          `).join("");
        }
      }
    }
  } catch (e) {
    const container = $("xocBlacklistContainer");
    if (container) renderLoadError(container, "SOC/NOC ölçümleri alınamadı", e, "loadAdminXocMetrics()");
  }
}

async function addXocBlacklist() {
  const ip = ($("xocBlacklistIp")?.value || "").trim();
  if (!ip) return toast("Lütfen geçerli bir IP adresi girin.", "error");
  try {
    await post("/api/admin/xoc/blacklist/add", { ip, reason: "Yönetici manuel izleme kaydı" });
    toast(`${ip} izleme listesine eklendi; firewall engeli uygulanmadı.`, "success");
    if ($("xocBlacklistIp")) $("xocBlacklistIp").value = "";
    loadAdminXocMetrics();
  } catch (e) {
    toast(e.message || "IP izleme listesine eklenemedi.", "error");
  }
}

async function removeXocBlacklist(ip) {
  try {
    await post("/api/admin/xoc/blacklist/remove", { ip });
    toast(`${ip} izleme listesinden çıkarıldı.`, "success");
    loadAdminXocMetrics();
  } catch (e) {
    toast(e.message || "İzleme listesi güncellenemedi.", "error");
  }
}

async function startXocDosSimulation() {
  const target_ip = ($("xocDosTargetIp")?.value || "").trim();
  if (!target_ip) return toast("Lütfen hedef IP girin.", "error");
  try {
    const res = await post("/api/admin/xoc/simulate-dos", { target_ip, intensity: "high" });
    toast(`DoS eğitim senaryosu tamamlandı; gerçek paket gönderilmedi: ${target_ip}`, "info");
    const box = $("xocDosResultBox");
    if (box && res.simulation) {
      box.innerHTML = `
        <div style="color:var(--cyan);font-weight:bold">✅ EĞİTİM SENARYOSU TAMAMLANDI (ID: ${esc(res.simulation.id)})</div>
        <div>Hedef etiketi: <b>${esc(res.simulation.target)}</b> · Sanal paket: <b>${Number(res.simulation.simulated_packets || 0).toLocaleString()}</b></div>
        <div style="font-size:10.5px;color:var(--muted);margin-top:4px">${esc(res.simulation.note)}</div>
      `;
    }
  } catch (e) {
    toast(e.message || "Simülasyon başlatılamadı.", "error");
  }
}

/* ---------- SALDIRI / SAVUNMA KATALOĞU (MITRE ATT&CK referanslı, salt eğitim amaçlı) ----------
   Her senaryo gerçek bir MITRE ATT&CK taktiğine etiketlenir ama TEKNİK UYGULAMA DETAYI
   İÇERMEZ (nasıl yapılır anlatılmaz). Amaç: "bu saldırı SOC ekranında nasıl görünür,
   hangi savunma katmanı onu durdurur" farkındalığı kazandırmaktır. */
const PURPLE_CATEGORIES = [
  { id: "recon",      label: "🔍 Keşif",              color: "#06b6d4" },
  { id: "access",     label: "🚪 İlk Erişim",          color: "#f59e0b" },
  { id: "credential", label: "🔑 Kimlik Bilgisi",      color: "#ef4444" },
  { id: "lateral",    label: "↔️ Yanal Hareket",       color: "#38bdf8" },
  { id: "c2",         label: "📡 Komuta & Kontrol",    color: "#8b5cf6" },
  { id: "exfil",      label: "📤 Veri Sızdırma",       color: "#f97316" },
  { id: "impact",     label: "💥 Etki (DoS/Ransom)",   color: "#dc2626" },
  { id: "web",        label: "🌐 Web Uygulama",        color: "#10b981" },
];

const PURPLE_CATALOG = [
  {
    id: "portscan", category: "recon", mitre: "TA0043 · T1595 Active Scanning",
    title: "Gizli SYN Stealth Port Tarama (Nmap tarzı)",
    red: "10.33.254.0/23 aralığında 1-65535 arası tüm portlar taranıyor...",
    purple: "XOC Güvenlik Skoru: Açık 3 servis tespit edildi (HTTP-80, HTTPS-443, SSH-22).",
    blue: "Simüle firewall adımı: 'SYN Port Scan Detected' kaydı ve geçici engel örneklendi.",
    defense: "Gerçek korunma: kullanılmayan servisleri kapatın, dışa açık olmayan portları router/firewall'da filtreleyin, IDS/IPS ile tarama paternlerini alarma bağlayın.",
    color: "#06b6d4",
  },
  {
    id: "sniffing", category: "recon", mitre: "TA0043 · T1040 Network Sniffing",
    title: "Ağ Trafiği Dinleme (Şifresiz Protokol Avı)",
    red: "Aynı ağ segmentinde ARP tablosu izlenerek şifresiz HTTP/FTP trafiği aranıyor...",
    purple: "XOC Korelasyonu: Promiscuous mod şüphesiyle switch port anomalisi işaretlendi.",
    blue: "Simüle SOC adımı: 'Olası Paket Dinleme' uyarısı ve segment izolasyonu örneklendi.",
    defense: "Gerçek korunma: her yerde TLS/HTTPS zorunlu kılın, kritik segmentleri VLAN ile ayırın, switch port security ve DHCP snooping açın.",
    color: "#06b6d4",
  },
  {
    id: "phishing", category: "access", mitre: "TA0001 · T1566 Phishing",
    title: "Kimlik Avı E-postası ile İlk Erişim",
    red: "'Fatura Ekli' konulu, meşru görünen bir e-posta 40 kullanıcıya gönderildi...",
    purple: "XOC Korelasyonu: Aynı ekli dosya hash'i 6 farklı posta kutusunda eşleşti.",
    blue: "Simüle e-posta ağ geçidi adımı: eki karantinaya alma ve kullanıcı uyarısı örneklendi.",
    defense: "Gerçek korunma: e-posta filtreleme/DMARC-SPF-DKIM, ekleri sandbox'ta patlatma, düzenli phishing farkındalık eğitimi (Academy modülü bunun için var).",
    color: "#f59e0b",
  },
  {
    id: "eviltwin", category: "access", mitre: "TA0001 · T1200 / Rogue Wi-Fi",
    title: "Sahte Erişim Noktası (Evil Twin Wi-Fi)",
    red: "Aynı SSID adıyla daha güçlü sinyalli sahte bir erişim noktası yayında...",
    purple: "XOC Anomali Analizi: aynı SSID için iki farklı BSSID/MAC eşleşmesi bulundu.",
    blue: "Simüle NOC adımı: 'Rogue AP Şüphesi' uyarısı ve kullanıcı bilgilendirmesi örneklendi.",
    defense: "Gerçek korunma: WPA3 + 802.1X kurumsal kimlik doğrulama kullanın, bilinmeyen AP'leri WIDS ile tespit edin, kullanıcıları halka açık/bilinmeyen ağlara VPN'siz bağlanmaması için eğitin.",
    color: "#f59e0b",
  },
  {
    id: "bruteforce", category: "credential", mitre: "TA0006 · T1110 Brute Force",
    title: "SSH / RDP Brute-Force Parola Saldırısı",
    red: "Port 22 & 3389 üzerine saniyede 150 hatalı parola deneniyor...",
    purple: "XOC Korelasyonu: 10.33.254.42 ➔ Port 22 çoklu yetkisiz giriş başarısızlığı eşleşti.",
    blue: "Simüle SIEM adımı: 'Brute-Force Saldırısı Tespiti' alarmı ve geçici IP engeli örneklendi.",
    defense: "Gerçek korunma: hesap kilitleme eşiği + artan bekleme süresi (NetMon'un kendi login kilidi bunu uygular), MFA, RDP/SSH'ı doğrudan internete açmayın (VPN arkasına alın).",
    color: "#ef4444",
  },
  {
    id: "credstuffing", category: "credential", mitre: "TA0006 · T1110.004 Credential Stuffing",
    title: "Sızmış Parola Listeleriyle Otomatik Deneme",
    red: "Farklı bir sızıntıdan elde edilen 50.000 kullanıcı/parola çifti otomatik deneniyor...",
    purple: "XOC Korelasyonu: Çok sayıda farklı kullanıcı adı, tek IP'den art arda denendi.",
    blue: "Simüle adım: 'Credential Stuffing Paterni' alarmı ve CAPTCHA/IP kısıtlama örneklendi.",
    defense: "Gerçek korunma: her sistemde farklı ve güçlü parola (parola yöneticisi), MFA, sızıntı veritabanlarına karşı parola kontrolü (haveibeenpwned tarzı).",
    color: "#ef4444",
  },
  {
    id: "lateral", category: "lateral", mitre: "TA0008 · T1021 Remote Services",
    title: "SMB/RDP ile Yanal Hareket",
    red: "Ele geçirilen bir istemciden iç ağdaki diğer sunuculara SMB ile bağlanmaya çalışılıyor...",
    purple: "XOC Korelasyonu: Tek bir host'tan kısa sürede 12 farklı iç IP'ye SMB bağlantı denemesi.",
    blue: "Simüle SOC adımı: 'Anormal İç Ağ Yayılımı' alarmı ve host izolasyonu örneklendi.",
    defense: "Gerçek korunma: ağ segmentasyonu (VLAN/mikro-segmentasyon), en az ayrıcalık ilkesi, iç trafikte de EDR/anomali izleme.",
    color: "#38bdf8",
  },
  {
    id: "privesc", category: "lateral", mitre: "TA0004 · T1068 Privilege Escalation",
    title: "Yerel Yetki Yükseltme Denemesi",
    red: "Standart bir kullanıcı hesabından yönetici (admin/root) yetkisine çıkmaya çalışılıyor...",
    purple: "XOC Korelasyonu: Kısa sürede çok sayıda başarısız yetki yükseltme çağrısı görüldü.",
    blue: "Simüle EDR adımı: 'Şüpheli Yetki Yükseltme' alarmı ve süreç sonlandırma örneklendi.",
    defense: "Gerçek korunma: işletim sistemi ve uygulamaları güncel tutun (patch yönetimi), günlük kullanıcıları admin yapmayın, EDR ile şüpheli süreç davranışlarını izleyin.",
    color: "#38bdf8",
  },
  {
    id: "c2beacon", category: "c2", mitre: "TA0011 · T1071 C2 Beacon Traffic",
    title: "Komuta-Kontrol (C2) Sinyal Trafiği",
    red: "Ele geçirilmiş bir cihaz, dışarıdaki bir sunucuya her 60 saniyede kısa 'yoklama' istekleri gönderiyor...",
    purple: "XOC Anomali Analizi: Periyodik/düzenli aralıklı düşük hacimli dış trafik paterni tespit edildi.",
    blue: "Simüle SOC adımı: 'Olası C2 Beacon' alarmı ve DNS/IP itibar kontrolü örneklendi.",
    defense: "Gerçek korunma: çıkış (egress) trafiği filtreleme, DNS sinkhole/itibar listeleri, bilinmeyen dış bağlantılar için uyarı kuralları.",
    color: "#8b5cf6",
  },
  {
    id: "exfiltration", category: "exfil", mitre: "TA0010 · T1041 Exfiltration Over C2",
    title: "Gece Yarısı Yüksek Hacimli Veri Çıkışı",
    red: "Dış bir IP'ye saat 03:14'te 4.2 GB veri transferi başlatıldı...",
    purple: "XOC Anomali Analizi: Mesai dışı saatte alışılmadık dış trafik akışı doğrulandı.",
    blue: "Simüle NOC/SOC adımı: 'Şüpheli Veri Sızıntısı' alarmı ve bant kısıtlama örneklendi.",
    defense: "Gerçek korunma: DLP (veri kaybı önleme) kuralları, büyük/mesai dışı transferler için alarm eşiği, hassas veriyi şifreleme.",
    color: "#f97316",
  },
  {
    id: "dos", category: "impact", mitre: "TA0040 · T1498 Network DoS",
    title: "Hizmet Dışı Bırakma (DoS/DDoS) Yük Testi",
    red: "Hedef servise normalin çok üzerinde istek gönderilerek kaynaklar tüketilmeye çalışılıyor...",
    purple: "XOC Korelasyonu: Tek/az sayıda kaynaktan anormal yüksek istek oranı görüldü.",
    blue: "Simüle adım: 'Olası DoS' alarmı ve hız sınırlama (rate limiting) örneklendi.",
    defense: "Gerçek korunma: rate limiting/WAF, CDN veya DDoS koruma servisi, kaynak kullanımı için otomatik ölçekleme ve alarm eşikleri.",
    color: "#dc2626",
  },
  {
    id: "ransomware", category: "impact", mitre: "TA0040 · T1486 Data Encrypted for Impact",
    title: "Fidye Yazılımı (Ransomware) Şifreleme Davranışı",
    red: "Kısa sürede çok sayıda dosya uzantısı değiştiriliyor ve toplu şifreleme paterni gözleniyor...",
    purple: "XOC Korelasyonu: Saniyede yüzlerce dosya değişikliği + yeni/bilinmeyen dosya uzantısı eşleşti.",
    blue: "Simüle EDR adımı: 'Toplu Dosya Şifreleme Paterni' alarmı ve süreç durdurma örneklendi.",
    defense: "Gerçek korunma: düzenli ve izole (offline/immutable) yedekleme, EDR ile davranış tabanlı tespit, e-posta/USB gibi giriş noktalarını sıkılaştırma.",
    color: "#dc2626",
  },
  {
    id: "webattack", category: "web", mitre: "TA0001 · T1190 Exploit Public-Facing App (SQLi/XSS paterni)",
    title: "Web Uygulamasına Otomatik Zafiyet Denemesi",
    red: "Giriş formuna art arda SQL enjeksiyonu ve script enjeksiyonu paternleri deneniyor...",
    purple: "XOC Korelasyonu: Tek IP'den kısa sürede çok sayıda anormal karakter dizisi içeren istek.",
    blue: "Simüle WAF adımı: 'Enjeksiyon Paterni Tespit Edildi' kaydı ve istek engelleme örneklendi.",
    defense: "Gerçek korunma: parametreli sorgular/ORM kullanımı (bu projede zaten uygulanıyor), girdi doğrulama, WAF, düzenli bağımlılık/güvenlik taraması.",
    color: "#10b981",
  },
];

function renderPurpleCategoryChips() {
  const wrap = $("purpleCategoryChips");
  if (!wrap) return;
  const active = _purpleActiveCategory || "all";
  const chips = [{ id: "all", label: "🗂️ Tümü", color: "var(--muted)" }, ...PURPLE_CATEGORIES];
  wrap.innerHTML = chips.map(c => {
    const isActive = c.id === active;
    return `<button class="mini-btn" onclick="setPurpleCategory('${c.id}')"
      style="border-color:${c.color};${isActive ? `background:${c.color};color:#000;font-weight:bold` : `color:${c.color}`}">${esc(c.label)}</button>`;
  }).join("");
}

function setPurpleCategory(catId) {
  _purpleActiveCategory = catId;
  renderPurpleCategoryChips();
  renderPurpleScenarioGrid();
}

function renderPurpleScenarioGrid() {
  const grid = $("purpleScenarioGrid");
  if (!grid) return;
  const active = _purpleActiveCategory || "all";
  const list = active === "all" ? PURPLE_CATALOG : PURPLE_CATALOG.filter(s => s.category === active);
  grid.innerHTML = list.map(s => `
    <button class="mini-btn blue" onclick="runPurpleSimulation('${s.id}')" style="text-align:left;padding:10px;border-left:3px solid ${s.color}">
      <div style="font-weight:bold;font-size:11.5px">${esc(s.title)}</div>
      <div style="font-size:9.5px;color:rgba(255,255,255,0.75);margin-top:3px">${esc(s.mitre)}</div>
    </button>
  `).join("");
}

let _purpleActiveCategory = "all";

function runPurpleSimulation(type) {
  if (_purpleSimTimer) clearInterval(_purpleSimTimer);

  const redBadge = $("redTeamState");
  const purpleBadge = $("purpleEngineState");
  const blueBadge = $("blueTeamState");
  const pulse = $("purplePulseAnim");
  const consoleEl = $("purpleConsole");

  const scn = PURPLE_CATALOG.find(s => s.id === type) || PURPLE_CATALOG[0];

  if (redBadge) { redBadge.textContent = "Sanal Senaryo"; redBadge.className = "badge fail"; }
  if (purpleBadge) { purpleBadge.textContent = "Demo Analizi"; purpleBadge.className = "badge warn"; }
  if (blueBadge) { blueBadge.textContent = "Demo Tamamlandı"; blueBadge.className = "badge ok"; }

  if (pulse) {
    pulse.style.opacity = "1";
    pulse.style.background = scn.color;
    pulse.style.left = "0%";
    setTimeout(() => { if (pulse) pulse.style.left = "50%"; }, 100);
    setTimeout(() => { if (pulse) pulse.style.left = "100%"; }, 1200);
  }

  if (consoleEl) {
    consoleEl.innerHTML = `
      <div style="color:${scn.color};font-weight:bold;margin-bottom:2px">🔴 RED TEAM: ${esc(scn.title)}</div>
      <div style="color:var(--muted);font-size:10px;margin-bottom:6px">MITRE ATT&amp;CK: ${esc(scn.mitre)}</div>
      <div style="color:var(--txt);margin-bottom:4px">└─ ${esc(scn.red)}</div>
      <div style="color:var(--purple);margin-bottom:4px">🟣 XOC PURPLE ENGINE: ${esc(scn.purple)}</div>
      <div style="color:var(--green);font-weight:bold;margin-bottom:6px">🔵 BLUE TEAM: ${esc(scn.blue)}</div>
      <div style="border-top:1px dashed var(--line);padding-top:6px;color:var(--cyan)">🛡️ GERÇEK HAYATTA KORUNMA: ${esc(scn.defense)}</div>
    `;
  }
}

Object.assign(globalThis, {
  _purpleSimTimer,
  renderPurpleTeamPage,
  loadAdminXocMetrics,
  addXocBlacklist,
  removeXocBlacklist,
  startXocDosSimulation,
  PURPLE_CATEGORIES,
  PURPLE_CATALOG,
  renderPurpleCategoryChips,
  setPurpleCategory,
  renderPurpleScenarioGrid,
  _purpleActiveCategory,
  runPurpleSimulation,
});
