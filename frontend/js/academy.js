import "./diagnostics.js";

/* ---------- Raporlar ---------- */
const EGITIM_KAVRAMLAR = [
  { key: "ip", renk: "blue", ico: "monitor", ad: "IP Adresi", ozet: "Ağdaki her cihaza atanan benzersiz numaradır; paketlerin kime gideceğini belirler." },
  { key: "dns", renk: "cyan", ico: "wifi", ad: "DNS", ozet: "İnsan tarafından okunan alan adlarını (site.com) IP adresine çevirir." },
  { key: "port", renk: "orange", ico: "gauge", ad: "Port", ozet: "Aynı IP üzerinde birden çok servisi ayırt etmeye yarayan numaradır (80=HTTP, 443=HTTPS, 22=SSH)." },
  { key: "mac", renk: "purple", ico: "list", ad: "MAC Adresi", ozet: "Ağ kartının donanımsal, değiştirilemeyen fiziksel adresidir." },
  { key: "nat", renk: "green", ico: "route", ad: "NAT", ozet: "Birden çok özel IP'yi tek bir genel (public) IP arkasında internete çıkarır." },
  { key: "dhcp", renk: "blue", ico: "activity", ad: "DHCP", ozet: "Ağa yeni katılan cihazlara otomatik IP adresi atayan servistir." },
  { key: "packets", renk: "cyan", ico: "report", ad: "Paketler", ozet: "Veri ağ üzerinde küçük parçalara (paketlere) bölünerek iletilir." },
  { key: "osi", renk: "orange", ico: "route", ad: "OSI Modeli", ozet: "Ağ iletişimini 7 katmana ayıran kavramsal referans modelidir (Fiziksel'den Uygulama'ya)." },
  { key: "subnet", renk: "purple", ico: "shield", ad: "Subnetting / CIDR", ozet: "Büyük bir ağı, /24 gibi CIDR gösterimiyle daha küçük alt ağlara böler." },
  { key: "routersw", renk: "green", ico: "wifi", ad: "Router vs Switch", ozet: "Switch aynı ağ içindeki cihazları, router ise farklı ağları birbirine bağlar." },
  { key: "tcpudp", renk: "blue", ico: "activity", ad: "TCP vs UDP", ozet: "TCP güvenilir ve sıralı iletim sağlar; UDP daha hızlıdır ama teslim garantisi vermez." },
  { key: "http", renk: "cyan", ico: "monitor", ad: "HTTP / HTTPS", ozet: "Web trafiğinin protokolüdür; HTTPS, TLS ile şifrelenmiş halidir." },
  { key: "tls", renk: "orange", ico: "shield", ad: "TLS", ozet: "İstemci ile sunucu arasında el sıkışma yaparak trafiği şifreler." },
  { key: "firewall", renk: "purple", ico: "shield", ad: "Firewall", ozet: "Tanımlı kurallara göre trafiği izin verir veya engeller." },
  { key: "vpn", renk: "green", ico: "route", ad: "VPN", ozet: "İnternet üzerinden şifreli, özel bir tünel oluşturur." },
];

/* Her kavram için küçük, döngüsel animasyonlu SVG diyagramı (native SMIL
   <animate>/<animateMotion> kullanılıyor — ek kütüphane/JS animasyon
   döngüsü gerekmiyor, tarayıcı kendisi oynatıyor). */
function _c(key) {
  const map = { blue: "blue", cyan: "cyan", orange: "orange", purple: "purple", green: "green", red: "red" };
  return `var(--${map[key] || "blue"})`;
}
const DIAGRAMS = {
  ip: `<svg viewBox="0 0 220 90"><g fill="none" stroke="${_c("blue")}" stroke-width="1.6">
    <rect x="8" y="10" width="30" height="20" rx="2"/><rect x="8" y="35" width="30" height="20" rx="2"/><rect x="8" y="60" width="30" height="20" rx="2"/>
    <path d="M38 20H100M38 45H100M38 70H100"/><rect x="100" y="30" width="34" height="30" rx="4"/>
    </g>
    <circle r="3" fill="${_c("blue")}"><animateMotion dur="2s" repeatCount="indefinite" path="M38 20H100"/></circle>
    <circle r="3" fill="${_c("cyan")}"><animateMotion dur="2.4s" repeatCount="indefinite" path="M38 45H100"/></circle>
    <circle r="3" fill="${_c("green")}"><animateMotion dur="2.8s" repeatCount="indefinite" path="M38 70H100"/></circle>
    <text x="12" y="24" font-size="7" fill="var(--txt-2)">.4</text><text x="12" y="49" font-size="7" fill="var(--txt-2)">.7</text><text x="12" y="74" font-size="7" fill="var(--txt-2)">.9</text>
    <text x="106" y="49" font-size="7" fill="var(--txt)">192.168.1.x</text></svg>`,

  dns: `<svg viewBox="0 0 220 90"><g font-size="9" fill="var(--txt)">
    <rect x="6" y="35" width="60" height="20" rx="4" fill="none" stroke="${_c("green")}"/><text x="14" y="48">site.com</text>
    <rect x="80" y="35" width="60" height="20" rx="4" fill="none" stroke="${_c("cyan")}"/><text x="93" y="48">DNS</text>
    <rect x="154" y="35" width="60" height="20" rx="4" fill="none" stroke="${_c("blue")}"/><text x="160" y="48" font-size="8">203.0.113.5</text></g>
    <circle r="3" fill="${_c("cyan")}"><animateMotion dur="2.2s" repeatCount="indefinite" path="M66 45H80"/></circle>
    <circle r="3" fill="${_c("blue")}"><animateMotion dur="2.2s" repeatCount="indefinite" begin="1.1s" path="M140 45H154"/></circle></svg>`,

  port: `<svg viewBox="0 0 220 90"><rect x="70" y="10" width="70" height="70" rx="6" fill="none" stroke="${_c("orange")}" stroke-width="1.6"/>
    <text x="82" y="26" font-size="8" fill="var(--txt)">SERVER</text>
    <g font-size="8" fill="var(--txt-2)">
    <rect x="80" y="32" width="50" height="12" fill="none" stroke="var(--line)"><animate attributeName="stroke" values="var(--line);${_c("orange")};var(--line)" dur="3s" repeatCount="indefinite"/></rect><text x="84" y="41">:80 HTTP</text>
    <rect x="80" y="47" width="50" height="12" fill="none" stroke="var(--line)"><animate attributeName="stroke" values="var(--line);${_c("orange")};var(--line)" dur="3s" begin="1s" repeatCount="indefinite"/></rect><text x="84" y="56">:443 HTTPS</text>
    <rect x="80" y="62" width="50" height="12" fill="none" stroke="var(--line)"><animate attributeName="stroke" values="var(--line);${_c("orange")};var(--line)" dur="3s" begin="2s" repeatCount="indefinite"/></rect><text x="84" y="71">:22 SSH</text></g></svg>`,

  mac: `<svg viewBox="0 0 220 90"><rect x="70" y="25" width="80" height="40" rx="6" fill="none" stroke="${_c("purple")}" stroke-width="1.6">
    <animate attributeName="stroke-opacity" values="1;0.4;1" dur="2s" repeatCount="indefinite"/></rect>
    <text x="82" y="49" font-size="9" fill="var(--txt)">3C:22:FB:9A</text></svg>`,

  nat: `<svg viewBox="0 0 220 90"><g font-size="7" fill="var(--txt-2)">
    <rect x="6" y="8" width="42" height="14" rx="3" fill="none" stroke="${_c("green")}"/><text x="10" y="18">10.0.0.12</text>
    <rect x="6" y="38" width="42" height="14" rx="3" fill="none" stroke="${_c("green")}"/><text x="10" y="48">10.0.0.17</text>
    <rect x="6" y="68" width="42" height="14" rx="3" fill="none" stroke="${_c("green")}"/><text x="10" y="78">10.0.0.23</text></g>
    <rect x="90" y="35" width="44" height="20" rx="4" fill="none" stroke="${_c("orange")}" stroke-width="1.6"/><text x="98" y="48" font-size="8" fill="var(--txt)">NAT</text>
    <rect x="164" y="35" width="50" height="20" rx="4" fill="none" stroke="${_c("blue")}"/><text x="168" y="48" font-size="7" fill="var(--txt)">203.0.113.5</text>
    <circle r="2.5" fill="${_c("green")}"><animateMotion dur="1.6s" repeatCount="indefinite" path="M48 15C70 15 70 45 90 45"/></circle>
    <circle r="2.5" fill="${_c("green")}"><animateMotion dur="1.6s" begin=".5s" repeatCount="indefinite" path="M48 45H90"/></circle>
    <circle r="2.5" fill="${_c("green")}"><animateMotion dur="1.6s" begin="1s" repeatCount="indefinite" path="M48 75C70 75 70 45 90 45"/></circle>
    <circle r="3" fill="${_c("blue")}"><animateMotion dur="1.6s" begin=".3s" repeatCount="indefinite" path="M134 45H164"/></circle></svg>`,

  dhcp: `<svg viewBox="0 0 220 90"><rect x="6" y="30" width="46" height="30" rx="4" fill="none" stroke="${_c("blue")}"/><text x="10" y="49" font-size="8" fill="var(--txt)">CLIENT</text>
    <rect x="168" y="30" width="46" height="30" rx="4" fill="none" stroke="${_c("green")}"/><text x="172" y="49" font-size="8" fill="var(--txt)">SERVER</text>
    <path d="M52 40H168" stroke="var(--line)"/>
    <circle r="3" fill="${_c("orange")}"><animateMotion dur="1s" repeatCount="indefinite" path="M52 40H168"/><animate attributeName="fill" values="${_c("orange")};${_c("orange")}" dur="1s" repeatCount="indefinite"/></circle>
    <path d="M52 52H168" stroke="var(--line)"/>
    <circle r="3" fill="${_c("cyan")}"><animateMotion dur="1s" begin="1s" repeatCount="indefinite" path="M168 52H52"/></circle>
    <text x="70" y="20" font-size="7" fill="var(--txt-3)">DISCOVER → OFFER → REQUEST → ACK</text></svg>`,

  packets: `<svg viewBox="0 0 220 90"><path d="M10 45H210" stroke="var(--line)"/>
    ${[0, 1, 2].map((i) => `<g><rect width="20" height="16" x="-10" y="-8" rx="3" fill="none" stroke="${_c(["blue", "cyan", "green"][i])}"><animateMotion dur="3s" begin="${i * 1}s" repeatCount="indefinite" path="M20 45H200"/></rect><text x="-4" y="4" font-size="8" fill="var(--txt)"><animateMotion dur="3s" begin="${i * 1}s" repeatCount="indefinite" path="M20 45H200"/>${i + 1}</text></g>`).join("")}
    </svg>`,

  osi: `<svg viewBox="0 0 220 96">${["Uygulama", "Sunum", "Oturum", "Taşıma", "Ağ", "Veri Bağı", "Fiziksel"]
    .map(
      (l, i) => `<rect x="30" y="${i * 13}" width="160" height="11" fill="none" stroke="var(--line)"><animate attributeName="stroke" values="var(--line);${_c("orange")};var(--line)" dur="4.9s" begin="${i * 0.4}s" repeatCount="indefinite"/></rect><text x="34" y="${i * 13 + 9}" font-size="7" fill="var(--txt-2)">${l}</text>`,
    )
    .join("")}</svg>`,

  subnet: `<svg viewBox="0 0 220 60"><text x="10" y="14" font-size="8" fill="var(--txt)">192.168.1.0/24</text>
    <rect x="10" y="24" width="150" height="16" fill="${_c("purple")}" fill-opacity="0.35" stroke="${_c("purple")}"/>
    <rect x="160" y="24" width="50" height="16" fill="var(--panel-2)" stroke="var(--line)"/>
    <text x="55" y="35" font-size="7" fill="var(--txt)">network (21 bit)</text><text x="167" y="35" font-size="7" fill="var(--txt-2)">host</text>
    <rect x="10" y="24" width="4" height="16" fill="${_c("cyan")}"><animate attributeName="x" values="10;206;10" dur="4s" repeatCount="indefinite"/></rect></svg>`,

  routersw: `<svg viewBox="0 0 220 80"><text x="14" y="14" font-size="8" fill="var(--txt-2)">Router — farklı ağları bağlar</text>
    <circle cx="30" cy="40" r="10" fill="none" stroke="${_c("green")}"/><circle cx="80" cy="40" r="10" fill="none" stroke="${_c("green")}"/>
    <circle r="2.5" fill="${_c("green")}"><animateMotion dur="1.8s" repeatCount="indefinite" path="M30 40 40 40"/></circle>
    <text x="120" y="14" font-size="8" fill="var(--txt-2)">Switch — aynı ağı bağlar</text>
    <rect x="130" y="35" width="70" height="10" fill="none" stroke="${_c("cyan")}"/>
    ${[0, 1, 2].map((i) => `<circle cx="${140 + i * 25}" cy="55" r="4" fill="none" stroke="${_c("cyan")}"/><line x1="${140 + i * 25}" y1="45" x2="${140 + i * 25}" y2="51" stroke="${_c("cyan")}"><animate attributeName="stroke-opacity" values="0.2;1;0.2" dur="1.5s" begin="${i * 0.3}s" repeatCount="indefinite"/></line>`).join("")}</svg>`,

  tcpudp: `<svg viewBox="0 0 220 70"><text x="6" y="12" font-size="8" fill="var(--txt-2)">TCP (sıralı)</text><path d="M10 24H210" stroke="var(--line)"/>
    ${[0, 1, 2].map((i) => `<circle r="3" fill="${_c("blue")}"><animateMotion dur="2.4s" begin="${i * 0.8}s" repeatCount="indefinite" path="M10 24H210"/></circle>`).join("")}
    <text x="6" y="48" font-size="8" fill="var(--txt-2)">UDP (hızlı, garantisiz)</text><path d="M10 60H210" stroke="var(--line)"/>
    ${[0, 1, 2, 3, 4].map((i) => `<circle r="2.5" fill="${_c("orange")}" fill-opacity="${i === 2 ? 0.25 : 1}"><animateMotion dur="1.1s" begin="${i * 0.22}s" repeatCount="indefinite" path="M10 60H210"/></circle>`).join("")}</svg>`,

  http: `<svg viewBox="0 0 220 70"><rect x="40" y="22" width="140" height="24" rx="12" fill="none" stroke="${_c("cyan")}"/>
    <text x="52" y="38" font-size="9" fill="var(--txt)">https://site.com</text>
    <path d="M154 22v-6a6 6 0 0 1 12 0v6" fill="none" stroke="${_c("green")}" stroke-width="2"><animate attributeName="stroke" values="${_c("green")};var(--red);${_c("green")}" dur="3s" repeatCount="indefinite"/></path>
    <rect x="152" y="22" width="16" height="12" rx="2" fill="${_c("green")}"><animate attributeName="fill" values="var(--green);var(--red);var(--green)" dur="3s" repeatCount="indefinite"/></rect></svg>`,

  tls: `<svg viewBox="0 0 220 80"><rect x="10" y="30" width="40" height="20" rx="4" fill="none" stroke="${_c("blue")}"/><text x="16" y="44" font-size="8" fill="var(--txt)">Client</text>
    <rect x="170" y="30" width="40" height="20" rx="4" fill="none" stroke="${_c("green")}"/><text x="176" y="44" font-size="8" fill="var(--txt)">Server</text>
    <path d="M50 34 L170 24" stroke="${_c("orange")}" stroke-dasharray="4 3"><animate attributeName="stroke-dashoffset" values="0;-14" dur="1.4s" repeatCount="indefinite"/></path>
    <path d="M170 46 L50 56" stroke="${_c("cyan")}" stroke-dasharray="4 3"><animate attributeName="stroke-dashoffset" values="0;-14" dur="1.4s" repeatCount="indefinite"/></path>
    <text x="80" y="18" font-size="7" fill="var(--txt-3)">hello / cert → şifreli kanal</text></svg>`,

  firewall: `<svg viewBox="0 0 220 80">${Array.from({ length: 9 }).map((_, i) => {
    const x = 60 + (i % 3) * 22, y = 15 + Math.floor(i / 3) * 22, blocked = i === 4;
    return `<rect x="${x}" y="${y}" width="16" height="16" fill="none" stroke="${blocked ? "var(--red)" : _c("green")}"><animate attributeName="stroke-opacity" values="1;0.3;1" dur="${blocked ? 1 : 2.4}s" repeatCount="indefinite" begin="${i * 0.1}s"/></rect>`;
  }).join("")}
    <text x="6" y="45" font-size="8" fill="var(--txt-2)">:443 ✓</text><text x="6" y="65" font-size="8" fill="var(--red)">:23 ✕</text></svg>`,

  vpn: `<svg viewBox="0 0 220 80"><rect x="8" y="30" width="34" height="22" rx="3" fill="none" stroke="${_c("blue")}"/><text x="10" y="44" font-size="7" fill="var(--txt)">PC</text>
    <path d="M42 40 C90 15 130 65 180 40" fill="none" stroke="${_c("green")}" stroke-width="2" stroke-dasharray="6 4"><animate attributeName="stroke-dashoffset" values="0;-20" dur="1.2s" repeatCount="indefinite"/></path>
    <circle cx="196" cy="40" r="20" fill="none" stroke="${_c("green")}"/><text x="186" y="44" font-size="7" fill="var(--txt)">🔒</text></svg>`,
};

function diagramFor(key) {
  return DIAGRAMS[key] || "";
}

/* ---------- CANLI DHCP DORA SİMÜLATÖRÜ ---------- */
let _dhcpSimTimer = null;
let _dhcpSimStep = 0;

function startDhcpSimulation() {
  if (_dhcpSimTimer) clearInterval(_dhcpSimTimer);
  _dhcpSimStep = 0;

  const steps = [
    { name: "DISCOVER", color: "#22d3ee", msg: "Aşama 1/4: DHCP DISCOVER — İstemci ağa 'DHCP Sunucusu Var mı?' yayını (broadcast) gönderiyor." },
    { name: "OFFER", color: "#f5a623", msg: "Aşama 2/4: DHCP OFFER — Sunucu teklif sunuyor: '192.168.1.100 IP adresini kullanabilirsin'." },
    { name: "REQUEST", color: "#3b9bff", msg: "Aşama 3/4: DHCP REQUEST — İstemci yanıt veriyor: '192.168.1.100 IP adresini kabul ediyorum'." },
    { name: "ACK", color: "#3ddc84", msg: "Aşama 4/4: DHCP ACK — Sunucu IP adresini istemciye başarıyla atadı ve onayladı!" }
  ];

  const packet = $("dhcpPacketAnim");
  const msgBox = $("dhcpSimMsg");
  const stepBadges = document.querySelectorAll(".dhcp-badge-step");

  function nextStep() {
    if (_dhcpSimStep >= steps.length) {
      clearInterval(_dhcpSimTimer);
      _dhcpSimTimer = null;
      if (packet) packet.style.opacity = "0";
      return;
    }

    const cur = steps[_dhcpSimStep];
    if (msgBox) {
      msgBox.style.display = "block";
      msgBox.style.borderColor = cur.color;
      msgBox.style.color = cur.color;
      msgBox.innerHTML = `<strong>[${cur.name}]</strong> ${cur.msg}`;
    }

    stepBadges.forEach((b, idx) => {
      if (idx === _dhcpSimStep) {
        b.style.background = cur.color;
        b.style.color = "#000";
        b.style.fontWeight = "bold";
        b.style.transform = "scale(1.1)";
      } else {
        b.style.background = "var(--panel-2)";
        b.style.color = "var(--txt-2)";
        b.style.transform = "scale(1)";
      }
    });

    if (packet) {
      packet.style.opacity = "1";
      packet.style.background = cur.color;
      if (_dhcpSimStep === 0 || _dhcpSimStep === 2) {
        packet.style.left = "20%";
        setTimeout(() => { if (packet) packet.style.left = "80%"; }, 50);
      } else {
        packet.style.left = "80%";
        setTimeout(() => { if (packet) packet.style.left = "20%"; }, 50);
      }
    }

    _dhcpSimStep++;
  }

  nextStep();
  _dhcpSimTimer = setInterval(nextStep, 2200);
}

/* ---------- SUBNET HESAPLAYICI ---------- */
function calculateSubnetCalc() {
  const ipStr = ($("subCalcIp")?.value || "").trim();
  let maskInput = ($("subCalcMask")?.value || "").trim();
  const resBox = $("subCalcResult");
  if (!resBox) return;

  if (!ipStr) {
    resBox.innerHTML = `<span style="color:var(--red)">Lütfen geçerli bir IP adresi girin.</span>`;
    return;
  }

  let cidr = 24;
  if (maskInput.startsWith("/")) {
    cidr = parseInt(maskInput.slice(1), 10);
  } else if (!isNaN(parseInt(maskInput, 10)) && parseInt(maskInput, 10) <= 32) {
    cidr = parseInt(maskInput, 10);
  } else if (maskInput.includes(".")) {
    const parts = maskInput.split(".").map(Number);
    const bin = parts.map(p => p.toString(2).padStart(8, '0')).join('');
    cidr = bin.indexOf('0') === -1 ? 32 : bin.indexOf('0');
  }

  if (isNaN(cidr) || cidr < 0 || cidr > 32) cidr = 24;

  try {
    const ipParts = ipStr.split(".").map(Number);
    if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) {
      throw new Error("Geçersiz IP formatı");
    }

    const ipNum = ((ipParts[0] << 24) >>> 0) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    const maskNum = cidr === 0 ? 0 : ((0xFFFFFFFF << (32 - cidr)) >>> 0);
    const netNum = (ipNum & maskNum) >>> 0;
    const bcastNum = (netNum | (~maskNum >>> 0)) >>> 0;

    const numToIp = (num) => [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255
    ].join(".");

    const maskStr = numToIp(maskNum);
    const netStr = numToIp(netNum);
    const bcastStr = numToIp(bcastNum);
    const firstUsableStr = cidr >= 31 ? netStr : numToIp(netNum + 1);
    const lastUsableStr = cidr >= 31 ? bcastStr : numToIp(bcastNum - 1);
    const usableHosts = cidr >= 31 ? (cidr === 31 ? 2 : 1) : Math.max(0, (2 ** (32 - cidr)) - 2);

    resBox.innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:10px;margin-top:10px">
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Ağ Adresi (Network ID)</span><br/><strong style="color:var(--blue)">${netStr} /${cidr}</strong></div>
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Alt Ağ Maskesi (Subnet Mask)</span><br/><strong>${maskStr}</strong></div>
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Yayın Adresi (Broadcast)</span><br/><strong style="color:var(--orange)">${bcastStr}</strong></div>
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Kullanılabilir IP Aralığı</span><br/><strong style="color:var(--green)">${firstUsableStr} — ${lastUsableStr}</strong></div>
        <div style="background:var(--panel-2);padding:10px;border-radius:8px;border:1px solid var(--line)"><span style="font-size:10px;color:var(--muted)">Toplam Kullanılabilir Host</span><br/><strong style="color:var(--purple)">${usableHosts.toLocaleString()} cihaz</strong></div>
      </div>
    `;
  } catch (err) {
    resBox.innerHTML = `<span style="color:var(--red)">Hata: ${esc(err.message)}</span>`;
  }
}

const EGITIM_KISALTMALAR_CATEGORIZED = [
  {
    cat: "Basic Networking Terms (Temel Ağ Terimleri)",
    items: [
      ["IP", "Internet Protocol — Ağdaki cihazları adresleyen protokol"],
      ["MAC", "Media Access Control — Donanım kartının fiziksel adresi"],
      ["LAN", "Local Area Network — Yerel alan ağı (Ev/Ofis)"],
      ["WAN", "Wide Area Network — Geniş alan ağı (İnternet)"]
    ]
  },
  {
    cat: "Internet & Communication (İnternet ve İletişim)",
    items: [
      ["DNS", "Domain Name System — Alan adlarını IP adreslerine dönüştürür"],
      ["DHCP", "Dynamic Host Configuration Protocol — Otomatik IP atama servisi"],
      ["HTTP", "HyperText Transfer Protocol — Web içerik aktarım protokolü"],
      ["HTTPS", "HyperText Transfer Protocol Secure — Şifreli web protokolü"],
      ["FTP", "File Transfer Protocol — Dosya aktarım protokolü"]
    ]
  },
  {
    cat: "Security & Protection (Güvenlik ve Koruma)",
    items: [
      ["VPN", "Virtual Private Network — Şifreli özel sanal ağ tüneli"],
      ["SSL", "Secure Sockets Layer — Güvenli soket katmanı şifrelemesi"],
      ["TLS", "Transport Layer Security — Modern taşıma katmanı şifrelemesi"],
      ["IDS", "Intrusion Detection System — Saldırı tespit sistemi"],
      ["IPS", "Intrusion Prevention System — Saldırı önleme sistemi"]
    ]
  },
  {
    cat: "Routing & Switching (Yönlendirme ve Anahtarlama)",
    items: [
      ["TCP", "Transmission Control Protocol — Güvenilir bağlantılı iletim"],
      ["UDP", "User Datagram Protocol — Hızlı bağlantısız iletim"],
      ["ARP", "Address Resolution Protocol — IP adresini MAC adresine çözer"],
      ["VLAN", "Virtual Local Area Network — Mantıksal sanal yerel ağ"],
      ["NAT", "Network Address Translation — Özel IP'leri Genel IP'ye dönüştürür"]
    ]
  },
  {
    cat: "Advanced Concepts (Gelişmiş Konseptler)",
    items: [
      ["QoS", "Quality of Service — Ağ trafiği önceliklendirme kalitesi"],
      ["BGP", "Border Gateway Protocol — İnternet omurgaları arası yönlendirme"],
      ["OSPF", "Open Shortest Path First — En kısa yol odaklı iç yönlendirme"],
      ["MPLS", "Multiprotocol Label Switching — Etiket tabanlı hızlı yönlendirme"]
    ]
  }
];

function filterAbbreviations() {
  const q = ($("abbrSearchInput")?.value || "").toLowerCase().trim();
  const container = $("abbrGridContainer");
  if (!container) return;

  container.innerHTML = EGITIM_KISALTMALAR_CATEGORIZED.map(cat => {
    const filtered = cat.items.filter(item => !q || item[0].toLowerCase().includes(q) || item[1].toLowerCase().includes(q));
    if (!filtered.length) return "";
    return `
      <div style="margin-bottom:14px">
        <h4 style="color:var(--blue);margin:0 0 8px;font-size:12px">${esc(cat.cat)}</h4>
        <div class="kisaltma-grid">
          ${filtered.map(k => `<div class="kisaltma-item"><b>${esc(k[0])}</b><span class="hint">${esc(k[1])}</span></div>`).join("")}
        </div>
      </div>
    `;
  }).join("");
}

const EGITIM_KISALTMALAR = [
  ["IP", "Internet Protocol"], ["MAC", "Media Access Control"], ["LAN", "Local Area Network"], ["WAN", "Wide Area Network"],
  ["DNS", "Domain Name System"], ["DHCP", "Dynamic Host Configuration Protocol"], ["HTTP", "HyperText Transfer Protocol"], ["HTTPS", "HTTP Secure"], ["FTP", "File Transfer Protocol"],
  ["VPN", "Virtual Private Network"], ["SSL", "Secure Sockets Layer"], ["TLS", "Transport Layer Security"], ["IDS", "Intrusion Detection System"], ["IPS", "Intrusion Prevention System"],
  ["TCP", "Transmission Control Protocol"], ["UDP", "User Datagram Protocol"], ["ARP", "Address Resolution Protocol"], ["VLAN", "Virtual Local Area Network"], ["NAT", "Network Address Translation"],
  ["QoS", "Quality of Service"], ["BGP", "Border Gateway Protocol"], ["OSPF", "Open Shortest Path First"], ["MPLS", "Multiprotocol Label Switching"],
];

const EGITIM_KOMUTLAR = [
  ["ipconfig / ifconfig", "Ağ arayüzü yapılandırmasını gösterir"],
  ["ipconfig /all", "Ayrıntılı IP, MAC ve DNS bilgisini gösterir"],
  ["ping [hedef]", "Bir sunucuya erişilebilirliği test eder"],
  ["tracert / traceroute", "Hedefe giden rota üzerindeki her sıçramayı listeler"],
  ["nslookup [alan adı]", "Bir alan adının DNS kaydını sorgular"],
  ["netstat -an", "Aktif bağlantıları ve dinleyen portları listeler"],
  ["arp -a", "Yerel ARP önbelleğini (IP-MAC eşlemesi) gösterir"],
  ["hostname", "Bilgisayarın ağ üzerindeki adını gösterir"],
  ["netsh", "Windows'ta ağ ayarlarını yapılandırır"],
];

const DHCP_ADIMLAR = [
  { k: "DISCOVER", a: "İstemci ağda \"bana bir IP lazım\" diye yayın yapar." },
  { k: "OFFER", a: "DHCP sunucusu uygun bir IP adresi teklif eder." },
  { k: "REQUEST", a: "İstemci teklif edilen IP'yi resmen talep eder." },
  { k: "ACK", a: "Sunucu onaylar; IP artık istemciye atanmıştır." },
];

/* ---------- DETAYLI İNTERNETE BAĞLANMA SİMÜLASYONU ---------- */
let _inetSimTimer = null;
let _inetSimStep = 0;

const INET_SIM_STEPS = [
  {
    step: 1,
    title: "1. Adım: Fiziksel Bağlantı & DHCP ile IP Alma",
    from: "CLIENT (192.168.1.42)",
    to: "ROUTER (192.168.1.1)",
    packetColor: "#22d3ee",
    packetPos: "25%",
    desc: "Bilgisayar yerel ağa bağlandığında DHCP sunucusundan kendi IP adresini (192.168.1.42), ağ geçidini (192.168.1.1) ve DNS sunucularını (8.8.8.8) alır.",
    header: "DHCP DISCOVER / OFFER / REQUEST / ACK — UDP Port 67/68"
  },
  {
    step: 2,
    title: "2. Adım: ARP ile Router MAC Adresini Öğrenme",
    from: "CLIENT",
    to: "ROUTER MAC",
    packetColor: "#a855f7",
    packetPos: "50%",
    desc: "İstemci 'google.com IP'sine paket göndereceğim ama gateway'in MAC adresini bilmeliyim' der. Yerel ağa 'Who has 192.168.1.1?' ARP isteği yayınlar ve router MAC adresini (00:1A:2B:3C:4D:5E) öğrenir.",
    header: "ARP Request / Reply — Ethernet Frame L2 Broadcast"
  },
  {
    step: 3,
    title: "3. Adım: DNS Sorgusu (Domain Name System)",
    from: "ROUTER",
    to: "DNS SUNUCUSU (8.8.8.8)",
    packetColor: "#f5a623",
    packetPos: "75%",
    desc: "İstemci DNS sunucusuna 'google.com adresi hangi IP?' diye sorar. DNS sunucusu yanıt verir: 142.250.187.14.",
    header: "DNS Query — A Record google.com ➔ 142.250.187.14 (UDP Port 53)"
  },
  {
    step: 4,
    title: "4. Adım: TCP 3-Way Handshake (Üçlü El Sıkışma)",
    from: "CLIENT",
    to: "WEB SUNUCUSU (142.250.187.14:443)",
    packetColor: "#3b9bff",
    packetPos: "85%",
    desc: "Google sunucusuyla güvenilir taşıma katmanı bağlantısı kurulur: 1) SYN ➔ 2) SYN-ACK ➔ 3) ACK. Sıra numaraları senkronize edilir.",
    header: "TCP Flag: SYN ➔ SYN+ACK ➔ ACK (Port 443)"
  },
  {
    step: 5,
    title: "5. Adım: TLS / SSL Güvenlik El Sıkışması",
    from: "CLIENT",
    to: "GOOGLE SSL SERVER",
    packetColor: "#a855f7",
    packetPos: "92%",
    desc: "İstemci 'Client Hello' gönderir, sunucu SSL sertifikasını sunar. Şifreleme algoritmaları (AES-256-GCM) ve simetrik oturum anahtarları oluşturulur. Artık tüm trafik şifrelidir!",
    header: "TLS 1.3 Handshake — Cipher Suite: TLS_AES_256_GCM_SHA384"
  },
  {
    step: 6,
    title: "6. Adım: Şifreli HTTP GET İsteği & Web Sayfası Yükleme",
    from: "GOOGLE SUNUCUSU",
    to: "CLIENT (200 OK)",
    packetColor: "#3ddc84",
    packetPos: "100%",
    desc: "İstemci şifreli tünelden 'GET / HTTP/2' isteği gönderir. Google sunucusu HTML/CSS/JS web verilerini 'HTTP/2 200 OK' yanıtıyla iletir ve sayfa ekranda görüntülenir!",
    header: "HTTP/2 200 OK — Content-Type: text/html; charset=UTF-8"
  }
];

function startInternetConnectionSim() {
  if (_inetSimTimer) clearInterval(_inetSimTimer);
  _inetSimStep = 0;

  const packet = $("inetPacketAnim");
  const msgBox = $("inetSimMsg");
  const stepBadges = document.querySelectorAll(".inet-badge-step");

  function nextStep() {
    if (_inetSimStep >= INET_SIM_STEPS.length) {
      clearInterval(_inetSimTimer);
      _inetSimTimer = null;
      if (packet) packet.style.opacity = "0";
      return;
    }

    const cur = INET_SIM_STEPS[_inetSimStep];
    if (msgBox) {
      msgBox.style.display = "block";
      msgBox.style.borderColor = cur.packetColor;
      msgBox.innerHTML = `
        <div style="color:${cur.packetColor};font-weight:bold;font-size:13px;margin-bottom:4px">${esc(cur.title)}</div>
        <div style="font-size:11.5px;color:var(--txt);margin-bottom:6px">${esc(cur.desc)}</div>
        <div style="font-family:Consolas, monospace;font-size:10.5px;color:var(--muted);background:rgba(0,0,0,0.3);padding:4px 8px;border-radius:4px">📦 Başlık Bilgisi: ${esc(cur.header)}</div>
      `;
    }

    stepBadges.forEach((b, idx) => {
      if (idx === _inetSimStep) {
        b.style.background = cur.packetColor;
        b.style.color = "#000";
        b.style.fontWeight = "bold";
        b.style.transform = "scale(1.08)";
      } else {
        b.style.background = "var(--panel-2)";
        b.style.color = "var(--txt-2)";
        b.style.transform = "scale(1)";
      }
    });

    if (packet) {
      packet.style.opacity = "1";
      packet.style.background = cur.packetColor;
      packet.style.left = cur.packetPos;
    }

    _inetSimStep++;
  }

  nextStep();
  _inetSimTimer = setInterval(nextStep, 2600);
}

/* ---------- ETKİLEŞİMLİ KAVRAM MODALİ (CLICK TO ENLARGE) ---------- */
const CONCEPT_DETAILS = {
  ip: {
    title: "IP Adresi (Internet Protocol)",
    sub: "Ağ Katmanı (Katman 3)",
    desc: "IP adresi, ağa bağlı her cihaza atanan mantıksal numaradır. Veri paketlerinin kaynak ve hedef arasında yönlendirilmesini sağlar.",
    example: "Örnek: Evinizdeki bilgisayarın yerel IP'si 192.168.1.45 iken, internetteki genel IP'niz 185.12.34.56 olabilir.",
    details: ["IPv4: 32-bit (örn. 192.168.1.1) — yaklaşık 4.3 milyar adres kapasitesi.", "IPv6: 128-bit (örn. 2001:0db8:85a3::8a2e:0370:7334) — neredeyse sınırsız adres kapasitesi."]
  },
  dns: {
    title: "DNS (Domain Name System)",
    sub: "Uygulama Katmanı (Katman 7)",
    desc: "İnsanların hatırlayabileceği alan adlarını (örn. google.com) bilgisayarların anladığı IP adreslerine (142.250.187.14) çeviren küresel yönlendirme sistemidir.",
    example: "Örnek: Tarayıcıya 'google.com' yazdığınızda, işletim sisteminiz öncelikle DNS sunucusuna sorgu atarak doğru IP adresini öğrenir.",
    details: ["Önbellekleme: Sık ziyaret edilen siteler bilgisayarınızda önbelleğe alınır.", "Sorgu Tipleri: A Record (IPv4), AAAA Record (IPv6), CNAME (Alias), MX (Mail)."]
  },
  port: {
    title: "Port (Bağlantı Noktası)",
    sub: "Taşıma Katmanı (Katman 4)",
    desc: "Aynı IP adresi üzerinde çalışan farklı uygulamaları ve servisleri ayırt etmeye yarayan 0-65535 arasındaki sanal kanallardır.",
    example: "Örnek: Aynı sunucuda Web sitesi Port 80/443'te, E-posta Port 25'te, SSH erişimi Port 22'de çalışır.",
    details: ["Tanınmış Portlar (0-1023): HTTP(80), HTTPS(443), SSH(22), DNS(53).", "Kayıtlı Portlar (1024-49151): MySQL(3306), RDP(3389)."]
  },
  mac: {
    title: "MAC Adresi (Media Access Control)",
    sub: "Veri Bağlantı Katmanı (Katman 2)",
    desc: "Ağ kartına (NIC) üretim aşamasında kazınan 48-bitlik eşsiz fiziksel adrestir.",
    example: "Örnek: 00:1A:2B:3C:4D:5E — İlk 3 blok (00:1A:2B) üretici firmayı (OUI/Vendor) gösterir.",
    details: ["Fiziksel İletim: Aynı yerel ağ (LAN) içindeki paketler IP değil MAC adresiyle teslim edilir.", "Değiştirilemezlik: IP adresi değişse bile MAC adresi sabit kalır."]
  },
  nat: {
    title: "NAT (Network Address Translation)",
    sub: "Ağ / Router Katmanı",
    desc: "Evinizdeki onlarca cihazın tek bir genel (Public) IP adresi arkasından internete çıkmasını sağlayan adrese çevirme teknolojisidir.",
    example: "Örnek: 192.168.1.10 ve 192.168.1.20 cihazları internete çıkarken modem hepsini tek bir Kamu IP'sine (85.100.1.2) dönüştürür.",
    details: ["PAT (Port Address Translation): Her yerel istemcinin bağlantısını farklı bir dış kaynak portu ile eşleştirir.", "IPv4 Tasarrufu: Dünyadaki IP adresi tükenmesini önleyen en kritik teknolojidir."]
  },
  dhcp: {
    title: "DHCP (Dynamic Host Configuration Protocol)",
    sub: "Uygulama / Yönetim Katmanı",
    desc: "Ağa yeni katılan cihazlara otomatik olarak IP Adresi, Alt Ağ Maskesi, Gateway ve DNS bilgilerini kiralayan servistir.",
    example: "Örnek: Telefonunuzla Wi-Fi'ya bağlandığınız an DHCP sunucusu 192.168.1.105 IP'sini cihazınıza kiralar.",
    details: ["DORA Akışı: Discover ➔ Offer ➔ Request ➔ Acknowledge.", "Kira Süresi (Lease Time): Belirlenen süre sonunda cihaz IP'yi yeniler."]
  },
  packets: {
    title: "Ağ Paketleri (Packets)",
    sub: "Veri İletim Yapısı",
    desc: "İnternet üzerindeki veriler tek parça halinde değil, küçük paketlere bölünerek iletilir. Her pakette Başlık (Header) ve Veri (Payload) bulunur.",
    example: "Örnek: 10 MB'lık bir fotoğraf dosyası ağda yaklaşık 7,000 küçük veri paketine bölünerek hedefe aktarılır.",
    details: ["Header İçeriği: Kaynak IP, Hedef IP, Port Numaraları, Sıra No.", "Yeniden Birleştirme: Hedef cihaz gelen paketleri sıra numarasına göre doğru sırada birleştirir."]
  },
  osi: {
    title: "OSI Modeli (Open Systems Interconnection)",
    sub: "7 Katmanlı Referans Mimarisi",
    desc: "Ağ iletişimini 7 standart katmana bölen kavramsal modeldir: 7.Uygulama, 6.Sunum, 5.Oturum, 4.Taşıma, 3.Ağ, 2.Veri Bağlantı, 1.Fiziksel.",
    example: "Örnek: Web tarayıcısı Katman 7'de çalışırken, ağ kablosu ve elektrik sinyalleri Katman 1'dedir.",
    details: ["Kapsülleme (Encapsulation): Üst katmandan gelen veri alt katmanlara indikçe yeni başlıklar (headers) eklenir.", "Katman Ayrımı: Her katman yalnızca bir altındaki ve üstündeki katmanla iletişim kurar."]
  },
  subnet: {
    title: "Subnetting & CIDR",
    sub: "Alt Ağ Yönetimi",
    desc: "Büyük bir IP ağını mantıksal parçalara bölme işlemidir. CIDR gösterimi (/24 gibi) ağın kaç IP içerdiğini belirtir.",
    example: "Örnek: /24 ağı (255.255.255.0) toplam 256 IP içerir; 254 cihaz kullanılabilir.",
    details: ["Network ID: Ağın ilk adresidir.", "Broadcast ID: Ağın tüm cihazlara yayın yapan son adresidir."]
  },
  routersw: {
    title: "Router vs Switch",
    sub: "Ağ Donanımları",
    desc: "Switch aynı yerel ağdaki (LAN) cihazları birbirine bağlar. Router ise farklı ağları (LAN ➔ WAN / İnternet) birbirine bağlar ve yönlendirir.",
    example: "Örnek: Odadaki bilgisayarlar Switch'e bağlanır; Switch de internete çıkmak için Router'a bağlanır.",
    details: ["Switch (L2): MAC adresleri tablosuna (CAM Table) bakarak anahtarlama yapar.", "Router (L3): IP yönlendirme tablosuna bakarak en uygun rotayı seçer."]
  },
  tcpudp: {
    title: "TCP vs UDP",
    sub: "Taşıma Katmanı (Katman 4)",
    desc: "TCP güvenilir, kontrollü ve sıralı iletim sağlar. UDP ise onay beklemeden çok hızlı veri aktarır.",
    example: "Örnek: Web siteleri ve dosya indirme TCP kullanırken; canlı yayınlar ve online oyunlar UDP kullanır.",
    details: ["TCP: 3-Way Handshake, Kayıp Paket Yeniden Gönderimi, Akış Kontrolü.", "UDP: Düşük gecikme, Başlık boyutu küçük (8 byte vs TCP 20 byte)."]
  },
  http: {
    title: "HTTP / HTTPS",
    sub: "Web Protokolü",
    desc: "HTTP web içeriklerini aktarır. HTTPS ise bu trafiği TLS/SSL şifrelemesi ile koruma altına alır.",
    example: "Örnek: HTTPS kullanıldığında aradaki bir hacker şifrenizi veya kredi kartı bilginizi okuyamaz.",
    details: ["HTTP Portu: 80 (Düz metin / Açık).", "HTTPS Portu: 443 (Şifreli / Güvenli)."]
  },
  tls: {
    title: "TLS / SSL Şifreleme",
    sub: "Güvenli İletişim Katmanı",
    desc: "İstemci ile sunucu arasında el sıkışma yaparak verileri simetrik şifreleme (AES) ile koruyan protokoldür.",
    example: "Örnek: Banka sitelerinde tarayıcıda görünen yeşil kilit simgesi TLS el sıkışmasının başarılı olduğunu gösterir.",
    details: ["Sertifika Doğrulama: Sunucunun kimliği dijital sertifika ile doğrulanır.", "Asimetrik ➔ Simetrik: Anahtar değişimi asimetrik (RSA/ECC), veri iletimi simetrik (AES) yapılır."]
  },
  firewall: {
    title: "Firewall (Güvenlik Duvarı)",
    sub: "Ağ Güvenlik Sistemi",
    desc: "Belirlenen güvenlik kurallarına göre ağ trafiğini denetleyen, yetkisiz erişimleri engelleyen sistemdir.",
    example: "Örnek: Port 23 (Telnet) ve Port 21 (FTP) dış dünyadan gelen isteklere otomatik engellenir.",
    details: ["Packet Filtering: IP, Port ve Protokol bazlı engelleme.", "Stateful Inspection: Bağlantının durumunu takip ederek karar verme."]
  },
  vpn: {
    title: "VPN (Virtual Private Network)",
    sub: "Sanal Özel Ağ Tüneli",
    desc: "İnternet üzerinde uçtan uca şifreli uç nokta tüneli oluşturarak güvenli uzaktan erişim sağlar.",
    example: "Örnek: Evden çalışırken şirket içi sunuculara sanki ofisteymiş gibi güvenle bağlanmanızı sağlar.",
    details: ["Tünelleme Protokolleri: OpenVPN, WireGuard, IPsec.", "Gizlilik: İSS veya yetkisiz 3. kişilerin trafiğinizi izlemesini engeller."]
  }
};

function openConceptModal(key) {
  const c = CONCEPT_DETAILS[key] || CONCEPT_DETAILS.ip;
  const diagramSvg = diagramFor(key);

  openModal(`
    <div style="text-align:center;margin-bottom:14px">
      <div style="background:var(--panel-2);border:1px solid var(--line);border-radius:12px;padding:16px;display:inline-block;margin-bottom:10px">
        <div style="width:280px;height:120px;display:grid;place-items:center">${diagramSvg}</div>
      </div>
      <h2 style="margin:4px 0;font-size:18px">${esc(c.title)}</h2>
      <span class="badge info">${esc(c.sub)}</span>
    </div>

    <div style="background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:12px;margin-bottom:12px;font-size:12px;line-height:1.5">
      ${esc(c.desc)}
    </div>

    <div style="background:rgba(61,220,132,0.08);border:1px solid rgba(61,220,132,0.25);border-radius:10px;padding:10px 12px;margin-bottom:12px;font-size:11.5px;color:var(--green)">
      💡 <strong>Gerçek Hayat Örneği:</strong> ${esc(c.example)}
    </div>

    <div style="border-top:1px solid var(--line);padding-top:10px">
      <b style="font-size:11px;color:var(--muted);display:block;margin-bottom:6px">TEKNİK DETAYLAR & STANDARTLAR</b>
      ${c.details.map(d => `<div style="font-size:11px;color:var(--txt-2);margin-bottom:4px">✓ ${esc(d)}</div>`).join("")}
    </div>

    <div style="display:flex;justify-content:flex-end;margin-top:16px">
      <button class="mini-btn blue" onclick="closeModalForce()">Kapat</button>
    </div>
  `);
}

async function openAcademyQuiz(moduleId) {
  try {
    const data = await get(`/api/academy/modules/${encodeURIComponent(moduleId)}`);
    const q = data.quiz;
    openModal(`
      <div class="modal-head"><h3>${esc(data.title)} — Mini Quiz</h3><button class="modal-close" onclick="closeModalForce()">×</button></div>
      <div class="modal-body">
        <div class="device-learning" style="margin-bottom:12px"><b>${esc(q.question)}</b></div>
        <div id="academyQuizOptions" style="display:grid;gap:8px">
          ${q.options.map((opt,i)=>`<button class="mini-btn" style="text-align:left;padding:10px" onclick="submitAcademyQuiz('${esc(moduleId)}',${i},this)">${String.fromCharCode(65+i)}. ${esc(opt)}</button>`).join("")}
        </div>
        <div id="academyQuizResult" style="margin-top:12px"></div>
      </div>
    `);
  } catch (e) { toast(e.message || "Quiz yüklenemedi", "error"); }
}

async function submitAcademyQuiz(moduleId, answer, btn) {
  try {
    const result = await post("/api/academy/quiz", {module_id: moduleId, answer});
    document.querySelectorAll("#academyQuizOptions button").forEach(b => b.disabled = true);
    const box = $("academyQuizResult");
    if (box) box.innerHTML = `<div class="device-learning ${result.correct ? "success" : "warning"}"><b>${result.correct ? "✓ Doğru" : "✗ Tekrar dene"}</b><div>${esc(result.message)}</div></div>`;
    if (result.correct) {
      const done = JSON.parse(localStorage.getItem("netmon_academy_done") || "[]");
      if (!done.includes(moduleId)) { done.push(moduleId); localStorage.setItem("netmon_academy_done", JSON.stringify(done)); }
    }
  } catch (e) { toast(e.message || "Cevap gönderilemedi", "error"); }
}

function renderEgitimPage() {
  const el = $("page-egitim");
  if (el.dataset.built) return;
  el.dataset.built = "1";
  el.innerHTML = `
    <div class="panel">
      <div class="panel-head" style="justify-content:center;border-bottom:none;padding-bottom:0">
        <h2 style="font-size:24px;text-align:center"><span style="color:#fff">15 Must-Know</span> <span style="background:var(--green);color:#000;padding:2px 8px;border-radius:6px;font-weight:800">Networking Concepts</span></h2>
      </div>
      <div class="panel-body">
        <div class="egitim-grid" style="display:grid;grid-template-columns:repeat(auto-fill, minmax(240px, 1fr));gap:16px;">
          ${EGITIM_KAVRAMLAR.map(
            (k, index) => `
            <div class="egitim-card" onclick="openConceptModal('${k.key}')" style="cursor:pointer;background:#0d1117;border:1px solid #30363d;border-radius:12px;padding:16px;display:flex;flex-direction:column;align-items:center;transition:transform 0.2s" onmouseover="this.style.transform='translateY(-4px)'" onmouseout="this.style.transform='none'">
              <div style="color:var(--green);font-weight:800;font-size:15px;margin-bottom:12px;letter-spacing:0.5px">${index+1}. ${esc(k.ad)}</div>
              <div class="egitim-diagram" style="width:100%;height:100px;background:#010409;border:1px solid #21262d;border-radius:8px;display:flex;align-items:center;justify-content:center;overflow:hidden">${diagramFor(k.key)}</div>
              <div style="color:#8b949e;font-size:11.5px;text-align:center;margin-top:12px;line-height:1.4">${esc(k.ozet)}</div>

            </div>`
          ).join("")}
        </div>
      </div>
    </div>

    <!-- DETAYLI İNTERNETE BAĞLANMA SİMÜLASYONU -->
    <div class="panel" style="margin-top:14px">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
        <h2>Detaylı İnternete Bağlanma Akış Simülasyonu</h2>
        <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;">
          <button class="mini-btn blue" onclick="startInternetConnectionSim()">🚀 İnternete Bağlanma Akışını Başlat</button>
        </div>
      </div>
      <div class="panel-body">
        <div style="position:relative;background:#060a12;border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:12px;overflow:hidden">
          <div style="display:flex;justify-content:space-between;align-items:center;position:relative;z-index:2;flex-wrap:wrap;gap:10px">
            <div style="text-align:center;background:var(--panel-2);border:1px solid var(--line);padding:10px 14px;border-radius:10px;min-width:110px">
              <div style="font-size:22px">💻</div>
              <strong style="font-size:11px">İstemci PC</strong>
              <div style="font-size:9.5px;color:var(--muted)">192.168.1.42</div>
            </div>

            <div style="text-align:center;background:var(--panel-2);border:1px solid var(--line);padding:10px 14px;border-radius:10px;min-width:110px">
              <div style="font-size:22px">🔀</div>
              <strong style="font-size:11px;color:var(--cyan)">Ev Router</strong>
              <div style="font-size:9.5px;color:var(--muted)">192.168.1.1</div>
            </div>

            <div style="text-align:center;background:var(--panel-2);border:1px solid var(--line);padding:10px 14px;border-radius:10px;min-width:110px">
              <div style="font-size:22px">🌐</div>
              <strong style="font-size:11px;color:var(--orange)">DNS Sunucu</strong>
              <div style="font-size:9.5px;color:var(--muted)">8.8.8.8</div>
            </div>

            <div style="text-align:center;background:var(--panel-2);border:1px solid var(--line);padding:10px 14px;border-radius:10px;min-width:110px">
              <div style="font-size:22px">🔒</div>
              <strong style="font-size:11px;color:var(--green)">Google Web</strong>
              <div style="font-size:9.5px;color:var(--muted)">142.250.187.14</div>
            </div>
          </div>

          <div style="position:relative;height:4px;background:var(--line);margin:18px 0 12px">
            <div id="inetPacketAnim" style="position:absolute;width:14px;height:14px;border-radius:50%;background:var(--blue);top:-5px;left:0%;opacity:0;transition:left 2.2s ease-in-out, opacity 0.3s;box-shadow:0 0 12px currentColor"></div>
          </div>

          <div style="display:flex;justify-content:space-between;gap:6px;margin-top:14px;flex-wrap:wrap">
            ${INET_SIM_STEPS.map(
              (s) => `<div class="inet-badge-step" style="flex:1;min-width:90px;text-align:center;padding:5px 6px;border-radius:6px;background:var(--panel-2);color:var(--txt-2);font-size:10px;border:1px solid var(--line);transition:all 0.3s">${s.step}. ${s.title.split(":")[0]}</div>`
            ).join("")}
          </div>

          <div id="inetSimMsg" style="display:none;margin-top:14px;padding:12px;border-radius:8px;background:rgba(255,255,255,0.02);border:1px solid var(--line);"></div>
        </div>
      </div>
    </div>

    <!-- CANLI DHCP DORA SİMÜLATÖRÜ -->
    <div class="panel" style="margin-top:20px;background:#060a12;border:none">
      <div class="panel-body" style="padding:40px 20px;display:flex;flex-direction:column;align-items:center">

        <div style="text-align:left;width:100%;max-width:700px;margin-bottom:30px">
           <h1 style="color:#fff;font-size:20px;letter-spacing:1px;margin:0">DHCP &mdash; LIVE ANIMATED EXAMPLE</h1>
           <div id="dhcpSimSubtitle" style="color:var(--blue);font-size:12px;font-weight:bold;margin-top:6px">Step 1 of 4: DHCP DISCOVER</div>
        </div>

        <div style="display:flex;align-items:center;justify-content:center;width:100%;max-width:700px;position:relative">

           <!-- Client -->
           <div style="width:140px;height:140px;border:2px solid var(--blue);border-radius:12px;display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(59,155,255,0.05);z-index:2">
              <div style="font-size:40px;margin-bottom:10px">💻</div>
              <div style="color:var(--blue);font-weight:bold;font-size:11px;letter-spacing:0.5px">DHCP CLIENT</div>
           </div>

           <!-- Network Arrow Container -->
           <div style="flex:1;height:2px;background:var(--orange);margin:0 -2px;position:relative;display:flex;align-items:center;justify-content:center;z-index:1">
              <div style="position:absolute;width:120px;height:50px;border:1px solid #30363d;border-radius:50%;background:#0d1117;display:flex;align-items:center;justify-content:center;color:#8b949e;font-size:10px;font-weight:bold;letter-spacing:1px;z-index:2">NETWORK</div>
              <!-- Packet Dot -->
              <div id="dhcpPacketAnim" style="position:absolute;width:16px;height:16px;border-radius:50%;background:var(--orange);box-shadow:0 0 12px var(--orange);top:-7px;left:5%;opacity:0;transition:left 1.5s ease-in-out, opacity 0.2s;z-index:3"></div>
           </div>
           <div style="color:var(--orange);font-size:24px;margin-left:-15px;z-index:2;line-height:0;margin-top:-3px">▶</div>

           <!-- Server -->
           <div style="width:140px;height:140px;border:2px solid var(--green);border-radius:12px;display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(61,220,132,0.05);z-index:2;position:relative">
              <div style="font-size:40px;margin-bottom:10px">🗄️</div>
              <div style="color:var(--green);font-weight:bold;font-size:11px;letter-spacing:0.5px">DHCP SERVER</div>
              <div style="position:absolute;bottom:-10px;right:-10px;width:24px;height:24px;background:var(--green);color:#000;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:bold">25</div>
           </div>
        </div>

        <!-- Simulation Message -->
        <div id="dhcpSimMsg" style="color:#fff;font-size:14px;font-weight:bold;margin-top:30px;height:20px;text-align:center">Click a step below to animate</div>

        <!-- Buttons -->
        <div style="display:flex;gap:12px;margin-top:20px">
           <button class="mini-btn" style="background:#21262d;border:none;padding:10px 20px;font-size:11px;font-weight:bold;letter-spacing:0.5px" onclick="playDhcpStep(1)">DISCOVER</button>
           <button class="mini-btn" style="background:#21262d;border:none;padding:10px 20px;font-size:11px;font-weight:bold;letter-spacing:0.5px" onclick="playDhcpStep(2)">OFFER</button>
           <button class="mini-btn blue" style="padding:10px 20px;font-size:11px;font-weight:bold;letter-spacing:0.5px" onclick="playDhcpStep(3)">REQUEST</button>
           <button class="mini-btn" style="background:#21262d;border:none;padding:10px 20px;font-size:11px;font-weight:bold;letter-spacing:0.5px" onclick="playDhcpStep(4)">ACK</button>
        </div>
      </div>
    </div>

    <!-- SUBNETTING & CIDR HESAPLAYICI -->
    <div class="panel" style="margin-top:14px">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Subnetting & CIDR Hesaplayıcı</h2></div>
      <div class="panel-body">
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
          <input type="text" id="subCalcIp" placeholder="IP Adresi (örn: 192.168.1.100)" value="192.168.1.100" style="flex:1;min-width:200px" />
          <input type="text" id="subCalcMask" placeholder="CIDR Prefix veya Maske (örn: /24 veya 255.255.255.0)" value="/24" style="width:220px" />
          <button class="mini-btn blue" onclick="calculateSubnetCalc()">Hesapla</button>
        </div>
        <div id="subCalcResult"></div>
      </div>
    </div>

    <!-- SIK KULLANILAN AĞ KOMUTLARI -->
    <div class="panel" style="margin-top:14px">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;"><h2>Sık Kullanılan Ağ Komutları</h2></div>
      <div class="panel-body" style="padding:0">
        <table>
          <thead><tr><th>Komut</th><th>Ne İşe Yarar</th></tr></thead>
          <tbody>
            ${EGITIM_KOMUTLAR.map((c) => `<tr><td><code>${esc(c[0])}</code></td><td>${esc(c[1])}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <!-- KATEGORİK AĞ KISALTMALARI SÖZLÜĞÜ -->
    <div class="panel" style="margin-top:14px">
      <div class="panel-head" style="flex-wrap:wrap; height:auto; padding:12px; gap:12px;">
        <h2>Ağ Kısaltmaları Sözlüğü</h2>
        <div class="right" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;">
          <input type="text" id="abbrSearchInput" placeholder="Kısaltma veya tanım ara..." oninput="filterAbbreviations()" style="padding:4px 8px;font-size:11px;width:180px" />
        </div>
      </div>
      <div class="panel-body" id="abbrGridContainer">
        ${EGITIM_KISALTMALAR_CATEGORIZED.map(cat => `
          <div style="margin-bottom:14px">
            <h4 style="color:var(--blue);margin:0 0 8px;font-size:12px">${esc(cat.cat)}</h4>
            <div class="kisaltma-grid">
              ${cat.items.map(k => `<div class="kisaltma-item"><b>${esc(k[0])}</b><span class="hint">${esc(k[1])}</span></div>`).join("")}
            </div>
          </div>
        `).join("")}
      </div>
    </div>
  `;

  setTimeout(calculateSubnetCalc, 100);
}

/* ---------- MOR TAKIM (XOC / SOC / NOC) MODÜLÜ ---------- */

Object.assign(globalThis, {
  EGITIM_KAVRAMLAR,
  _c,
  DIAGRAMS,
  diagramFor,
  _dhcpSimTimer,
  _dhcpSimStep,
  startDhcpSimulation,
  calculateSubnetCalc,
  EGITIM_KISALTMALAR_CATEGORIZED,
  filterAbbreviations,
  EGITIM_KISALTMALAR,
  EGITIM_KOMUTLAR,
  DHCP_ADIMLAR,
  _inetSimTimer,
  _inetSimStep,
  INET_SIM_STEPS,
  startInternetConnectionSim,
  CONCEPT_DETAILS,
  openConceptModal,
  openAcademyQuiz,
  submitAcademyQuiz,
  renderEgitimPage,
});
