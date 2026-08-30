import "./device-experience.js";

let onboardingSkipped = false;
let onboardingStep = 1;

function maybeShowOnboarding() {
  if (onboardingSkipped || S.scanning || (S.devices || []).length || $("onboardingWizard")) return;
  const wizard = document.createElement("div");
  wizard.id = "onboardingWizard"; wizard.className = "onboarding-overlay";
  wizard.innerHTML = `<section class="onboarding-card"><header><small>NETMON İLK KURULUM</small><h2>Ağınızı üç adımda keşfedin</h2><div class="onboarding-steps"><i class="active">1</i><i>2</i><i>3</i></div></header><div id="onboardingPane"></div><footer><button class="mini-btn" onclick="skipOnboarding()">Atla, manuel devam et</button><div><button class="mini-btn" id="onboardingBack" onclick="changeOnboardingStep(-1)">Geri</button><button class="mini-btn blue" id="onboardingNext" onclick="changeOnboardingStep(1)">Devam</button></div></footer></section>`;
  document.body.appendChild(wizard); renderOnboardingStep();
}

function renderOnboardingStep() {
  const pane = $("onboardingPane"); if (!pane) return;
  document.querySelectorAll(".onboarding-steps i").forEach((item,index) => item.classList.toggle("active", index < onboardingStep));
  $("onboardingBack").hidden = onboardingStep === 1; $("onboardingNext").textContent = onboardingStep === 3 ? "İlk taramayı başlat" : "Devam";
  if (onboardingStep === 1) pane.innerHTML = `<label>Keşfedilecek subnet / CIDR<input id="onboardSubnet" value="${esc(S.settings?.subnet || "192.168.1.0/24")}" placeholder="192.168.1.0/24"></label><p>Yalnızca yetkili olduğunuz özel ağ aralıklarını girin.</p>`;
  if (onboardingStep === 2) pane.innerHTML = `<p>Kimlik bilgileri isteğe bağlıdır ve backend tarafından şifreli saklanır.</p><label>WMI kullanıcı adı<input id="onboardWmiUser"></label><label>WMI parolası<input id="onboardWmiPass" type="password"></label><label>SSH kullanıcı adı<input id="onboardSshUser"></label><label>SSH parolası<input id="onboardSshPass" type="password"></label><label>SNMP community<input id="onboardSnmp" type="password"></label>`;
  if (onboardingStep === 3) pane.innerHTML = `<div class="onboarding-ready"><b>Hazır</b><span>Ayarlar kaydedilecek ve ilk agentless keşif başlatılacak.</span><div class="onboarding-progress"><i id="onboardingProgress"></i></div></div>`;
}

async function changeOnboardingStep(delta) {
  if (delta < 0) { onboardingStep = Math.max(1, onboardingStep - 1); renderOnboardingStep(); return; }
  if (onboardingStep === 1) { const subnet = $("onboardSubnet")?.value.trim(); if (!subnet) return toast("Subnet/CIDR girin.", "warn"); S.onboarding = { subnet }; onboardingStep = 2; renderOnboardingStep(); return; }
  if (onboardingStep === 2) { S.onboarding = { ...(S.onboarding || {}), wmi_username: $("onboardWmiUser")?.value.trim(), wmi_password: $("onboardWmiPass")?.value, ssh_username: $("onboardSshUser")?.value.trim(), ssh_password: $("onboardSshPass")?.value, snmp_community: $("onboardSnmp")?.value }; onboardingStep = 3; renderOnboardingStep(); return; }
  const button = $("onboardingNext"); if (button) button.disabled = true;
  try { const settings = Object.fromEntries(Object.entries(S.onboarding || {}).filter(([,value]) => value)); await post("/api/settings", settings); const progress = $("onboardingProgress"); if (progress) progress.style.width = "35%"; await scanNetwork(); if (progress) progress.style.width = "100%"; setTimeout(() => { $("onboardingWizard")?.remove(); go("dashboard"); }, 350); }
  catch (error) { toast(`İlk kurulum tamamlanamadı: ${error.message}`, "fail"); if (button) button.disabled = false; }
}

function skipOnboarding() { onboardingSkipped = true; $("onboardingWizard")?.remove(); }

Object.assign(globalThis, { maybeShowOnboarding, renderOnboardingStep, changeOnboardingStep, skipOnboarding });
