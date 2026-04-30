const STORE = "phisher-enterprise-v7";
const SHIFT_SECONDS = 30 * 60;
const TABS = ["preview", "headers", "auth", "links", "attachments"];
const THREAT_URLS = {
  itSupport: "https://help-okta-auth.com",
  office365: "https://com-verify.ru",
  shipping: "https://shipping-tracker-update.com",
  cfoWire: "https://sharepoint-docs-access.net",
  knownKit: "https://microsoft-update.xyz"
};
const CLEAN_URLS = [
  "https://yourcompany.com",
  "https://workday.com",
  "https://zoom.us"
];
const USER_PROFILES = {
  "Maya Torres (CFO)": { department: "Finance", riskScore: 94 },
  "Rafi Islam (IT Admin)": { department: "IT", riskScore: 71 },
  "Nina Patel (Sales Intern)": { department: "Sales", riskScore: 67 },
  "Liam Chowdhury (Security Analyst)": { department: "SOC", riskScore: 48 },
  "Sadia Rahman (HR Lead)": { department: "HR", riskScore: 38 },
  "Omar Khan (Finance Manager)": { department: "Finance", riskScore: 86 },
  "Jui Sarker (Operations)": { department: "Operations", riskScore: 52 }
};
const REASON_CODES = [
  "Authentication Failure",
  "Domain Spoofing",
  "Malicious Link",
  "Malicious Attachment",
  "Social Engineering",
  "Known Safe Sender",
  "Internal Communication"
];

let state = load();
let selected = state.incidents[0]?.id || null;
let answerKey = false;
let shiftTimer = null;
let currentView = "inbox";

function load() {
  const raw = localStorage.getItem(STORE);
  if (!raw) return freshState();
  try {
    const parsed = JSON.parse(raw);
    parsed.incidents = (parsed.incidents || []).map(normalizeIncident);
    parsed.filters = parsed.filters || { room: "all", phishml: "all", priority: "all", status: "all", query: "" };
    parsed.shiftEndsAt = parsed.shiftEndsAt || (Date.now() + SHIFT_SECONDS * 1000);
    parsed.currentView = parsed.currentView || "inbox";
    parsed.highContrast = Boolean(parsed.highContrast);
    parsed.finalFiveInjected = Boolean(parsed.finalFiveInjected);
    parsed.muted = Boolean(parsed.muted);
    parsed.tutorialSeen = Boolean(parsed.tutorialSeen);
    return parsed;
  } catch {
    return freshState();
  }
}

function freshState() {
  return {
    incidents: generateIncidents(55).concat(generateQuishingIncidents(10)),
    filters: { room: "all", phishml: "all", priority: "all", status: "all", query: "" },
    shiftEndsAt: Date.now() + SHIFT_SECONDS * 1000,
    currentView: "inbox",
    highContrast: false,
    finalFiveInjected: false,
    muted: false,
    tutorialSeen: false
  };
}

function save() {
  state.currentView = currentView;
  localStorage.setItem(STORE, JSON.stringify(state));
}

function playTone(freq, durationMs, type = "sine", volume = 0.04) {
  if (state.muted) return;
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (!AudioCtx) return;
  const ctx = new AudioCtx();
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = type;
  osc.frequency.value = freq;
  gain.gain.value = volume;
  osc.connect(gain);
  gain.connect(ctx.destination);
  osc.start();
  setTimeout(() => {
    osc.stop();
    ctx.close();
  }, durationMs);
}

function playCue(name) {
  if (name === "resolve") {
    playTone(840, 90, "triangle", 0.05);
    setTimeout(() => playTone(1240, 120, "triangle", 0.05), 100);
  } else if (name === "datastream") {
    [420, 520, 620, 720].forEach((f, idx) => setTimeout(() => playTone(f, 75, "square", 0.02), idx * 85));
  } else if (name === "warning") {
    playTone(320, 180, "sawtooth", 0.06);
    setTimeout(() => playTone(260, 180, "sawtooth", 0.06), 200);
  }
}

function normalizeIncident(i) {
  return {
    ...i,
    status: i.status || "received",
    tab: i.tab || "preview",
    tags: i.tags || [],
    noteDraft: i.noteDraft || "",
    discussion: i.discussion || [],
    attachments: i.attachments || [],
    extractedQrUrl: i.extractedQrUrl || "",
    expectedDisposition: i.expectedDisposition || i.phishml,
    reporterProfile: i.reporterProfile || inferReporterProfile(i.reporter),
    reasonCode: i.reasonCode || "",
    pendingDisposition: i.pendingDisposition || i.phishml
  };
}

function inferReporterProfile(name) {
  if (USER_PROFILES[name]) return name;
  return "Liam Chowdhury (Security Analyst)";
}

function now() {
  return new Date().toLocaleString();
}

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function auth(malicious, idx) {
  if (malicious) {
    return {
      spf: `spf=fail smtp.mailfrom=mail-${idx}.secure-alert.net`,
      dkim: `dkim=fail header.d=secure-alert${idx}.net`,
      dmarc: "dmarc=fail p=reject"
    };
  }
  return {
    spf: "spf=pass smtp.mailfrom=academy.local",
    dkim: "dkim=pass header.d=academy.local",
    dmarc: "dmarc=pass p=quarantine"
  };
}

function randomHash(len) {
  const chars = "abcdef0123456789";
  let out = "";
  for (let i = 0; i < len; i += 1) out += chars[rand(0, chars.length - 1)];
  return out;
}

function makeAttachment(nameBase, suspicious) {
  const ext = suspicious ? ["pdf.exe", "docm", "html", "zip"][rand(0, 3)] : ["pdf", "docx", "xlsx"][rand(0, 2)];
  return {
    name: `${nameBase}.${ext}`,
    size: `${rand(42, 940)} KB`,
    md5: randomHash(32),
    sha256: randomHash(64)
  };
}

function rawHeaders(from, reply, authObj, idx) {
  return [
    `Received: from edge${idx}.mail-gateway.net (185.10.${idx % 255}.31)`,
    `Return-Path: <${reply}>`,
    `From: ${from}`,
    `Reply-To: ${reply}`,
    `X-Sender: ${reply}`,
    `X-Originating-IP: [185.10.${idx % 255}.31]`,
    `Authentication-Results: ${authObj.spf}; ${authObj.dkim}; ${authObj.dmarc}`,
    `Message-ID: <${idx}.${Date.now()}@mail-gateway.net>`,
    `MIME-Version: 1.0`,
    "Content-Type: text/html; charset=UTF-8"
  ].join("\n");
}

function pickReporter(idx, targetRisk = "mixed") {
  const names = Object.keys(USER_PROFILES);
  if (targetRisk === "high") {
    const high = names.filter((n) => USER_PROFILES[n].department === "Finance");
    return high[idx % high.length];
  }
  return names[idx % names.length];
}

function generateIncidentByType(type, idx) {
  const id = `PHI-${String(idx).padStart(4, "0")}`;
  const base = {
    id,
    icon: "✉",
    status: "received",
    date: now(),
    room: "inbox",
    tags: [],
    discussion: [],
    noteDraft: "",
    extractedQrUrl: ""
  };
  if (type === "ceo_fraud") {
    const from = "CEO Office <ceo@academy-leadership.com>";
    const reply = `payment-ops${idx}@academy-wire-safe.net`;
    const a = auth(true, idx);
    const reporter = pickReporter(idx, "high");
    return normalizeIncident({
      ...base,
      category: "CEO Fraud",
      priority: "critical",
      reporter,
      reporterProfile: reporter,
      subject: `Confidential Wire Request ${idx}`,
      phishml: "threat",
      expectedDisposition: "threat",
      phishmlScore: rand(88, 99),
      from,
      replyTo: reply,
      preview: "Urgent request from executive persona to complete same-day transfer.",
      links: [makeLink("https://sharepoint.com/finance-docs", THREAT_URLS.cfoWire, "Impersonation domain tied to wire-fraud lures.")],
      attachments: [makeAttachment("wire_statement", true)],
      auth: a,
      raw: rawHeaders(from, reply, a, idx),
      redFlag: "Reply-To domain does not match executive sender domain."
    });
  }
  if (type === "mfa_fatigue") {
    const from = `Identity Alerts <no-reply@id-prompt${idx}.com>`;
    const reply = `helpdesk@id-prompt${idx}.com`;
    const a = auth(true, idx);
    const reporter = pickReporter(idx);
    return normalizeIncident({
      ...base,
      category: "MFA Fatigue",
      priority: "high",
      reporter,
      reporterProfile: reporter,
      subject: `Repeated MFA Prompt Alert ${idx}`,
      phishml: "spam",
      expectedDisposition: "threat",
      phishmlScore: rand(55, 79),
      from,
      replyTo: reply,
      preview: "Unexpected multiple MFA prompts with urgent 'approve now' language.",
      links: [makeLink("https://okta.com/security", THREAT_URLS.itSupport, "Typosquatting identity portal observed.")],
      attachments: [makeAttachment("mfa_alert", true)],
      auth: a,
      raw: rawHeaders(from, reply, a, idx),
      redFlag: "Unexpected MFA approval lure from non-corporate sender domain."
    });
  }
  if (type === "password_reset") {
    const from = `IT Password Reset <password-reset${idx}@academy-support-help.com>`;
    const reply = `reset@academy-support-help.com`;
    const a = auth(true, idx);
    const reporter = pickReporter(idx);
    return normalizeIncident({
      ...base,
      category: "IT Password Reset",
      priority: "medium",
      reporter,
      reporterProfile: reporter,
      subject: `Password Reset Confirmation ${idx}`,
      phishml: "spam",
      expectedDisposition: "spam",
      phishmlScore: rand(45, 74),
      from,
      replyTo: reply,
      preview: "Reset link expires in 5 minutes. Immediate action required.",
      links: [makeLink("https://portal.office.com", idx % 4 === 0 ? THREAT_URLS.knownKit : THREAT_URLS.office365, "Credential-harvest destination with masked branding.")],
      attachments: [makeAttachment("reset_notice", true)],
      auth: a,
      raw: rawHeaders(from, reply, a, idx),
      redFlag: "Lookalike support domain and auth failures."
    });
  }
  const from = "HR Newsletter <hr-news@academy.local>";
  const reply = "hr-news@academy.local";
  const a = auth(false, idx);
  const reporter = pickReporter(idx);
  return normalizeIncident({
    ...base,
    category: "Clean Newsletter",
    priority: "low",
    reporter,
    reporterProfile: reporter,
    subject: `HR Monthly Newsletter ${idx}`,
    phishml: "clean",
    expectedDisposition: "clean",
    phishmlScore: rand(5, 30),
    from,
    replyTo: reply,
    preview: "Internal HR updates and employee engagement announcements.",
    links: [makeLink(CLEAN_URLS[idx % CLEAN_URLS.length], CLEAN_URLS[idx % CLEAN_URLS.length], "Known safe corporate domain.")],
    attachments: [makeAttachment("newsletter", false)],
    auth: a,
    raw: rawHeaders(from, reply, a, idx),
    redFlag: "No significant red flag. Legitimate internal communication."
  });
}

function generateIncidents(total) {
  const kinds = ["ceo_fraud", "mfa_fatigue", "password_reset", "clean"];
  const out = [];
  for (let i = 1; i <= total; i += 1) out.push(generateIncidentByType(kinds[(i - 1) % kinds.length], i));
  return out;
}

function generateQuishingIncidents(total) {
  const out = [];
  for (let i = 1; i <= total; i += 1) {
    const idx = 9000 + i;
    const id = `PHI-Q${String(i).padStart(3, "0")}`;
    const from = "IT Service Desk <it-support@academy-ithelp.com>";
    const reply = `security${idx}@academy-ithelp.com`;
    const a = auth(true, idx);
    const url = THREAT_URLS.shipping;
    const reporter = pickReporter(idx, "high");
    out.push(normalizeIncident({
      id,
      icon: "▣",
      status: "received",
      date: now(),
      room: "inbox",
      category: "Quishing",
      priority: "high",
      reporter,
      reporterProfile: reporter,
      subject: `MFA Re-Enrollment Required (QR) Q${i}`,
      phishml: "threat",
      expectedDisposition: "threat",
      phishmlScore: rand(76, 98),
      from,
      replyTo: reply,
      preview: "Scan QR code to restore MFA access.",
      links: [makeLink("https://fedex.com/track", url, "New domain matching shipping pretext campaigns.")],
      attachments: [makeAttachment("mfa_qr", true)],
      auth: a,
      raw: rawHeaders(from, reply, a, idx),
      redFlag: "QR-code lure paired with suspicious domain and failing auth.",
      tags: [],
      discussion: [],
      noteDraft: "",
      qrData: url,
      extractedQrUrl: ""
    }));
  }
  return out;
}

function generateSurgeIncidents(total) {
  const out = [];
  for (let i = 0; i < total; i += 1) {
    const idx = 12000 + rand(1, 999);
    const reporter = pickReporter(idx, "high");
    const type = ["ceo_fraud", "mfa_fatigue", "password_reset"][rand(0, 2)];
    const incident = generateIncidentByType(type, idx);
    incident.reporter = reporter;
    incident.reporterProfile = reporter;
    incident.priority = ["critical", "high"][rand(0, 1)];
    incident.date = `${now()} (SURGE)`;
    incident.subject = `[Final 5] ${incident.subject}`;
    out.push(incident);
  }
  return out;
}

function pmlClass(v) {
  if (v === "threat") return "pml-threat";
  if (v === "spam") return "pml-spam";
  return "pml-clean";
}

function confidenceText(score) {
  if (score >= 75) return "High";
  if (score >= 45) return "Medium";
  return "Low";
}

function confidenceColor(score) {
  if (score >= 75) return "var(--threat)";
  if (score >= 45) return "var(--spam)";
  return "var(--clean)";
}

function isLocked() {
  return Date.now() >= state.shiftEndsAt;
}

function getDomain(link) {
  const raw = typeof link === "string" ? link : link.destination;
  return raw.replace(/^hxxps?:\/\//, "").replace(/^https?:\/\//, "").replace(/\[\.\]/g, ".").split("/")[0];
}

function makeLink(visibleText, destination, intel = "") {
  return { visibleText, destination, intel };
}

function filtered() {
  return state.incidents.filter((i) => {
    const f = state.filters;
    if (f.room !== "all") {
      if (f.room === "critical" && i.priority !== "critical") return false;
      if (f.room === "review" && i.status !== "in_review") return false;
      if (f.room === "resolved" && i.status !== "resolved") return false;
      if (f.room === "inbox" && i.room !== "inbox") return false;
    }
    if (f.phishml !== "all" && i.phishml !== f.phishml) return false;
    if (f.priority !== "all" && i.priority !== f.priority) return false;
    if (f.status !== "all" && i.status !== f.status) return false;
    if (f.query) {
      const hay = `${i.reporter} ${i.subject} ${i.from} ${i.replyTo}`.toLowerCase();
      if (!hay.includes(f.query.toLowerCase())) return false;
    }
    return true;
  });
}

function appendLog(i, icon, text, actor = "system") {
  i.discussion.push({ ts: now(), icon, text, actor });
}

function pastReportCount(name) {
  return state.incidents.filter((i) => i.reporter === name).length;
}

function riskClass(score) {
  if (score >= 90) return "risk-critical";
  if (score >= 80) return "risk-high";
  return "";
}

function renderRows() {
  const tbody = document.getElementById("incident-rows");
  tbody.innerHTML = filtered().map((i) => {
    const profile = USER_PROFILES[i.reporterProfile] || USER_PROFILES[inferReporterProfile(i.reporter)];
    const scoreClass = riskClass(profile.riskScore);
    return `
      <tr class="incident-row ${i.id === selected ? "active" : ""}" data-id="${i.id}">
        <td>${i.icon}</td>
        <td>${i.priority.toUpperCase()}</td>
        <td class="reporter-cell">
          <span class="reporter-tag">${i.reporter}</span>
          <div class="reporter-tip">
            <div><strong>Name:</strong> ${i.reporter}</div>
            <div><strong>Department:</strong> ${profile.department}</div>
            <div><strong>Risk Score:</strong> <span class="${scoreClass}">${profile.riskScore}</span></div>
            <div><strong>Past Reports:</strong> ${pastReportCount(i.reporter)}</div>
          </div>
        </td>
        <td>${i.subject}</td>
        <td><span class="pml ${pmlClass(i.phishml)}">PML:${i.phishml.toUpperCase()}</span></td>
        <td>${i.status.replaceAll("_", " ").toUpperCase()}</td>
        <td>${i.date}</td>
      </tr>
    `;
  }).join("");
  tbody.querySelectorAll(".incident-row").forEach((r) => r.addEventListener("click", () => {
    if (isLocked()) return;
    selected = r.dataset.id;
    renderAll();
  }));
}

function renderPreviewTab(i, mismatch) {
  const qr = i.category === "Quishing" ? `
    <div class="qr-preview">
      <img alt="QR phishing preview" src="https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(i.qrData || i.links[0])}" />
    </div>
  ` : "";
  return `<p>${i.preview}</p>${qr}${answerKey ? `<p class="${mismatch ? "warn" : "ok"}">Red Flag: ${i.redFlag}</p>` : ""}`;
}

function renderLinksTab(i) {
  return `
    ${i.links.map((l) => `
      <div class="link-row">
        <span class="mono"><strong>Visible Text:</strong> ${l.visibleText}<br><strong>Actual Destination:</strong> ${l.destination}</span>
        <button class="urlscan-btn" data-domain="${getDomain(l)}" aria-label="Search domain on URLScan">Search on URLScan.io</button>
      </div>
      ${l.intel ? `<p class="muted">OSINT Match: ${l.intel}</p>` : ""}
    `).join("")}
    ${i.category === "Quishing" ? `<button id="extract-qr-btn" aria-label="Extract URL from QR code">Extract URL from QR Code</button><p class="muted">${i.extractedQrUrl || ""}</p>` : ""}
  `;
}

function renderAttachmentsTab(i) {
  return `
    <table class="grid">
      <thead><tr><th>Name</th><th>Size</th><th>MD5</th><th>SHA256</th></tr></thead>
      <tbody>
        ${i.attachments.map((a) => `<tr><td>${a.name}</td><td>${a.size}</td><td class="mono">${a.md5}</td><td class="mono">${a.sha256}</td></tr>`).join("")}
      </tbody>
    </table>
    <button id="detonate-btn" aria-label="Detonate selected file in sandbox">Detonate in Sandbox</button>
  `;
}

function renderTriage() {
  const pane = document.getElementById("triage-pane");
  const i = state.incidents.find((x) => x.id === selected);
  if (!i) {
    pane.innerHTML = "<p>No incident selected.</p>";
    return;
  }
  const tab = i.tab || "preview";
  const locked = isLocked();
  const mismatch = i.from.split("@")[1]?.replace(">", "") !== i.replyTo.split("@")[1];
  const noteLength = (i.noteDraft || "").trim().length;
  const canResolve = i.status === "in_review" && Boolean(i.reasonCode) && noteLength >= 20;
  const headerDebrief = mismatch
    ? "Instructor Note: Reply-To diverges from the sender domain, a classic routing redirection indicator."
    : "Instructor Note: Header alignment is normal; confirm intent via links and attachment behavior.";
  const authDebrief = i.auth.spf.includes("fail")
    ? "Instructor Note: SPF failed because the observed sending source is not authorized for the claimed domain."
    : "Instructor Note: SPF passed, which can still occur on lookalike domains; continue layered validation.";
  pane.innerHTML = `
    <div class="confidence">
      <div class="confidence-head">
        <span>PhishML ${i.phishmlScore}%</span>
        <span>${confidenceText(i.phishmlScore)} Likelihood</span>
      </div>
      <div class="confidence-bar" style="width:${i.phishmlScore}%; background:${confidenceColor(i.phishmlScore)};"></div>
    </div>
    <h3>${i.subject}</h3>
    <p class="muted">From: ${i.from}<br>Reply-To: ${i.replyTo}</p>
    <div class="tabs">
      ${TABS.map((t) => `<button class="tab ${t === tab ? "active" : ""}" data-tab="${t}" aria-label="Open ${t} tab">${t.toUpperCase()}</button>`).join("")}
    </div>
    <div class="tab-panel">
      ${tab === "preview" ? renderPreviewTab(i, mismatch) : ""}
      ${tab === "headers" ? `<p><strong>From:</strong> ${i.from}<br><strong>Reply-To:</strong> ${i.replyTo}</p><p class="${mismatch ? "warn" : "ok"}">${mismatch ? "From/Reply-To mismatch detected." : "No mismatch detected."}</p>${answerKey ? `<div class="debrief">${headerDebrief}</div>` : ""}` : ""}
      ${tab === "auth" ? `<p>SPF: ${i.auth.spf}<br>DKIM: ${i.auth.dkim}<br>DMARC: ${i.auth.dmarc}</p>${answerKey ? `<div class="debrief">${authDebrief}</div>` : ""}` : ""}
      ${tab === "links" ? renderLinksTab(i) : ""}
      ${tab === "attachments" ? renderAttachmentsTab(i) : ""}
    </div>
    <div class="actions">
      <button id="classify-threat-btn" aria-label="Classify threat">Threat</button>
      <button id="classify-spam-btn" aria-label="Classify spam">Spam</button>
      <button id="classify-clean-btn" aria-label="Classify clean">Clean</button>
      <button id="assign-btn" aria-label="Assign incident">Assign</button>
      <button id="review-btn" aria-label="Set in review">In Review</button>
      <button id="resolve-btn" aria-label="Resolve incident" ${canResolve ? "" : "disabled"}>Resolve</button>
      <button id="tag-btn" aria-label="Add threat tag">Add Tag</button>
      <button id="phishrip-btn" aria-label="Run PhishRIP simulation" ${i.phishml !== "threat" ? "disabled" : ""}>Run PhishRIP</button>
      <button id="zap-btn" aria-label="Run zero-hour auto purge" ${i.phishml !== "threat" ? "disabled" : ""}>Run ZAP</button>
      <button id="phishflip-btn" aria-label="Convert threat into simulation" ${i.phishml !== "threat" ? "disabled" : ""}>PhishFlip</button>
      <button id="block-btn" aria-label="Block sender domain">Block</button>
    </div>
    <label>Reason Code (required)
      <select id="reason-code" aria-label="Reason code for disposition">
        <option value="">Select a reason...</option>
        ${REASON_CODES.map((code) => `<option value="${code}" ${i.reasonCode === code ? "selected" : ""}>${code}</option>`).join("")}
      </select>
    </label>
    <label>Analyst Notes (Auto-save)
      <textarea id="analyst-notes" aria-label="Analyst notes area" rows="5" ${locked ? "disabled" : ""}>${i.noteDraft || ""}</textarea>
    </label>
    <div class="shortcut-legend"><strong>Shortcuts:</strong> T = Threat, S = Spam, C = Clean</div>
    <div class="log">${i.discussion.slice().reverse().map((d) => `<div>${d.icon} ${d.ts} - ${d.text}</div>`).join("") || "No logs yet."}</div>
  `;

  pane.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
    i.tab = b.dataset.tab;
    save();
    renderTriage();
  }));
  pane.querySelector("#classify-threat-btn").addEventListener("click", () => setDisposition(i, "threat"));
  pane.querySelector("#classify-spam-btn").addEventListener("click", () => setDisposition(i, "spam"));
  pane.querySelector("#classify-clean-btn").addEventListener("click", () => setDisposition(i, "clean"));
  pane.querySelector("#assign-btn").addEventListener("click", () => clickAction(i, "👤", "Assigned to analyst."));
  pane.querySelector("#review-btn").addEventListener("click", () => {
    if (i.status === "received") {
      i.status = "in_review";
      clickAction(i, "🛠", "Status changed to In Review.");
    }
  });
  pane.querySelector("#resolve-btn").addEventListener("click", () => {
    if (i.status === "in_review" && i.reasonCode && (i.noteDraft || "").trim().length >= 20) {
      i.status = "resolved";
      clickAction(i, "✅", `Status changed to Resolved. Reason: ${i.reasonCode}.`);
      showToast(`Incident ${i.id} resolved.`);
      playCue("resolve");
    }
  });
  pane.querySelector("#tag-btn").addEventListener("click", () => {
    if (!i.tags.includes("Needs Investigation")) i.tags.push("Needs Investigation");
    clickAction(i, "🏷", "Tag added: Needs Investigation.");
  });
  pane.querySelector("#block-btn").addEventListener("click", () => clickAction(i, "⛔", "Sender domain blocked."));
  pane.querySelector("#phishrip-btn").addEventListener("click", () => runPhishRip(i));
  pane.querySelector("#zap-btn").addEventListener("click", () => runZap(i));
  pane.querySelector("#phishflip-btn").addEventListener("click", () => runPhishFlip(i));

  pane.querySelectorAll(".urlscan-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const domain = btn.dataset.domain;
      window.open(`https://urlscan.io/search/#domain:${encodeURIComponent(domain)}`, "_blank", "noopener,noreferrer");
      appendLog(i, "🔎", `Pivoted to URLScan search for ${domain}.`, "analyst");
      appendEvidenceClip(i, "Evidence: [OSINT Search Logged]");
      save();
      renderTriage();
    });
  });

  const extractBtn = pane.querySelector("#extract-qr-btn");
  if (extractBtn) {
    extractBtn.addEventListener("click", () => {
      i.extractedQrUrl = i.qrData || i.links[0];
      if (typeof i.extractedQrUrl !== "string") i.extractedQrUrl = i.extractedQrUrl.destination;
      appendLog(i, "▣", `Extracted URL from QR code: ${i.extractedQrUrl}`, "analyst");
      save();
      renderTriage();
    });
  }

  const detonateBtn = pane.querySelector("#detonate-btn");
  if (detonateBtn) detonateBtn.addEventListener("click", () => runDetonation(i));

  const notes = pane.querySelector("#analyst-notes");
  notes.addEventListener("input", () => {
    i.noteDraft = notes.value;
    save();
    renderTriage();
  });
  pane.querySelector("#reason-code").addEventListener("change", (e) => {
    i.reasonCode = e.target.value;
    save();
    renderTriage();
  });
}

function setDisposition(i, label) {
  if (isLocked()) return;
  i.pendingDisposition = label;
  i.phishml = label;
  if (label === "threat") i.priority = "high";
  if (label === "spam") i.priority = "medium";
  if (label === "clean") i.priority = "low";
  appendLog(i, "🧭", `Disposition selected: ${label.toUpperCase()}.`, "analyst");
  save();
  renderAll();
}

function appendEvidenceClip(i, clipText) {
  if (!(i.noteDraft || "").includes(clipText)) {
    i.noteDraft = `${(i.noteDraft || "").trim()}\n${clipText}`.trim();
  }
}

function clickAction(i, icon, text) {
  if (isLocked()) return;
  appendLog(i, icon, text, "analyst");
  save();
  renderAll();
}

function runPhishRIPLike(messageBuilder, i, icon, doneMessage) {
  if (isLocked()) return;
  const modal = document.getElementById("phishrip-modal");
  const bar = document.getElementById("phishrip-bar");
  const txt = document.getElementById("phishrip-text");
  modal.classList.remove("hidden");
  let pct = 0;
  bar.style.width = "0%";
  txt.textContent = messageBuilder("start");
  const timer = setInterval(() => {
    pct += 10;
    bar.style.width = `${pct}%`;
    if (pct >= 100) {
      clearInterval(timer);
      txt.textContent = messageBuilder("end");
      appendLog(i, icon, doneMessage, "system");
      save();
      renderTriage();
    }
  }, 180);
}

function runPhishRip(i) {
  const ripped = rand(3, 48);
  runPhishRIPLike(
    (phase) => (phase === "start" ? "Scanning 5,000 mailboxes..." : `Scan complete. ${ripped} identical threats ripped (quarantined).`),
    i,
    "🧹",
    `PhishRIP completed. ${ripped} identical threats quarantined.`
  );
}

function runZap(i) {
  const domain = getDomain(i.links[0] || { destination: i.replyTo });
  const removed = rand(7, 110);
  runPhishRIPLike(
    (phase) => (phase === "start" ? `ZAP scanning sender domain ${domain} across tenant...` : `ZAP complete. ${removed} messages purged for domain ${domain}.`),
    i,
    "⚡",
    `ZAP executed. Proactive purge removed ${removed} messages from sender domain ${domain}.`
  );
}

function runPhishFlip(i) {
  if (isLocked() || i.phishml !== "threat") return;
  appendLog(i, "🔄", "Threat sanitized. Training campaign live.", "system");
  if (!i.tags.includes("PhishFlip")) i.tags.push("PhishFlip");
  save();
  renderTriage();
  renderAnalytics();
}

function runDetonation(i) {
  const modal = document.getElementById("detonate-modal");
  const out = document.getElementById("detonate-output");
  modal.classList.remove("hidden");
  playCue("datastream");
  const file = i.attachments[0];
  const lines = [
    `[${now()}] Initializing sandbox container...`,
    `[${now()}] Mounting sample: ${file.name}`,
    `[${now()}] Analyzing file structure...`,
    `[${now()}] Static signature check... suspicious entropy detected`,
    `[${now()}] Heuristic check: Malicious API calls detected`,
    `[${now()}] Network emulation: C2 beacon attempt observed`,
    `[${now()}] Verdict: MALICIOUS`
  ];
  const primaryLink = i.links?.[0]?.destination || "";
  if (primaryLink.includes("microsoft-update.xyz")) {
    lines.splice(lines.length - 1, 0, `[${now()}] Matched known phishing kit: "PhishKit-V3-Office365"`);
  }
  out.textContent = "";
  let idx = 0;
  const timer = setInterval(() => {
    out.textContent += `${lines[idx]}\n`;
    out.scrollTop = out.scrollHeight;
    idx += 1;
    if (idx >= lines.length) {
      clearInterval(timer);
      appendLog(i, "💣", `Detonation completed for ${file.name}. Verdict: malicious behavior observed.`, "sandbox");
      appendEvidenceClip(i, "Evidence: [Sandbox Detonation Performed]");
      save();
      renderTriage();
      renderAnalytics();
    }
  }, 380);
}

function classifySelected(label) {
  if (isLocked()) return;
  const i = state.incidents.find((x) => x.id === selected);
  if (!i) return;
  setDisposition(i, label);
  appendLog(i, "⌨", `Shortcut classification set to ${label.toUpperCase()}.`, "analyst");
}

function metricBar(label, value, total, color = "#1d4ed8") {
  const pct = total ? Math.round((value / total) * 100) : 0;
  return `
    <div class="metric-row">
      <span>${label}: ${value} (${pct}%)</span>
      <div class="metric-bar"><div class="metric-fill" style="width:${pct}%; background:${color};"></div></div>
    </div>
  `;
}

function renderAnalytics() {
  const host = document.getElementById("analytics-content");
  if (!host) return;
  const all = state.incidents;
  const resolved = all.filter((i) => i.status === "resolved").length;
  const pending = all.length - resolved;
  const threat = all.filter((i) => i.phishml === "threat").length;
  const spam = all.filter((i) => i.phishml === "spam").length;
  const clean = all.filter((i) => i.phishml === "clean").length;
  const correct = all.filter((i) => i.phishml === i.expectedDisposition).length;
  const incorrect = all.length - correct;
  const neutralized = all.reduce((sum, i) => sum + i.discussion.filter((d) => d.icon === "🧹" || d.icon === "⚡").length, 0);
  const accuracyPct = all.length ? Math.round((correct / all.length) * 100) : 0;

  host.innerHTML = `
    <p><strong>Overall Accuracy:</strong> ${accuracyPct}% | <strong>Threats Neutralized:</strong> ${neutralized}</p>
    <div class="dash-grid">
      <article class="dash-card">
        <h3>Incident Status</h3>
        ${metricBar("Resolved", resolved, all.length, "#059669")}
        ${metricBar("Pending", pending, all.length, "#dc2626")}
      </article>
      <article class="dash-card">
        <h3>Disposition Distribution</h3>
        ${metricBar("Threat", threat, all.length, "#dc2626")}
        ${metricBar("Spam", spam, all.length, "#d4a017")}
        ${metricBar("Clean", clean, all.length, "#059669")}
      </article>
      <article class="dash-card">
        <h3>Student Accuracy</h3>
        ${metricBar("Correct", correct, all.length, "#2563eb")}
        ${metricBar("Incorrect", incorrect, all.length, "#f97316")}
      </article>
    </div>
  `;
}

function switchView(view) {
  currentView = view;
  const inbox = document.getElementById("inbox-view");
  const dash = document.getElementById("dashboard-view");
  const inboxBtn = document.getElementById("view-inbox");
  const dashBtn = document.getElementById("view-dashboard");
  const showInbox = view === "inbox";
  inbox.classList.toggle("hidden", !showInbox);
  dash.classList.toggle("hidden", showInbox);
  inboxBtn.classList.toggle("active", showInbox);
  dashBtn.classList.toggle("active", !showInbox);
  if (!showInbox) renderAnalytics();
  save();
}

function updateTimer() {
  const el = document.getElementById("shift-timer");
  const left = Math.max(0, Math.floor((state.shiftEndsAt - Date.now()) / 1000));
  const m = Math.floor(left / 60);
  const s = left % 60;
  el.textContent = `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  el.classList.toggle("pulse", left > 0 && left < 300);
  if (left < 300 && !state.finalFiveInjected) {
    const surge = generateSurgeIncidents(rand(3, 5));
    state.incidents = surge.concat(state.incidents);
    state.finalFiveInjected = true;
    playCue("warning");
    save();
    renderRows();
    renderAnalytics();
  }
  if (left === 0) {
    clearInterval(shiftTimer);
    el.textContent = "SHIFT LOCKED";
  }
}

function bind() {
  document.getElementById("room-filter").addEventListener("change", (e) => { state.filters.room = e.target.value; save(); renderRows(); });
  document.getElementById("phishml-filter").addEventListener("change", (e) => { state.filters.phishml = e.target.value; save(); renderRows(); });
  document.getElementById("priority-filter").addEventListener("change", (e) => { state.filters.priority = e.target.value; save(); renderRows(); });
  document.getElementById("status-filter").addEventListener("change", (e) => { state.filters.status = e.target.value; save(); renderRows(); });
  document.getElementById("search-filter").addEventListener("input", (e) => { state.filters.query = e.target.value; save(); renderRows(); });
  document.getElementById("answer-key-toggle").addEventListener("click", () => { answerKey = !answerKey; renderTriage(); });
  document.getElementById("view-inbox").addEventListener("click", () => switchView("inbox"));
  document.getElementById("view-dashboard").addEventListener("click", () => switchView("dashboard"));
  document.getElementById("contrast-toggle").addEventListener("click", () => {
    state.highContrast = !state.highContrast;
    document.body.classList.toggle("high-contrast", state.highContrast);
    save();
  });
  document.getElementById("mute-toggle").addEventListener("click", () => {
    state.muted = !state.muted;
    document.getElementById("mute-toggle").textContent = `Mute: ${state.muted ? "On" : "Off"}`;
    save();
  });
  document.getElementById("help-toggle").addEventListener("click", () => {
    document.getElementById("quickstart-modal").classList.remove("hidden");
  });
  document.getElementById("close-quickstart").addEventListener("click", () => {
    state.tutorialSeen = true;
    save();
    document.getElementById("quickstart-modal").classList.add("hidden");
  });
  document.getElementById("reset-sim").addEventListener("click", () => {
    localStorage.removeItem(STORE);
    state = freshState();
    selected = state.incidents[0]?.id || null;
    answerKey = false;
    currentView = "inbox";
    save();
    renderAll();
  });
  document.getElementById("download-report").addEventListener("click", () => downloadShiftReport());
  document.getElementById("close-modal").addEventListener("click", () => document.getElementById("phishrip-modal").classList.add("hidden"));
  document.getElementById("close-detonate-modal").addEventListener("click", () => document.getElementById("detonate-modal").classList.add("hidden"));
  document.addEventListener("keydown", (e) => {
    if (["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName)) return;
    const k = e.key.toLowerCase();
    if (k === "t") classifySelected("threat");
    if (k === "s") classifySelected("spam");
    if (k === "c") classifySelected("clean");
  });
}

function hydrate() {
  document.getElementById("room-filter").value = state.filters.room;
  document.getElementById("phishml-filter").value = state.filters.phishml;
  document.getElementById("priority-filter").value = state.filters.priority;
  document.getElementById("status-filter").value = state.filters.status;
  document.getElementById("search-filter").value = state.filters.query;
}

function renderAll() {
  hydrate();
  renderRows();
  renderTriage();
  renderAnalytics();
  switchView(currentView);
  document.body.classList.toggle("high-contrast", state.highContrast);
  document.getElementById("mute-toggle").textContent = `Mute: ${state.muted ? "On" : "Off"}`;
  if (!state.tutorialSeen) {
    document.getElementById("quickstart-modal").classList.remove("hidden");
  }
  updateTimer();
}

function downloadShiftReport() {
  const all = state.incidents;
  const threatIncidents = all.filter((i) => i.phishml === "threat");
  const correct = all.filter((i) => i.phishml === i.expectedDisposition).length;
  const accuracyPct = all.length ? Math.round((correct / all.length) * 100) : 0;
  const neutralized = all.reduce((sum, i) => sum + i.discussion.filter((d) => d.icon === "🧹" || d.icon === "⚡").length, 0);
  const lines = [
    "KnowBe4 PhishER Simulator - Shift Report",
    `Generated: ${now()}`,
    "",
    `Overall Accuracy Score: ${accuracyPct}% (${correct}/${all.length})`,
    `Total Threats Neutralized (PhishRIP/ZAP): ${neutralized}`,
    "",
    "Threat Incident Submission (includes evidence clips):"
  ];
  threatIncidents.forEach((i) => {
    lines.push(`- ${i.id} | ${i.subject}`);
    lines.push(`  Analyst Notes: ${i.noteDraft?.trim() || "No notes submitted."}`);
  });
  const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `shift-report-${Date.now()}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function showToast(text) {
  const toast = document.getElementById("toast");
  toast.textContent = text;
  toast.classList.remove("hidden");
  setTimeout(() => toast.classList.add("hidden"), 2000);
}

currentView = state.currentView || "inbox";
bind();
renderAll();
shiftTimer = setInterval(updateTimer, 1000);
