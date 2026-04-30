const STORE = "phisher-enterprise-v5";
const SHIFT_SECONDS = 30 * 60;
const TABS = ["preview", "headers", "auth", "links", "attachments"];
const THREAT_DOMAINS = [
  "hxxp://bit.ly/3kP0xPh",
  "hxxps://microsoft-secure-login[.]com",
  "hxxps://docusign-verify-session[.]net",
  "hxxps://okta-auth-recovery[.]org",
  "hxxps://office365-validate-user[.]com"
];
const CLEAN_URLS = [
  "https://okta.com",
  "https://docusign.com",
  "https://microsoft.com",
  "https://google.com",
  "https://academy.local/intranet"
];

let state = load();
let selected = state.incidents[0]?.id || null;
let answerKey = false;
let shiftTimer = null;

function load() {
  const raw = localStorage.getItem(STORE);
  if (!raw) return freshState();
  try {
    const parsed = JSON.parse(raw);
    parsed.incidents = (parsed.incidents || []).map(normalizeIncident);
    parsed.filters = parsed.filters || { room: "all", phishml: "all", priority: "all", status: "all", query: "" };
    parsed.shiftEndsAt = parsed.shiftEndsAt || (Date.now() + SHIFT_SECONDS * 1000);
    return parsed;
  } catch {
    return freshState();
  }
}

function freshState() {
  return {
    incidents: generateIncidents(55).concat(generateQuishingIncidents(10)),
    filters: { room: "all", phishml: "all", priority: "all", status: "all", query: "" },
    shiftEndsAt: Date.now() + SHIFT_SECONDS * 1000
  };
}

function save() {
  localStorage.setItem(STORE, JSON.stringify(state));
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
    extractedQrUrl: i.extractedQrUrl || ""
  };
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
      dmarc: `dmarc=fail p=reject`
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
    `Content-Type: text/html; charset=UTF-8`
  ].join("\n");
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
    return normalizeIncident({
      ...base,
      category: "CEO Fraud",
      priority: "critical",
      reporter: `finance${idx % 8}@academy.local`,
      subject: `Confidential Wire Request ${idx}`,
      phishml: "threat",
      phishmlScore: rand(88, 99),
      from,
      replyTo: reply,
      preview: "Urgent request from executive persona to complete same-day transfer.",
      links: [THREAT_DOMAINS[idx % THREAT_DOMAINS.length]],
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
    return normalizeIncident({
      ...base,
      category: "MFA Fatigue",
      priority: "high",
      reporter: `employee${idx % 17}@academy.local`,
      subject: `Repeated MFA Prompt Alert ${idx}`,
      phishml: "spam",
      phishmlScore: rand(55, 79),
      from,
      replyTo: reply,
      preview: "Unexpected multiple MFA prompts with urgent 'approve now' language.",
      links: [THREAT_DOMAINS[(idx + 1) % THREAT_DOMAINS.length]],
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
    return normalizeIncident({
      ...base,
      category: "IT Password Reset",
      priority: "medium",
      reporter: `staff${idx % 22}@academy.local`,
      subject: `Password Reset Confirmation ${idx}`,
      phishml: "spam",
      phishmlScore: rand(45, 74),
      from,
      replyTo: reply,
      preview: "Reset link expires in 5 minutes. Immediate action required.",
      links: [THREAT_DOMAINS[(idx + 2) % THREAT_DOMAINS.length]],
      attachments: [makeAttachment("reset_notice", true)],
      auth: a,
      raw: rawHeaders(from, reply, a, idx),
      redFlag: "Lookalike support domain and auth failures."
    });
  }
  const from = "HR Newsletter <hr-news@academy.local>";
  const reply = "hr-news@academy.local";
  const a = auth(false, idx);
  return normalizeIncident({
    ...base,
    category: "Clean Newsletter",
    priority: "low",
    reporter: `member${idx % 16}@academy.local`,
    subject: `HR Monthly Newsletter ${idx}`,
    phishml: "clean",
    phishmlScore: rand(5, 30),
    from,
    replyTo: reply,
    preview: "Internal HR updates and employee engagement announcements.",
    links: [CLEAN_URLS[idx % CLEAN_URLS.length]],
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
    const url = THREAT_DOMAINS[i % THREAT_DOMAINS.length];
    out.push(normalizeIncident({
      id,
      icon: "▣",
      status: "received",
      date: now(),
      room: "inbox",
      category: "Quishing",
      priority: "high",
      reporter: `user${i}@academy.local`,
      subject: `MFA Re-Enrollment Required (QR) Q${i}`,
      phishml: "threat",
      phishmlScore: rand(76, 98),
      from,
      replyTo: reply,
      preview: "Scan QR code to restore MFA access.",
      links: [url],
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
  const normalized = link.replace(/^hxxps?:\/\//, "").replace(/^https?:\/\//, "").replace(/\[\.\]/g, ".").split("/")[0];
  return normalized;
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

function renderRows() {
  const tbody = document.getElementById("incident-rows");
  tbody.innerHTML = filtered().map((i) => `
    <tr class="incident-row ${i.id === selected ? "active" : ""}" data-id="${i.id}">
      <td>${i.icon}</td>
      <td>${i.priority.toUpperCase()}</td>
      <td>${i.reporter}</td>
      <td>${i.subject}</td>
      <td><span class="pml ${pmlClass(i.phishml)}">PML:${i.phishml.toUpperCase()}</span></td>
      <td>${i.status.replaceAll("_", " ").toUpperCase()}</td>
      <td>${i.date}</td>
    </tr>
  `).join("");
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
        <span class="mono">${l}</span>
        <button class="urlscan-btn" data-domain="${getDomain(l)}" aria-label="Search domain on URLScan">Search on URLScan.io</button>
      </div>
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
      ${tab === "headers" ? `<p><strong>From:</strong> ${i.from}<br><strong>Reply-To:</strong> ${i.replyTo}</p><p class="${mismatch ? "warn" : "ok"}">${mismatch ? "From/Reply-To mismatch detected." : "No mismatch detected."}</p>` : ""}
      ${tab === "auth" ? `<p>SPF: ${i.auth.spf}<br>DKIM: ${i.auth.dkim}<br>DMARC: ${i.auth.dmarc}</p>` : ""}
      ${tab === "links" ? renderLinksTab(i) : ""}
      ${tab === "attachments" ? renderAttachmentsTab(i) : ""}
    </div>
    <div class="actions">
      <button id="assign-btn" aria-label="Assign incident">Assign</button>
      <button id="review-btn" aria-label="Set in review">In Review</button>
      <button id="resolve-btn" aria-label="Resolve incident">Resolve</button>
      <button id="tag-btn" aria-label="Add threat tag">Add Tag</button>
      <button id="phishrip-btn" aria-label="Run PhishRIP simulation" ${i.phishml !== "threat" ? "disabled" : ""}>Run PhishRIP</button>
      <button id="block-btn" aria-label="Block sender domain">Block</button>
    </div>
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
  pane.querySelector("#assign-btn").addEventListener("click", () => clickAction(i, "👤", "Assigned to analyst."));
  pane.querySelector("#review-btn").addEventListener("click", () => {
    if (i.status === "received") {
      i.status = "in_review";
      clickAction(i, "🛠", "Status changed to In Review.");
    }
  });
  pane.querySelector("#resolve-btn").addEventListener("click", () => {
    if (i.status === "in_review") {
      i.status = "resolved";
      clickAction(i, "✅", "Status changed to Resolved.");
    }
  });
  pane.querySelector("#tag-btn").addEventListener("click", () => {
    if (!i.tags.includes("Needs Investigation")) i.tags.push("Needs Investigation");
    clickAction(i, "🏷", "Tag added: Needs Investigation.");
  });
  pane.querySelector("#block-btn").addEventListener("click", () => clickAction(i, "⛔", "Sender domain blocked."));
  pane.querySelector("#phishrip-btn").addEventListener("click", () => runPhishRip(i));

  pane.querySelectorAll(".urlscan-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const domain = btn.dataset.domain;
      window.open(`https://urlscan.io/search/#domain:${encodeURIComponent(domain)}`, "_blank", "noopener,noreferrer");
      appendLog(i, "🔎", `Pivoted to URLScan search for ${domain}.`, "analyst");
      save();
    });
  });

  const extractBtn = pane.querySelector("#extract-qr-btn");
  if (extractBtn) {
    extractBtn.addEventListener("click", () => {
      i.extractedQrUrl = i.qrData || i.links[0];
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
  });
}

function clickAction(i, icon, text) {
  if (isLocked()) return;
  appendLog(i, icon, text, "analyst");
  save();
  renderAll();
}

function runPhishRip(i) {
  if (isLocked()) return;
  const modal = document.getElementById("phishrip-modal");
  const bar = document.getElementById("phishrip-bar");
  const txt = document.getElementById("phishrip-text");
  modal.classList.remove("hidden");
  let pct = 0;
  bar.style.width = "0%";
  txt.textContent = "Scanning 5,000 mailboxes...";
  const timer = setInterval(() => {
    pct += 10;
    bar.style.width = `${pct}%`;
    if (pct >= 100) {
      clearInterval(timer);
      const ripped = rand(3, 48);
      txt.textContent = `Scan complete. ${ripped} identical threats ripped (quarantined).`;
      appendLog(i, "🧹", `PhishRIP completed. ${ripped} threats quarantined.`, "system");
      save();
      renderTriage();
    }
  }, 180);
}

function runDetonation(i) {
  const modal = document.getElementById("detonate-modal");
  const out = document.getElementById("detonate-output");
  modal.classList.remove("hidden");
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
  out.textContent = "";
  let idx = 0;
  const timer = setInterval(() => {
    out.textContent += `${lines[idx]}\n`;
    out.scrollTop = out.scrollHeight;
    idx += 1;
    if (idx >= lines.length) {
      clearInterval(timer);
      appendLog(i, "💣", `Detonation completed for ${file.name}. Verdict: malicious behavior observed.`, "sandbox");
      save();
    }
  }, 380);
}

function classifySelected(label) {
  if (isLocked()) return;
  const i = state.incidents.find((x) => x.id === selected);
  if (!i) return;
  i.phishml = label;
  if (label === "threat") i.priority = "high";
  if (label === "spam") i.priority = "medium";
  if (label === "clean") i.priority = "low";
  appendLog(i, "⌨", `Shortcut classification set to ${label.toUpperCase()}.`, "analyst");
  save();
  renderAll();
}

function updateTimer() {
  const el = document.getElementById("shift-timer");
  const left = Math.max(0, Math.floor((state.shiftEndsAt - Date.now()) / 1000));
  const m = Math.floor(left / 60);
  const s = left % 60;
  el.textContent = `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
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
  document.getElementById("reset-sim").addEventListener("click", () => {
    state = freshState();
    selected = state.incidents[0]?.id || null;
    answerKey = false;
    save();
    renderAll();
  });
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
  updateTimer();
}

bind();
renderAll();
shiftTimer = setInterval(updateTimer, 1000);
