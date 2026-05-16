/* ═══════════════════════════════════════════════════════════════
   KnowBe4 PhishER Simulator — app.js
   Teaching tool: simulates the PhishER inbox triage workflow.
═══════════════════════════════════════════════════════════════ */

const STORE = "phisher-enterprise-v9";
const SHIFT_SECONDS = 30 * 60;
const TABS = ["preview", "headers", "auth", "links", "attachments"];

/* Training-safe destinations (RFC 2606 .invalid) */
const THREAT_URLS = {
  itSupport: "https://signin.okta-verify.invalid/login",
  office365: "https://office365-login.office-verify.invalid/common/oauth2",
  shipping:  "https://track.fedex-parcel.invalid/status",
  cfoWire:   "https://secure.sharepoint-wire.invalid/finance",
  knownKit:  "https://security-update.office365-kit.invalid/renew"
};

/* Real vendor homepages for clean scenarios */
const CLEAN_URLS = [
  "https://www.microsoft.com",
  "https://www.okta.com",
  "https://www.docusign.com",
  "https://www.zoom.us",
  "https://www.workday.com"
];

const USER_PROFILES = {
  "Maya Torres (CFO)":                 { department: "Finance",    riskScore: 94 },
  "Rafi Islam (IT Admin)":             { department: "IT",         riskScore: 71 },
  "Nina Patel (Sales Intern)":         { department: "Sales",      riskScore: 67 },
  "Liam Chowdhury (Security Analyst)": { department: "SOC",        riskScore: 48 },
  "Sadia Rahman (HR Lead)":            { department: "HR",         riskScore: 38 },
  "Omar Khan (Finance Manager)":       { department: "Finance",    riskScore: 86 },
  "Jui Sarker (Operations)":           { department: "Operations", riskScore: 52 }
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

/* ─── Runtime state ─────────────────────────────────────────── */
let state    = load();
let selected = state.incidents[0]?.id || null;
let answerKey  = false;
let shiftTimer = null;
let currentView = "inbox";

/* ═══════════════════════════════════════════════════════════════
   PERSISTENCE
═══════════════════════════════════════════════════════════════ */
function load() {
  const raw = localStorage.getItem(STORE);
  if (!raw) return freshState();
  try {
    const p = JSON.parse(raw);
    p.incidents         = (p.incidents || []).map(normalizeIncident);
    p.filters           = p.filters   || defaultFilters();
    p.filterPills       = p.filterPills || defaultPills();
    p.phishmlThresholds = p.phishmlThresholds || { clean: 95, spam: 95, threat: 95 };
    p.phishmlEnabled    = p.phishmlEnabled !== false;
    p.savedRooms        = p.savedRooms || [];
    p.shiftEndsAt       = p.shiftEndsAt || (Date.now() + SHIFT_SECONDS * 1000);
    p.currentView       = p.currentView || "inbox";
    p.highContrast      = Boolean(p.highContrast);
    p.finalFiveInjected = Boolean(p.finalFiveInjected);
    p.muted             = Boolean(p.muted);
    p.tutorialSeen      = Boolean(p.tutorialSeen);
    return p;
  } catch {
    return freshState();
  }
}

function freshState() {
  return {
    incidents:         generateIncidents(55).concat(generateQuishingIncidents(10)),
    filters:           defaultFilters(),
    filterPills:       defaultPills(),
    phishmlThresholds: { clean: 95, spam: 95, threat: 95 },
    phishmlEnabled:    true,
    savedRooms:        [],
    shiftEndsAt:       Date.now() + SHIFT_SECONDS * 1000,
    currentView:       "inbox",
    highContrast:      false,
    finalFiveInjected: false,
    muted:             false,
    tutorialSeen:      false
  };
}

function defaultFilters() {
  return { room: "all", query: "" };
}

function defaultPills() {
  return {
    categories: { unknown: true, clean: true, spam: true, threat: true },
    statuses:   { received: true, in_review: true, resolved: true },
    priorities: { critical: true, high: true, medium: true, low: true, unknown: true }
  };
}

function save() {
  state.currentView = currentView;
  localStorage.setItem(STORE, JSON.stringify(state));
}

/* ═══════════════════════════════════════════════════════════════
   AUDIO CUES
═══════════════════════════════════════════════════════════════ */
function playTone(freq, durationMs, type = "sine", volume = 0.04) {
  if (state.muted) return;
  const Ctx = window.AudioContext || window.webkitAudioContext;
  if (!Ctx) return;
  const ctx  = new Ctx();
  const osc  = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = type;
  osc.frequency.value = freq;
  gain.gain.value = volume;
  osc.connect(gain);
  gain.connect(ctx.destination);
  osc.start();
  setTimeout(() => { osc.stop(); ctx.close(); }, durationMs);
}

function playCue(name) {
  if (name === "resolve") {
    playTone(840,  90,  "triangle", 0.05);
    setTimeout(() => playTone(1240, 120, "triangle", 0.05), 100);
  } else if (name === "datastream") {
    [420, 520, 620, 720].forEach((f, i) => setTimeout(() => playTone(f, 75, "square", 0.02), i * 85));
  } else if (name === "warning") {
    playTone(320, 180, "sawtooth", 0.06);
    setTimeout(() => playTone(260, 180, "sawtooth", 0.06), 200);
  }
}

/* ═══════════════════════════════════════════════════════════════
   INCIDENT MODEL
═══════════════════════════════════════════════════════════════ */
function normalizeIncident(i) {
  return {
    ...i,
    status:              i.status              || "received",
    tab:                 i.tab                 || "preview",
    tags:                i.tags                || [],
    noteDraft:           i.noteDraft           || "",
    discussion:          i.discussion          || [],
    attachments:         i.attachments         || [],
    extractedQrUrl:      i.extractedQrUrl      || "",
    expectedDisposition: i.expectedDisposition || i.phishml,
    reporterProfile:     i.reporterProfile     || inferReporterProfile(i.reporter),
    reasonCode:          i.reasonCode          || "",
    pendingDisposition:  i.pendingDisposition  || i.phishml,
    humanClassified:     i.humanClassified     || false
  };
}

function inferReporterProfile(name) {
  return USER_PROFILES[name] ? name : "Liam Chowdhury (Security Analyst)";
}

/* ─── Category display (PhishML threshold logic) ─────────────
   In real PhishER items start as "Unknown" until PhishML is
   confident (score >= threshold) or a human classifies them.  */
function getDisplayCategory(i) {
  if (i.humanClassified) return i.phishml;
  if (!state.phishmlEnabled) return "unknown";
  const t   = state.phishmlThresholds;
  const exp = i.expectedDisposition;
  if (exp === "threat" && i.phishmlScore >= t.threat) return "threat";
  if (exp === "spam"   && i.phishmlScore >= t.spam)   return "spam";
  if (exp === "clean"  && i.phishmlScore >= t.clean)  return "clean";
  return "unknown";
}

/* ─── Helpers ────────────────────────────────────────────────── */
function now()          { return new Date().toLocaleString(); }
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function parseFromName(from) {
  return from.replace(/<[^>]+>/, "").trim().replace(/^"|"$/g, "");
}
function parseFromEmail(from) {
  const m = from.match(/<([^>]+)>/);
  return m ? m[1] : from;
}

function riskClass(score) {
  if (score >= 90) return "risk-critical";
  if (score >= 80) return "risk-high";
  return "";
}

function pastReportCount(name) {
  return state.incidents.filter((i) => i.reporter === name).length;
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

function isLocked() { return Date.now() >= state.shiftEndsAt; }

function getDomain(link) {
  const raw = typeof link === "string" ? link : link.destination;
  return raw.replace(/^hxxps?:\/\//, "").replace(/^https?:\/\//, "").replace(/\[\.\]/g, ".").split("/")[0];
}

function makeLink(visibleText, destination, intel = "") {
  return { visibleText, destination, intel };
}

function catBadgeHtml(cat) {
  const labels = { unknown: "Unknown", clean: "Clean", spam: "Spam", threat: "Threat" };
  return `<span class="cat-badge cat-${cat}">${labels[cat] || cat}</span>`;
}

function appendLog(i, icon, text, actor = "system") {
  i.discussion.push({ ts: now(), icon, text, actor });
}

function appendEvidenceClip(i, clipText) {
  if (!(i.noteDraft || "").includes(clipText)) {
    i.noteDraft = `${(i.noteDraft || "").trim()}\n${clipText}`.trim();
  }
}

/* ═══════════════════════════════════════════════════════════════
   INCIDENT GENERATORS
═══════════════════════════════════════════════════════════════ */
function auth(malicious, idx) {
  if (malicious) {
    return {
      spf:   `spf=fail smtp.mailfrom=mail-${idx}.secure-alert.net`,
      dkim:  `dkim=fail header.d=secure-alert${idx}.net`,
      dmarc: "dmarc=fail p=reject"
    };
  }
  return {
    spf:   "spf=pass smtp.mailfrom=academy.local",
    dkim:  "dkim=pass header.d=academy.local",
    dmarc: "dmarc=pass p=quarantine"
  };
}

function randomHash(len) {
  const chars = "abcdef0123456789";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[rand(0, chars.length - 1)];
  return out;
}

function makeAttachment(nameBase, suspicious) {
  const ext = suspicious
    ? ["pdf.exe", "docm", "html", "zip"][rand(0, 3)]
    : ["pdf", "docx", "xlsx"][rand(0, 2)];
  return { name: `${nameBase}.${ext}`, size: `${rand(42, 940)} KB`, md5: randomHash(32), sha256: randomHash(64) };
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

function pickReporter(idx, targetRisk = "mixed") {
  const names = Object.keys(USER_PROFILES);
  if (targetRisk === "high") {
    const high = names.filter((n) => USER_PROFILES[n].department === "Finance");
    return high[idx % high.length];
  }
  return names[idx % names.length];
}

function generateIncidentByType(type, idx) {
  const id   = `PHI-${String(idx).padStart(4, "0")}`;
  const base = {
    id, icon: "✉", status: "received", date: now(),
    room: "inbox", tags: [], discussion: [], noteDraft: "", extractedQrUrl: "",
    humanClassified: false
  };

  if (type === "ceo_fraud") {
    const from     = "CEO Office <ceo@academy-leadership.com>";
    const reply    = `payment-ops${idx}@academy-wire-safe.net`;
    const a        = auth(true, idx);
    const reporter = pickReporter(idx, "high");
    return normalizeIncident({
      ...base, category: "CEO Fraud", priority: "critical", reporter, reporterProfile: reporter,
      subject: `Confidential Wire Request ${idx}`, phishml: "threat", expectedDisposition: "threat",
      phishmlScore: rand(88, 99), from, replyTo: reply,
      preview: "Urgent request from executive persona to complete same-day wire transfer.",
      links:       [makeLink("https://www.office.com/", THREAT_URLS.cfoWire, "Training: visible brand vs typosquat destination (.invalid).")],
      attachments: [makeAttachment("wire_statement", true)],
      auth: a, raw: rawHeaders(from, reply, a, idx),
      redFlag: "Reply-To domain does not match executive sender domain."
    });
  }

  if (type === "mfa_fatigue") {
    const from     = `Identity Alerts <no-reply@id-prompt${idx}.com>`;
    const reply    = `helpdesk@id-prompt${idx}.com`;
    const a        = auth(true, idx);
    const reporter = pickReporter(idx);
    return normalizeIncident({
      ...base, category: "MFA Fatigue", priority: "high", reporter, reporterProfile: reporter,
      subject: `Repeated MFA Prompt Alert ${idx}`, phishml: "spam", expectedDisposition: "threat",
      phishmlScore: rand(55, 79), from, replyTo: reply,
      preview: "Unexpected multiple MFA prompts with urgent 'approve now' language.",
      links:       [makeLink("https://www.okta.com/", THREAT_URLS.itSupport, "Training: legitimate-looking label vs fake sign-in host.")],
      attachments: [makeAttachment("mfa_alert", true)],
      auth: a, raw: rawHeaders(from, reply, a, idx),
      redFlag: "Unexpected MFA approval lure from non-corporate sender domain."
    });
  }

  if (type === "password_reset") {
    const from     = `IT Password Reset <password-reset${idx}@academy-support-help.com>`;
    const reply    = `reset@academy-support-help.com`;
    const a        = auth(true, idx);
    const reporter = pickReporter(idx);
    return normalizeIncident({
      ...base, category: "IT Password Reset", priority: "medium", reporter, reporterProfile: reporter,
      subject: `Password Reset Confirmation ${idx}`, phishml: "spam", expectedDisposition: "spam",
      phishmlScore: rand(45, 74), from, replyTo: reply,
      preview: "Reset link expires in 5 minutes. Immediate action required.",
      links:       [makeLink("https://login.microsoftonline.com/", idx % 4 === 0 ? THREAT_URLS.knownKit : THREAT_URLS.office365, "Training: OAuth-looking lure — verify destination host.")],
      attachments: [makeAttachment("reset_notice", true)],
      auth: a, raw: rawHeaders(from, reply, a, idx),
      redFlag: "Lookalike support domain and authentication failures."
    });
  }

  /* Clean newsletter */
  const from     = "HR Newsletter <hr-news@academy.local>";
  const reply    = "hr-news@academy.local";
  const a        = auth(false, idx);
  const reporter = pickReporter(idx);
  return normalizeIncident({
    ...base, category: "Clean Newsletter", priority: "low", reporter, reporterProfile: reporter,
    subject: `HR Monthly Newsletter ${idx}`, phishml: "clean", expectedDisposition: "clean",
    phishmlScore: rand(5, 30), from, replyTo: reply,
    preview: "Internal HR updates and employee engagement announcements.",
    links:       [makeLink(CLEAN_URLS[idx % CLEAN_URLS.length], CLEAN_URLS[idx % CLEAN_URLS.length], "Real vendor homepage — label matches destination.")],
    attachments: [makeAttachment("newsletter", false)],
    auth: a, raw: rawHeaders(from, reply, a, idx),
    redFlag: "No significant red flag. Legitimate internal communication."
  });
}

function generateIncidents(total) {
  const kinds = ["ceo_fraud", "mfa_fatigue", "password_reset", "clean"];
  return Array.from({ length: total }, (_, k) => generateIncidentByType(kinds[k % kinds.length], k + 1));
}

function generateQuishingIncidents(total) {
  return Array.from({ length: total }, (_, k) => {
    const i       = k + 1;
    const idx     = 9000 + i;
    const from    = "IT Service Desk <it-support@academy-ithelp.com>";
    const reply   = `security${idx}@academy-ithelp.com`;
    const a       = auth(true, idx);
    const url     = THREAT_URLS.shipping;
    const reporter = pickReporter(idx, "high");
    return normalizeIncident({
      id: `PHI-Q${String(i).padStart(3, "0")}`,
      icon: "▣", status: "received", date: now(), room: "inbox",
      category: "Quishing", priority: "high", reporter, reporterProfile: reporter,
      subject: `MFA Re-Enrollment Required (QR) Q${i}`,
      phishml: "threat", expectedDisposition: "threat",
      phishmlScore: rand(76, 98), from, replyTo: reply,
      preview: "Scan the QR code below to restore your MFA access immediately.",
      links:       [makeLink("https://www.fedex.com/", url, "Training: carrier branding vs fake tracking host.")],
      attachments: [makeAttachment("mfa_qr", true)],
      auth: a, raw: rawHeaders(from, reply, a, idx),
      redFlag: "QR-code lure paired with suspicious domain and failing auth.",
      tags: [], discussion: [], noteDraft: "",
      qrData: url, extractedQrUrl: "", humanClassified: false
    });
  });
}

function generateSurgeIncidents(total) {
  return Array.from({ length: total }, () => {
    const idx      = 12000 + rand(1, 999);
    const reporter = pickReporter(idx, "high");
    const type     = ["ceo_fraud", "mfa_fatigue", "password_reset"][rand(0, 2)];
    const incident = generateIncidentByType(type, idx);
    incident.reporter        = reporter;
    incident.reporterProfile = reporter;
    incident.priority        = ["critical", "high"][rand(0, 1)];
    incident.date            = `${now()} (SURGE)`;
    incident.subject         = `[Final 5] ${incident.subject}`;
    return incident;
  });
}

/* ═══════════════════════════════════════════════════════════════
   FILTERING
═══════════════════════════════════════════════════════════════ */
function filtered() {
  const f    = state.filters;
  const pills = state.filterPills;

  return state.incidents.filter((i) => {
    /* Room quick-filter */
    if (f.room !== "all") {
      if (f.room === "critical" && i.priority !== "critical") return false;
      if (f.room === "review"   && i.status   !== "in_review") return false;
      if (f.room === "resolved" && i.status   !== "resolved")  return false;
      if (f.room === "inbox"    && i.room     !== "inbox")     return false;
      /* Saved rooms have their own filter snapshot */
      const savedRoom = state.savedRooms.find((r) => r.id === f.room);
      if (savedRoom) {
        const sf = savedRoom.snapshot;
        if (sf.query && !`${i.reporter} ${i.subject} ${i.from} ${i.replyTo}`.toLowerCase().includes(sf.query.toLowerCase())) return false;
      }
    }

    /* Category pill filter */
    const cat = getDisplayCategory(i);
    if (!pills.categories[cat]) return false;

    /* Status pill filter */
    if (!pills.statuses[i.status]) return false;

    /* Priority pill filter */
    if (!pills.priorities[i.priority]) return false;

    /* Text search */
    if (f.query) {
      const hay = `${i.reporter} ${i.subject} ${i.from} ${i.replyTo}`.toLowerCase();
      if (!hay.includes(f.query.toLowerCase())) return false;
    }

    return true;
  });
}

/* ═══════════════════════════════════════════════════════════════
   RENDER — INBOX TABLE
═══════════════════════════════════════════════════════════════ */
function renderRows() {
  const tbody  = document.getElementById("incident-rows");
  const rows   = filtered();

  document.getElementById("incident-count").textContent =
    `${rows.length.toLocaleString()} of ${state.incidents.length.toLocaleString()}`;

  tbody.innerHTML = rows.map((i) => {
    const profile    = USER_PROFILES[i.reporterProfile] || USER_PROFILES[inferReporterProfile(i.reporter)];
    const scoreClass = riskClass(profile.riskScore);
    const cat        = getDisplayCategory(i);
    const fromName   = parseFromName(i.from);
    const fromEmail  = parseFromEmail(i.from);
    const hasAttach  = i.attachments && i.attachments.length > 0;

    return `
      <tr class="incident-row ${i.id === selected ? "active" : ""}" data-id="${i.id}">
        <td class="col-check"><input type="checkbox" aria-label="Select incident ${i.id}" onclick="event.stopPropagation()" /></td>
        <td class="col-category">${catBadgeHtml(cat)}</td>
        <td class="col-from reporter-cell">
          <span class="reporter-tag">${fromName}</span>
          <div class="reporter-tip">
            <div><strong>Reported by:</strong> ${i.reporter}</div>
            <div><strong>Dept:</strong> ${profile.department}</div>
            <div><strong>Risk Score:</strong> <span class="${scoreClass}">${profile.riskScore}</span></div>
            <div><strong>Past Reports:</strong> ${pastReportCount(i.reporter)}</div>
          </div>
        </td>
        <td class="col-from-email"><span class="from-email-cell" title="${fromEmail}">${fromEmail}</span></td>
        <td class="col-subject">${i.subject}</td>
        <td class="col-attach">${hasAttach ? '<span class="attach-icon" title="Has attachment">📎</span>' : ""}</td>
        <td class="col-reported-at">${i.date}</td>
      </tr>`;
  }).join("");

  tbody.querySelectorAll(".incident-row").forEach((r) => {
    r.addEventListener("click", () => {
      if (isLocked()) return;
      selected = r.dataset.id;
      renderAll();
    });
  });
}

/* ═══════════════════════════════════════════════════════════════
   RENDER — TRIAGE SIDEBAR
═══════════════════════════════════════════════════════════════ */
function renderPreviewTab(i, mismatch) {
  const qrPayload = i.qrData || i.links[0]?.destination || "";
  const qr = i.category === "Quishing"
    ? `<div class="qr-preview"><img alt="QR phishing preview" src="https://api.qrserver.com/v1/create-qr-code/?size=140x140&data=${encodeURIComponent(qrPayload)}" /></div>`
    : "";
  const flag = answerKey ? `<p class="${mismatch ? "warn" : "ok"}"><strong>Instructor Note:</strong> ${i.redFlag}</p>` : "";
  return `<p>${i.preview}</p>${qr}${flag}`;
}

function renderLinksTab(i) {
  const rows = i.links.map((l) => `
    <div class="link-row">
      <span class="mono"><strong>Visible Text:</strong> ${l.visibleText}<br><strong>Actual URL:</strong> ${l.destination}</span>
      <button class="urlscan-btn" data-domain="${getDomain(l)}" aria-label="Search domain on URLScan">URLScan ↗</button>
    </div>
    ${l.intel ? `<p class="muted" style="margin:0 0 8px">OSINT: ${l.intel}</p>` : ""}
  `).join("");

  const qrExtract = i.category === "Quishing"
    ? `<button id="extract-qr-btn" aria-label="Extract URL from QR code">Extract URL from QR</button>
       <p class="muted">${i.extractedQrUrl || ""}</p>`
    : "";

  return `
    <p class="muted">Suspicious destinations use reserved <code>.invalid</code> domains — safe for classroom practice.</p>
    ${rows}${qrExtract}`;
}

function renderAttachmentsTab(i) {
  const rows = i.attachments.map((a) =>
    `<tr><td>${a.name}</td><td>${a.size}</td><td class="mono">${a.md5.slice(0, 12)}…</td><td class="mono">${a.sha256.slice(0, 16)}…</td></tr>`
  ).join("");
  return `
    <table class="grid" style="font-size:11px">
      <thead><tr><th>Name</th><th>Size</th><th>MD5</th><th>SHA256</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <button id="detonate-btn" style="margin-top:8px" aria-label="Detonate selected file in sandbox">Detonate in Sandbox 💣</button>`;
}

function updateResolveButton(i) {
  const pane = document.getElementById("triage-pane");
  if (!pane || selected !== i.id) return;
  const btn = pane.querySelector("#resolve-btn");
  if (!btn) return;
  btn.disabled = !(i.status === "in_review" && i.reasonCode && (i.noteDraft || "").trim().length >= 20);
}

function patchNotesUI(i) {
  const pane = document.getElementById("triage-pane");
  if (!pane || selected !== i.id) { renderTriage(); return; }
  const ta = pane.querySelector("#analyst-notes");
  if (ta) {
    const pos = typeof ta.selectionStart === "number" ? ta.selectionStart : null;
    ta.value = i.noteDraft || "";
    updateResolveButton(i);
    if (pos !== null) {
      const at = Math.min(Math.max(pos, 0), ta.value.length);
      requestAnimationFrame(() => { try { ta.focus(); ta.setSelectionRange(at, at); } catch (_) {} });
    }
  } else {
    renderTriage();
  }
}

function renderTriage() {
  const pane = document.getElementById("triage-pane");
  const i    = state.incidents.find((x) => x.id === selected);
  if (!i) {
    pane.innerHTML = `<p class="triage-placeholder">Select an incident from the list to begin triage.</p>`;
    return;
  }

  const tab        = i.tab || "preview";
  const locked     = isLocked();
  const fromName   = parseFromName(i.from);
  const fromEmail  = parseFromEmail(i.from);
  const mismatch   = fromEmail.split("@")[1] !== i.replyTo.split("@")[1];
  const noteLength = (i.noteDraft || "").trim().length;
  const canResolve = i.status === "in_review" && Boolean(i.reasonCode) && noteLength >= 20;
  const cat        = getDisplayCategory(i);

  const headerDebrief = mismatch
    ? "Reply-To diverges from the sender domain — a classic routing redirection indicator. Check the actual destination."
    : "Header alignment looks normal. Confirm intent via links and attachment behavior.";
  const authDebrief = i.auth.spf.includes("fail")
    ? "SPF failed: the observed sending source is not authorized for the claimed domain — spoofing risk."
    : "SPF passed. Note this can still occur on lookalike domains; continue layered validation.";

  pane.innerHTML = `
    <div class="confidence">
      <div class="confidence-head">
        <span>PhishML Score: <strong>${i.phishmlScore}%</strong></span>
        <span>${confidenceText(i.phishmlScore)} Likelihood &nbsp; ${catBadgeHtml(cat)}</span>
      </div>
      <div class="confidence-bar" style="width:${i.phishmlScore}%; background:${confidenceColor(i.phishmlScore)};"></div>
    </div>

    <h3 style="margin:8px 0 4px;font-size:14px">${i.subject}</h3>
    <p class="muted" style="margin:0 0 8px">
      <strong>From:</strong> ${fromName} &lt;${fromEmail}&gt;<br>
      <strong>Reply-To:</strong> ${i.replyTo}<br>
      <strong>Reported by:</strong> ${i.reporter}
    </p>

    <div class="tabs">
      ${TABS.map((t) => `<button class="tab ${t === tab ? "active" : ""}" data-tab="${t}" aria-label="Open ${t} tab">${t.toUpperCase()}</button>`).join("")}
    </div>
    <div class="tab-panel">
      ${tab === "preview"     ? renderPreviewTab(i, mismatch) : ""}
      ${tab === "headers"     ? `
        <div class="headers-lab">
          <div class="header-line"><strong>From:</strong> ${i.from}</div>
          <div class="header-line ${mismatch ? "suspicious" : ""}"><strong>Reply-To:</strong> ${i.replyTo}</div>
        </div>
        <p class="${mismatch ? "warn" : "ok"}">${mismatch ? "⚠ From / Reply-To mismatch detected — possible spoofing." : "✓ No mismatch detected."}</p>
        ${answerKey ? `<div class="debrief"><strong>Instructor:</strong> ${headerDebrief}</div>` : ""}` : ""}
      ${tab === "auth"        ? `
        <p class="muted">Authentication results from mail headers:</p>
        <div class="${i.auth.spf.includes("fail") ? "warn" : "ok"}" style="margin-bottom:6px"><strong>SPF:</strong> ${i.auth.spf}</div>
        <div class="${i.auth.dkim.includes("fail") ? "warn" : "ok"}" style="margin-bottom:6px"><strong>DKIM:</strong> ${i.auth.dkim}</div>
        <div class="${i.auth.dmarc.includes("fail") ? "warn" : "ok"}"><strong>DMARC:</strong> ${i.auth.dmarc}</div>
        ${answerKey ? `<div class="debrief" style="margin-top:8px"><strong>Instructor:</strong> ${authDebrief}</div>` : ""}` : ""}
      ${tab === "links"       ? renderLinksTab(i) : ""}
      ${tab === "attachments" ? renderAttachmentsTab(i) : ""}
    </div>

    <div class="actions">
      <button id="classify-threat-btn" style="background:#fff0eb;border-color:#e05000;color:#7c2d12;font-weight:700" aria-label="Classify as threat">Threat</button>
      <button id="classify-spam-btn"   style="background:#f5f3ff;border-color:#7c3aed;color:#4c1d95;font-weight:700" aria-label="Classify as spam">Spam</button>
      <button id="classify-clean-btn"  style="background:#f0fdf4;border-color:#16a34a;color:#14532d;font-weight:700" aria-label="Classify as clean">Clean</button>
      <button id="assign-btn"   aria-label="Assign incident">Assign</button>
      <button id="review-btn"   aria-label="Set status to In Review" ${i.status !== "received" ? "disabled" : ""}>In Review</button>
      <button id="resolve-btn"  aria-label="Resolve incident" ${canResolve ? "" : "disabled"}>Resolve ✓</button>
      <button id="tag-btn"      aria-label="Add Needs Investigation tag">Add Tag</button>
      <button id="block-btn"    aria-label="Block sender domain">Block Sender</button>
      <button id="phishrip-btn" aria-label="Run PhishRIP simulation"  ${cat !== "threat" ? "disabled" : ""}>Run PhishRIP 🧹</button>
      <button id="zap-btn"      aria-label="Run zero-hour auto purge" ${cat !== "threat" ? "disabled" : ""}>Run ZAP ⚡</button>
      <button id="phishflip-btn" aria-label="Convert threat to training" ${cat !== "threat" ? "disabled" : ""}>PhishFlip 🔄</button>
    </div>

    <label>Reason Code <span style="color:#dc2626">(required)</span>
      <select id="reason-code" aria-label="Reason code for disposition">
        <option value="">Select a reason…</option>
        ${REASON_CODES.map((code) => `<option value="${code}" ${i.reasonCode === code ? "selected" : ""}>${code}</option>`).join("")}
      </select>
    </label>

    <label>Analyst Notes <span class="muted">(min 20 chars to resolve — auto-saves)</span>
      <textarea id="analyst-notes" rows="4" aria-label="Analyst notes" ${locked ? "disabled" : ""}>${i.noteDraft || ""}</textarea>
    </label>

    <div class="shortcut-legend"><strong>Shortcuts:</strong> <kbd>T</kbd> Threat &nbsp; <kbd>S</kbd> Spam &nbsp; <kbd>C</kbd> Clean — disabled while typing.</div>

    <div class="log">
      ${i.discussion.length
        ? i.discussion.slice().reverse().map((d) => `<div class="log-entry">${d.icon} <strong>${d.ts}</strong> — ${d.text}</div>`).join("")
        : "<div style='color:#94a3b8'>No activity logged yet.</div>"}
    </div>`;

  /* ── Event listeners ── */
  pane.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
    i.tab = b.dataset.tab; save(); renderTriage();
  }));

  pane.querySelector("#classify-threat-btn").addEventListener("click", () => setDisposition(i, "threat"));
  pane.querySelector("#classify-spam-btn").addEventListener("click",   () => setDisposition(i, "spam"));
  pane.querySelector("#classify-clean-btn").addEventListener("click",  () => setDisposition(i, "clean"));

  pane.querySelector("#assign-btn").addEventListener("click",  () => clickAction(i, "👤", "Assigned to analyst queue."));
  pane.querySelector("#review-btn").addEventListener("click",  () => {
    if (i.status === "received") { i.status = "in_review"; clickAction(i, "🛠", "Status → In Review."); }
  });
  pane.querySelector("#resolve-btn").addEventListener("click", () => {
    if (i.status === "in_review" && i.reasonCode && noteLength >= 20) {
      i.status = "resolved";
      clickAction(i, "✅", `Resolved. Reason: ${i.reasonCode}.`);
      showToast(`Incident ${i.id} resolved.`);
      playCue("resolve");
    }
  });
  pane.querySelector("#tag-btn").addEventListener("click",   () => {
    if (!i.tags.includes("Needs Investigation")) i.tags.push("Needs Investigation");
    clickAction(i, "🏷", "Tag added: Needs Investigation.");
  });
  pane.querySelector("#block-btn").addEventListener("click",     () => clickAction(i, "⛔", "Sender domain blocked."));
  pane.querySelector("#phishrip-btn").addEventListener("click",  () => runPhishRip(i));
  pane.querySelector("#zap-btn").addEventListener("click",       () => runZap(i));
  pane.querySelector("#phishflip-btn").addEventListener("click", () => runPhishFlip(i));

  pane.querySelectorAll(".urlscan-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const domain = btn.dataset.domain;
      window.open(`https://urlscan.io/search/#domain:${encodeURIComponent(domain)}`, "_blank", "noopener,noreferrer");
      appendLog(i, "🔎", `URLScan search for domain: ${domain}.`, "analyst");
      appendEvidenceClip(i, "Evidence: [OSINT Search Logged]");
      save(); patchNotesUI(i);
    });
  });

  const extractBtn = pane.querySelector("#extract-qr-btn");
  if (extractBtn) {
    extractBtn.addEventListener("click", () => {
      i.extractedQrUrl = typeof i.qrData === "string" ? i.qrData : i.links[0]?.destination || "";
      appendLog(i, "▣", `Extracted URL from QR code: ${i.extractedQrUrl}`, "analyst");
      save(); renderTriage();
    });
  }

  const detonateBtn = pane.querySelector("#detonate-btn");
  if (detonateBtn) detonateBtn.addEventListener("click", () => runDetonation(i));

  pane.querySelector("#analyst-notes").addEventListener("input", (e) => {
    i.noteDraft = e.target.value; save(); updateResolveButton(i);
  });
  pane.querySelector("#reason-code").addEventListener("change", (e) => {
    i.reasonCode = e.target.value; save(); updateResolveButton(i);
  });
}

/* ═══════════════════════════════════════════════════════════════
   ACTIONS
═══════════════════════════════════════════════════════════════ */
function setDisposition(i, label) {
  if (isLocked()) return;
  i.phishml          = label;
  i.humanClassified  = true;
  i.pendingDisposition = label;
  if (label === "threat") i.priority = "high";
  if (label === "spam")   i.priority = "medium";
  if (label === "clean")  i.priority = "low";
  appendLog(i, "🧭", `Disposition set: ${label.toUpperCase()}.`, "analyst");
  save(); renderAll();
}

function clickAction(i, icon, text) {
  if (isLocked()) return;
  appendLog(i, icon, text, "analyst");
  save(); renderAll();
}

function runPhishRIPLike(messageBuilder, i, icon, doneMessage) {
  if (isLocked()) return;
  const modal = document.getElementById("phishrip-modal");
  const bar   = document.getElementById("phishrip-bar");
  const txt   = document.getElementById("phishrip-text");
  modal.classList.remove("hidden");
  bar.style.width = "0%";
  txt.textContent = messageBuilder("start");
  let pct = 0;
  const timer = setInterval(() => {
    pct += 10;
    bar.style.width = `${pct}%`;
    if (pct >= 100) {
      clearInterval(timer);
      txt.textContent = messageBuilder("end");
      appendLog(i, icon, doneMessage, "system");
      save(); renderTriage();
    }
  }, 180);
}

function runPhishRip(i) {
  const ripped = rand(3, 48);
  runPhishRIPLike(
    (p) => p === "start" ? "Scanning 5,000 mailboxes…" : `Scan complete. ${ripped} identical threats quarantined.`,
    i, "🧹", `PhishRIP complete — ${ripped} identical threats quarantined.`
  );
}

function runZap(i) {
  const domain  = getDomain(i.links[0] || { destination: i.replyTo });
  const removed = rand(7, 110);
  runPhishRIPLike(
    (p) => p === "start" ? `ZAP scanning domain ${domain}…` : `ZAP complete. ${removed} messages purged for ${domain}.`,
    i, "⚡", `ZAP executed — ${removed} messages purged for domain ${domain}.`
  );
}

function runPhishFlip(i) {
  if (isLocked() || getDisplayCategory(i) !== "threat") return;
  appendLog(i, "🔄", "Threat sanitized and converted to training campaign.", "system");
  if (!i.tags.includes("PhishFlip")) i.tags.push("PhishFlip");
  save(); renderTriage(); renderAnalytics();
}

function runDetonation(i) {
  const modal = document.getElementById("detonate-modal");
  const out   = document.getElementById("detonate-output");
  modal.classList.remove("hidden");
  playCue("datastream");
  const file  = i.attachments[0];
  const lines = [
    `[${now()}] Initializing sandbox container…`,
    `[${now()}] Mounting sample: ${file.name}`,
    `[${now()}] Analyzing file structure…`,
    `[${now()}] Static signature: suspicious entropy detected`,
    `[${now()}] Heuristic check: Malicious API calls detected`,
    `[${now()}] Network emulation: C2 beacon attempt observed`,
    `[${now()}] Verdict: MALICIOUS`
  ];
  if (i.links?.[0]?.destination?.includes("office365-kit.invalid")) {
    lines.splice(lines.length - 1, 0, `[${now()}] Matched known phishing kit: "PhishKit-V3-Office365"`);
  }
  out.textContent = "";
  let idx = 0;
  const timer = setInterval(() => {
    out.textContent += `${lines[idx]}\n`;
    out.scrollTop = out.scrollHeight;
    idx++;
    if (idx >= lines.length) {
      clearInterval(timer);
      appendLog(i, "💣", `Sandbox detonation of ${file.name}: malicious behavior confirmed.`, "sandbox");
      appendEvidenceClip(i, "Evidence: [Sandbox Detonation Performed]");
      save(); patchNotesUI(i); renderAnalytics();
    }
  }, 380);
}

function classifySelected(label) {
  if (isLocked()) return;
  const i = state.incidents.find((x) => x.id === selected);
  if (!i) return;
  setDisposition(i, label);
  appendLog(i, "⌨", `Keyboard shortcut — classified as ${label.toUpperCase()}.`, "analyst");
}

/* ═══════════════════════════════════════════════════════════════
   RENDER — DASHBOARD ANALYTICS
═══════════════════════════════════════════════════════════════ */
function metricBar(label, value, total, color = "#1d4ed8") {
  const pct = total ? Math.round((value / total) * 100) : 0;
  return `
    <div class="metric-row">
      <span>${label}: ${value} (${pct}%)</span>
      <div class="metric-bar"><div class="metric-fill" style="width:${pct}%;background:${color}"></div></div>
    </div>`;
}

function renderAnalytics() {
  const host = document.getElementById("analytics-content");
  if (!host) return;
  const all        = state.incidents;
  const resolved   = all.filter((i) => i.status === "resolved").length;
  const pending    = all.length - resolved;
  const threat     = all.filter((i) => i.phishml === "threat").length;
  const spam       = all.filter((i) => i.phishml === "spam").length;
  const clean      = all.filter((i) => i.phishml === "clean").length;
  const correct    = all.filter((i) => i.humanClassified && i.phishml === i.expectedDisposition).length;
  const classified = all.filter((i) => i.humanClassified).length;
  const neutralized = all.reduce((s, i) => s + i.discussion.filter((d) => d.icon === "🧹" || d.icon === "⚡").length, 0);
  const accuracy   = classified ? Math.round((correct / classified) * 100) : 0;

  host.innerHTML = `
    <p style="margin:8px 0"><strong>Accuracy:</strong> ${accuracy}% (${correct}/${classified} human-classified)
    &nbsp;|&nbsp; <strong>Neutralized:</strong> ${neutralized}</p>
    <div class="dash-grid">
      <article class="dash-card">
        <h3>Incident Status</h3>
        ${metricBar("Resolved", resolved, all.length, "#059669")}
        ${metricBar("Pending",  pending,  all.length, "#dc2626")}
      </article>
      <article class="dash-card">
        <h3>Disposition Distribution</h3>
        ${metricBar("Threat", threat, all.length, "#e05000")}
        ${metricBar("Spam",   spam,   all.length, "#7c3aed")}
        ${metricBar("Clean",  clean,  all.length, "#16a34a")}
      </article>
      <article class="dash-card">
        <h3>Student Accuracy</h3>
        ${metricBar("Correct",   correct,              classified, "#2563eb")}
        ${metricBar("Incorrect", classified - correct, classified, "#f97316")}
        <p class="muted" style="margin-top:8px">Based on ${classified} manually classified incidents.</p>
      </article>
    </div>`;
}

/* ═══════════════════════════════════════════════════════════════
   RENDER — SETTINGS (PhishML)
═══════════════════════════════════════════════════════════════ */
function renderPhishMLSettings() {
  const host = document.getElementById("settings-content");
  if (!host) return;
  const t = state.phishmlThresholds;

  host.innerHTML = `
    <h2>PhishML</h2>
    <div class="phishml-info">
      <p><strong>PhishML</strong> is PhishER's machine-learning module. It analyzes every reported message and assigns a confidence score (0–100%) for three categories: <em>Clean</em>, <em>Spam</em>, and <em>Threat</em>.</p>
      <p>If a score meets or exceeds the <strong>confidence threshold</strong> you set below, PhishML automatically tags the message with that category — so your analysts can focus on the <em>Unknown</em> items that need human review.</p>
      <p>PhishML learns continuously from the decisions made by you and the wider KnowBe4 user community, improving accuracy over time.</p>
    </div>

    <div class="phishml-config">
      <div class="toggle-row">
        <label class="toggle-switch" aria-label="Enable PhishML">
          <input type="checkbox" id="phishml-enabled-toggle" ${state.phishmlEnabled ? "checked" : ""} />
          <span class="toggle-slider"></span>
        </label>
        <span>PhishML Enabled</span>
      </div>
      <hr class="settings-divider" />
      <p class="threshold-label">Set your Confidence Thresholds below. Messages scoring at or above a threshold are auto-tagged by PhishML.</p>

      <div class="threshold-row">
        <label class="toggle-switch" aria-label="Enable Clean threshold">
          <input type="checkbox" checked />
          <span class="toggle-slider"></span>
        </label>
        <span class="threshold-label-name" style="color:#16a34a">Clean</span>
        <input type="range" class="threshold-slider" id="clean-threshold"  min="1" max="100" value="${t.clean}" />
        <span class="threshold-val" id="clean-threshold-val">${t.clean}</span>
      </div>

      <div class="threshold-row">
        <label class="toggle-switch" aria-label="Enable Spam threshold">
          <input type="checkbox" checked />
          <span class="toggle-slider"></span>
        </label>
        <span class="threshold-label-name" style="color:#7c3aed">Spam</span>
        <input type="range" class="threshold-slider spam-slider" id="spam-threshold" min="1" max="100" value="${t.spam}" />
        <span class="threshold-val" id="spam-threshold-val">${t.spam}</span>
      </div>

      <div class="threshold-row">
        <label class="toggle-switch" aria-label="Enable Threat threshold">
          <input type="checkbox" checked />
          <span class="toggle-slider"></span>
        </label>
        <span class="threshold-label-name" style="color:#e05000">Threat</span>
        <input type="range" class="threshold-slider threat-slider" id="threat-threshold" min="1" max="100" value="${t.threat}" />
        <span class="threshold-val" id="threat-threshold-val">${t.threat}</span>
      </div>

      <div class="phishml-note">
        💡 <strong>Try it:</strong> Lower a threshold (e.g. to 50) and watch the Inbox — more items will be auto-classified instead of showing as <em>Unknown</em>.
        Raise it back to 95 to see how high-confidence thresholds keep more items in the human review queue.
      </div>
    </div>`;

  /* Bind PhishML enable toggle */
  host.querySelector("#phishml-enabled-toggle").addEventListener("change", (e) => {
    state.phishmlEnabled = e.target.checked;
    save(); renderRows();
  });

  /* Bind threshold sliders */
  ["clean", "spam", "threat"].forEach((cat) => {
    const slider = host.querySelector(`#${cat}-threshold`);
    const valEl  = host.querySelector(`#${cat}-threshold-val`);
    slider.addEventListener("input", () => {
      state.phishmlThresholds[cat] = Number(slider.value);
      valEl.textContent = slider.value;
      save(); renderRows();
    });
  });
}

/* ═══════════════════════════════════════════════════════════════
   VIEW SWITCHING
═══════════════════════════════════════════════════════════════ */
function switchView(view) {
  currentView = view;
  const views = ["inbox", "playbook", "dashboard", "settings"];
  views.forEach((v) => {
    const el  = document.getElementById(`${v}-view`);
    const btn = document.getElementById(`view-${v}`);
    if (el)  el.classList.toggle("hidden", v !== view);
    if (btn) btn.classList.toggle("active", v === view);
  });
  if (view === "dashboard") renderAnalytics();
  if (view === "settings")  renderPhishMLSettings();
  save();
}

/* ═══════════════════════════════════════════════════════════════
   PILL FILTER INITIALIZATION
═══════════════════════════════════════════════════════════════ */
function initPillFilters() {
  /* Category pills */
  document.querySelectorAll("#category-pills .filter-pill").forEach((btn) => {
    const cat = btn.dataset.cat;
    btn.classList.toggle("active", state.filterPills.categories[cat] !== false);
    btn.setAttribute("aria-pressed", state.filterPills.categories[cat] !== false ? "true" : "false");
    btn.addEventListener("click", () => {
      state.filterPills.categories[cat] = !state.filterPills.categories[cat];
      btn.classList.toggle("active", state.filterPills.categories[cat]);
      btn.setAttribute("aria-pressed", state.filterPills.categories[cat] ? "true" : "false");
      save(); renderRows();
    });
  });

  /* Status pills */
  document.querySelectorAll("#status-pills .filter-pill").forEach((btn) => {
    const s = btn.dataset.status;
    btn.classList.toggle("active", state.filterPills.statuses[s] !== false);
    btn.setAttribute("aria-pressed", state.filterPills.statuses[s] !== false ? "true" : "false");
    btn.addEventListener("click", () => {
      state.filterPills.statuses[s] = !state.filterPills.statuses[s];
      btn.classList.toggle("active", state.filterPills.statuses[s]);
      btn.setAttribute("aria-pressed", state.filterPills.statuses[s] ? "true" : "false");
      save(); renderRows();
    });
  });

  /* Priority pills */
  document.querySelectorAll("#priority-pills .filter-pill[data-priority]").forEach((btn) => {
    const p = btn.dataset.priority;
    btn.classList.toggle("active", state.filterPills.priorities[p] !== false);
    btn.setAttribute("aria-pressed", state.filterPills.priorities[p] !== false ? "true" : "false");
    btn.addEventListener("click", () => {
      state.filterPills.priorities[p] = !state.filterPills.priorities[p];
      btn.classList.toggle("active", state.filterPills.priorities[p]);
      btn.setAttribute("aria-pressed", state.filterPills.priorities[p] ? "true" : "false");
      save(); renderRows();
    });
  });
}

/* ═══════════════════════════════════════════════════════════════
   ROOMS
═══════════════════════════════════════════════════════════════ */
function renderSavedRooms() {
  const host = document.getElementById("saved-rooms-list");
  if (!host) return;
  host.innerHTML = state.savedRooms.map((r) =>
    `<button class="room-item saved-room ${state.filters.room === r.id ? "active" : ""}" data-room="${r.id}" aria-label="Room: ${r.name}">${r.name}</button>`
  ).join("");
  host.querySelectorAll(".room-item").forEach((btn) => {
    btn.addEventListener("click", () => selectRoom(btn.dataset.room));
  });
}

function selectRoom(roomId) {
  state.filters.room = roomId;
  document.querySelectorAll(".room-item").forEach((b) => b.classList.toggle("active", b.dataset.room === roomId));
  save(); renderRows(); renderSavedRooms();
}

function initRooms() {
  document.querySelectorAll("#rooms-list .room-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.room === state.filters.room);
    btn.addEventListener("click", () => selectRoom(btn.dataset.room));
  });
  renderSavedRooms();
}

/* ═══════════════════════════════════════════════════════════════
   PLAYBOOK TABS
═══════════════════════════════════════════════════════════════ */
function initPlaybookTabs() {
  const tabs   = document.querySelectorAll(".playbook-tab");
  const panels = document.querySelectorAll(".playbook-panel");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const id = tab.dataset.playbookTab;
      tabs.forEach((t) => {
        t.classList.toggle("active", t === tab);
        t.setAttribute("aria-selected", t === tab ? "true" : "false");
      });
      panels.forEach((p) => { p.hidden = p.id !== `playbook-panel-${id}`; });
    });
  });
}

/* ═══════════════════════════════════════════════════════════════
   TIMER
═══════════════════════════════════════════════════════════════ */
function updateTimer() {
  const el   = document.getElementById("shift-timer");
  const left = Math.max(0, Math.floor((state.shiftEndsAt - Date.now()) / 1000));
  const m    = Math.floor(left / 60);
  const s    = left % 60;
  el.textContent = `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  el.classList.toggle("pulse", left > 0 && left < 300);

  if (left < 300 && !state.finalFiveInjected) {
    const surge = generateSurgeIncidents(rand(3, 5));
    state.incidents = surge.concat(state.incidents);
    state.finalFiveInjected = true;
    playCue("warning");
    save(); renderRows(); renderAnalytics();
  }
  if (left === 0) {
    clearInterval(shiftTimer);
    el.textContent = "SHIFT LOCKED";
  }
}

/* ═══════════════════════════════════════════════════════════════
   CSV EXPORT
═══════════════════════════════════════════════════════════════ */
function downloadCSV() {
  const headers = ["ID", "Category (PhishML)", "From Name", "From Email", "Subject", "Reported At", "Reporter", "Status", "Tags", "Priority", "PhishML Score", "Expected"];
  const rows    = state.incidents.map((i) => [
    i.id,
    getDisplayCategory(i),
    `"${parseFromName(i.from)}"`,
    parseFromEmail(i.from),
    `"${i.subject.replace(/"/g, '""')}"`,
    i.date,
    i.reporter,
    i.status,
    `"${i.tags.join("; ")}"`,
    i.priority,
    i.phishmlScore,
    i.expectedDisposition
  ].join(","));
  const csv  = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement("a"), { href: url, download: `phisher-inbox-${Date.now()}.csv` });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast("CSV downloaded.");
}

/* ═══════════════════════════════════════════════════════════════
   SHIFT REPORT
═══════════════════════════════════════════════════════════════ */
function downloadShiftReport() {
  const all         = state.incidents;
  const classified  = all.filter((i) => i.humanClassified);
  const correct     = classified.filter((i) => i.phishml === i.expectedDisposition).length;
  const neutralized = all.reduce((s, i) => s + i.discussion.filter((d) => d.icon === "🧹" || d.icon === "⚡").length, 0);
  const accuracy    = classified.length ? Math.round((correct / classified.length) * 100) : 0;
  const threats     = all.filter((i) => i.phishml === "threat");

  const lines = [
    "KnowBe4 PhishER Simulator — Shift Report",
    `Generated: ${now()}`,
    "",
    `Accuracy Score : ${accuracy}% (${correct}/${classified.length} manually classified)`,
    `Threats Neutralized (PhishRIP/ZAP): ${neutralized}`,
    "",
    "── Threat Incidents ──────────────────────────────────"
  ];
  threats.forEach((i) => {
    lines.push(`[${i.id}] ${i.subject}`);
    lines.push(`  Status: ${i.status}   Reason: ${i.reasonCode || "none"}`);
    lines.push(`  Notes: ${i.noteDraft?.trim() || "No notes submitted."}`);
    lines.push("");
  });

  const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement("a"), { href: url, download: `shift-report-${Date.now()}.txt` });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* ═══════════════════════════════════════════════════════════════
   TOAST
═══════════════════════════════════════════════════════════════ */
function showToast(text) {
  const el = document.getElementById("toast");
  el.textContent = text;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 2200);
}

/* ═══════════════════════════════════════════════════════════════
   RENDER ALL
═══════════════════════════════════════════════════════════════ */
function renderAll() {
  renderRows();
  renderTriage();
  renderAnalytics();
  document.body.classList.toggle("high-contrast", state.highContrast);
  document.getElementById("mute-toggle").textContent = `Mute: ${state.muted ? "On" : "Off"}`;
  if (!state.tutorialSeen) document.getElementById("quickstart-modal").classList.remove("hidden");
  updateTimer();
}

/* ═══════════════════════════════════════════════════════════════
   EVENT BINDING
═══════════════════════════════════════════════════════════════ */
function bind() {
  /* Search */
  document.getElementById("search-filter").addEventListener("input", (e) => {
    state.filters.query = e.target.value; save(); renderRows();
  });

  /* View navigation */
  document.getElementById("view-inbox").addEventListener("click",     () => switchView("inbox"));
  document.getElementById("view-playbook").addEventListener("click",  () => switchView("playbook"));
  document.getElementById("view-dashboard").addEventListener("click", () => switchView("dashboard"));
  document.getElementById("view-settings").addEventListener("click",  () => switchView("settings"));

  /* Playbook CTA */
  document.getElementById("playbook-go-inbox")?.addEventListener("click", () => switchView("inbox"));

  /* PhishML Settings nav (already active, just show) */
  document.getElementById("phishml-nav-btn")?.addEventListener("click", () => {
    document.querySelectorAll(".settings-nav-item").forEach((b) => b.classList.remove("active"));
    document.getElementById("phishml-nav-btn").classList.add("active");
    renderPhishMLSettings();
  });

  /* Top controls */
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
  document.getElementById("answer-key-toggle").addEventListener("click", () => {
    answerKey = !answerKey;
    document.getElementById("answer-key-toggle").textContent = answerKey ? "Instructor Key: ON" : "Instructor Key";
    renderTriage();
  });
  document.getElementById("help-toggle").addEventListener("click", () => {
    document.getElementById("quickstart-modal").classList.remove("hidden");
  });
  document.getElementById("reset-sim").addEventListener("click", () => {
    if (!confirm("Reset the lab? This clears all saved progress.")) return;
    localStorage.removeItem(STORE);
    state       = freshState();
    selected    = state.incidents[0]?.id || null;
    answerKey   = false;
    currentView = "inbox";
    save();
    initPillFilters();
    initRooms();
    switchView("inbox");
    renderAll();
  });

  /* CSV + Refresh */
  document.getElementById("csv-download").addEventListener("click", () => downloadCSV());
  document.getElementById("refresh-btn").addEventListener("click",  () => {
    renderRows(); renderTriage(); showToast("Inbox refreshed.");
  });

  /* Shift report */
  document.getElementById("download-report").addEventListener("click", () => downloadShiftReport());

  /* Modals */
  document.getElementById("close-modal").addEventListener("click",         () => document.getElementById("phishrip-modal").classList.add("hidden"));
  document.getElementById("close-detonate-modal").addEventListener("click", () => document.getElementById("detonate-modal").classList.add("hidden"));
  document.getElementById("close-quickstart").addEventListener("click",     () => {
    state.tutorialSeen = true; save();
    document.getElementById("quickstart-modal").classList.add("hidden");
  });

  /* Save query as room */
  document.getElementById("save-room-btn").addEventListener("click", () => {
    document.getElementById("room-name-input").value = "";
    document.getElementById("save-room-modal").classList.remove("hidden");
  });
  document.getElementById("confirm-save-room").addEventListener("click", () => {
    const name = document.getElementById("room-name-input").value.trim();
    if (!name) { showToast("Enter a room name."); return; }
    const id   = `saved-${Date.now()}`;
    state.savedRooms.push({ id, name, snapshot: { ...state.filters, pills: JSON.parse(JSON.stringify(state.filterPills)) } });
    save(); renderSavedRooms();
    document.getElementById("save-room-modal").classList.add("hidden");
    showToast(`Room "${name}" saved.`);
  });
  document.getElementById("cancel-save-room").addEventListener("click", () => {
    document.getElementById("save-room-modal").classList.add("hidden");
  });

  /* Keyboard shortcuts */
  document.addEventListener("keydown", (e) => {
    const tag = e.target?.tagName;
    if (tag === "TEXTAREA" || tag === "INPUT" || tag === "SELECT" || e.target?.isContentEditable) return;
    const k = e.key.toLowerCase();
    if (k === "t") classifySelected("threat");
    if (k === "s") classifySelected("spam");
    if (k === "c") classifySelected("clean");
  });
}

/* ═══════════════════════════════════════════════════════════════
   HYDRATE (restore filter UI from saved state)
═══════════════════════════════════════════════════════════════ */
function hydrate() {
  const search = document.getElementById("search-filter");
  if (search) search.value = state.filters.query || "";
}

/* ═══════════════════════════════════════════════════════════════
   BOOT
═══════════════════════════════════════════════════════════════ */
currentView = state.currentView || "inbox";
hydrate();
bind();
initPillFilters();
initRooms();
initPlaybookTabs();
renderAll();
switchView(currentView);
shiftTimer = setInterval(updateTimer, 1000);
