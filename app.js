const scenarioPacks = {
  easy: [
    {
      id: "E-1001",
      subject: "Security awareness newsletter",
      sender: "Security Team <security@academy.local>",
      source: "User Reported",
      severity: "low",
      status: "requires_attention",
      receivedAt: "2026-05-01 09:10",
      messageId: "<easy1001@academy.local>",
      auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
      url: "https://academy.local/security-news",
      domainAgeDays: 2500,
      bodySummary: "Monthly awareness newsletter from internal team.",
      headerSnippet: "Return-Path: security@academy.local\nReceived-SPF: pass",
      timeline: ["Delivered to all staff", "No unusual click behavior"],
      groundTruth: "benign",
      actions: [],
      notes: [],
      resolvedBy: null
    },
    {
      id: "E-1002",
      subject: "Your mailbox is full - verify now",
      sender: "IT Admin <it-help@secure-mailbox-now.com>",
      source: "Defender Email",
      severity: "high",
      status: "requires_attention",
      receivedAt: "2026-05-01 09:14",
      messageId: "<easy1002@secure-mailbox-now.com>",
      auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
      url: "https://secure-mailbox-now.com/auth",
      domainAgeDays: 4,
      bodySummary: "Mailbox suspension lure with credential prompt.",
      headerSnippet: "Return-Path: it-help@secure-mailbox-now.com\nReceived-SPF: fail",
      timeline: ["Delivered to 12 users", "2 clicks in 3 minutes"],
      groundTruth: "phishing",
      actions: [],
      notes: [],
      resolvedBy: null
    }
  ],
  medium: [
    {
      id: "M-3001",
      subject: "Action required: Re-authenticate your Microsoft account",
      sender: "Microsoft Security <noreply@ms-secure-auth.com>",
      source: "Defender Email",
      severity: "critical",
      status: "requires_attention",
      receivedAt: "2026-05-01 10:11",
      messageId: "<med3001@ms-secure-auth.com>",
      auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
      url: "https://microsoft365-secure-auth.net/session",
      domainAgeDays: 3,
      bodySummary: "User told account will be disabled in 30 minutes unless they sign in.",
      headerSnippet: "Return-Path: security@ms-secure-auth.com\nX-Originating-IP: 185.33.17.20\nReceived-SPF: fail",
      timeline: ["Delivered to 17 inboxes", "2 users clicked", "1 user submitted credentials"],
      groundTruth: "phishing",
      actions: [],
      notes: [],
      resolvedBy: null
    },
    {
      id: "M-3002",
      subject: "IT Maintenance Window Notification",
      sender: "IT Operations <itops@academy.local>",
      source: "Reported by user",
      severity: "low",
      status: "requires_attention",
      receivedAt: "2026-05-01 10:00",
      messageId: "<med3002@academy.local>",
      auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
      url: "https://status.academy.local",
      domainAgeDays: 3200,
      bodySummary: "Maintenance notification and expected downtime.",
      headerSnippet: "Return-Path: itops@academy.local\nX-Originating-IP: 10.10.2.12\nReceived-SPF: pass",
      timeline: ["Delivered to all staff", "No suspicious click pattern"],
      groundTruth: "benign",
      actions: [],
      notes: [],
      resolvedBy: null
    },
    {
      id: "M-3003",
      subject: "Invoice overdue - immediate payment required",
      sender: "Finance Desk <billing@pay-support-now.com>",
      source: "Defender Email",
      severity: "high",
      status: "requires_attention",
      receivedAt: "2026-05-01 10:22",
      messageId: "<med3003@pay-support-now.com>",
      auth: { spf: "softfail", dkim: "fail", dmarc: "fail" },
      url: "https://shared-invoice-docs.net/open",
      domainAgeDays: 1,
      bodySummary: "Invoice lure containing suspicious payment link.",
      headerSnippet: "Return-Path: billing@pay-support-now.com\nX-Originating-IP: 91.204.12.9\nReceived-SPF: softfail",
      timeline: ["Delivered to finance list", "Attachment downloaded 3 times"],
      groundTruth: "phishing",
      actions: [],
      notes: [],
      resolvedBy: null
    }
  ],
  hard: [
    {
      id: "H-5001",
      subject: "MFA registration issue - manual fix needed",
      sender: "Identity Desk <identity@corp-security.help>",
      source: "Defender Email",
      severity: "high",
      status: "requires_attention",
      receivedAt: "2026-05-01 11:03",
      messageId: "<hard5001@corp-security.help>",
      auth: { spf: "pass", dkim: "fail", dmarc: "fail" },
      url: "https://sso-check-security.help/recover",
      domainAgeDays: 16,
      bodySummary: "Looks internal, but asks to validate MFA seed with external form.",
      headerSnippet: "Return-Path: identity@corp-security.help\nReceived-SPF: pass\nDKIM-Signature: missing",
      timeline: ["Delivered to 9 privileged users", "1 click within 1 minute"],
      groundTruth: "phishing",
      actions: [],
      notes: [],
      resolvedBy: null
    },
    {
      id: "H-5002",
      subject: "SharePoint file access request",
      sender: "Collab Bot <no-reply@sharepointonline.com>",
      source: "User Reported",
      severity: "medium",
      status: "requires_attention",
      receivedAt: "2026-05-01 11:07",
      messageId: "<hard5002@sharepointonline.com>",
      auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
      url: "https://tenant.sharepoint.com/sites/finance",
      domainAgeDays: 5000,
      bodySummary: "Legitimate sharing workflow from Microsoft tenant.",
      headerSnippet: "Return-Path: no-reply@sharepointonline.com\nReceived-SPF: pass",
      timeline: ["Single recipient", "User uncertain and reported proactively"],
      groundTruth: "benign",
      actions: [],
      notes: [],
      resolvedBy: null
    },
    {
      id: "H-5003",
      subject: "Payroll adjustment confirmation",
      sender: "HR Service <hr@academy-payroll.co>",
      source: "Defender Email",
      severity: "critical",
      status: "requires_attention",
      receivedAt: "2026-05-01 11:19",
      messageId: "<hard5003@academy-payroll.co>",
      auth: { spf: "neutral", dkim: "fail", dmarc: "fail" },
      url: "https://academy-payroll.co/portal/login",
      domainAgeDays: 8,
      bodySummary: "Well-crafted BEC lure with realistic tone and payment urgency.",
      headerSnippet: "Return-Path: hr@academy-payroll.co\nReceived-SPF: neutral",
      timeline: ["Delivered to payroll + HR", "3 clicks", "1 credential submission"],
      groundTruth: "phishing",
      actions: [],
      notes: [],
      resolvedBy: null
    },
    {
      id: "H-5004",
      subject: "Vendor renewal contract draft",
      sender: "Legal Team <legal@academy.local>",
      source: "Mailflow",
      severity: "low",
      status: "requires_attention",
      receivedAt: "2026-05-01 11:25",
      messageId: "<hard5004@academy.local>",
      auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
      url: "https://docusign.com/session/contract",
      domainAgeDays: 9000,
      bodySummary: "Legitimate legal workflow with approved external signing platform.",
      headerSnippet: "Return-Path: legal@academy.local\nReceived-SPF: pass",
      timeline: ["Delivered to procurement", "No suspicious indicators"],
      groundTruth: "benign",
      actions: [],
      notes: [],
      resolvedBy: null
    }
  ]
};

const defaultState = {
  activePack: "medium",
  incidents: structuredClone(scenarioPacks.medium),
  templates: [
    { id: "TPL-1", name: "M365 Security Alert", category: "Credential Harvest", difficulty: "High" },
    { id: "TPL-2", name: "Invoice Payment Reminder", category: "Business Email Compromise", difficulty: "Medium" },
    { id: "TPL-3", name: "HR Policy Update", category: "Awareness Control", difficulty: "Low" }
  ],
  landingPages: [
    { id: "LP-1", name: "Microsoft Login Clone", capture: true, redirect: "https://office.com" },
    { id: "LP-2", name: "Finance Portal Clone", capture: true, redirect: "https://quickbooks.intuit.com" }
  ],
  groups: [
    { id: "GRP-1", name: "SOC Class A", users: 14 },
    { id: "GRP-2", name: "SOC Class B", users: 12 }
  ],
  campaigns: [
    { id: "CMP-9001", name: "Week 2: Password Expiry Drill", template: "M365 Security Alert", group: "SOC Class A", status: "Completed", results: "Sent 14 / Open 12 / Click 7 / Submit 3" }
  ],
  scorecards: {}
};

let state = loadState();
let activeUser = loadActiveUser();
let selectedIncidentId = null;

function loadState() {
  const raw = localStorage.getItem("kb4sim-phase2-state");
  if (!raw) return structuredClone(defaultState);
  try { return JSON.parse(raw); } catch { return structuredClone(defaultState); }
}

function saveState() {
  localStorage.setItem("kb4sim-phase2-state", JSON.stringify(state));
}

function loadActiveUser() {
  const raw = localStorage.getItem("kb4sim-active-user");
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function saveActiveUser() {
  if (!activeUser) {
    localStorage.removeItem("kb4sim-active-user");
    return;
  }
  localStorage.setItem("kb4sim-active-user", JSON.stringify(activeUser));
}

function now() {
  return new Date().toLocaleString();
}

function scoreIncident(incident) {
  let score = 0;
  if (incident.auth.spf !== "pass") score += 20;
  if (incident.auth.dkim !== "pass") score += 20;
  if (incident.auth.dmarc !== "pass") score += 20;
  if (incident.domainAgeDays <= 30) score += 20;
  if (/urgent|disable|payment|required|verify/i.test(incident.subject)) score += 20;
  return Math.min(score, 100);
}

function normalizeStatus(status) {
  return status.replaceAll("_", " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function upsertScorecard(userName, role) {
  if (!state.scorecards[userName]) {
    state.scorecards[userName] = { role, score: 0, resolved: 0, correctVerdicts: 0, containmentActions: 0, notesAdded: 0, beginWorkCount: 0 };
  } else {
    state.scorecards[userName].role = role;
  }
}

function applyPoints(action, incident) {
  if (!activeUser) return;
  upsertScorecard(activeUser.name, activeUser.role);
  const board = state.scorecards[activeUser.name];
  if (action === "begin") {
    board.score += 5;
    board.beginWorkCount += 1;
  }
  if (action === "benign" || action === "resolve") {
    board.resolved += 1;
    const correct = (action === "benign" && incident.groundTruth === "benign") || (action === "resolve" && incident.groundTruth === "phishing");
    if (correct) {
      board.score += 40;
      board.correctVerdicts += 1;
    } else {
      board.score = Math.max(0, board.score - 15);
    }
  }
  if (action === "quarantine" || action === "block_domain" || action === "zap") {
    if (incident.groundTruth === "phishing") board.score += 15;
    else board.score = Math.max(0, board.score - 10);
    board.containmentActions += 1;
  }
}

function setAppVisibility() {
  const login = document.getElementById("login-screen");
  const app = document.getElementById("app-root");
  if (activeUser) {
    login.classList.add("hidden");
    app.classList.remove("hidden");
    document.getElementById("active-user-pill").textContent = `${activeUser.role.toUpperCase()}: ${activeUser.name}`;
  } else {
    login.classList.remove("hidden");
    app.classList.add("hidden");
  }
}

function renderMetrics() {
  const total = state.incidents.length;
  const open = state.incidents.filter((i) => i.status !== "resolved").length;
  const resolved = state.incidents.filter((i) => i.status === "resolved").length;
  const analyst = activeUser ? state.scorecards[activeUser.name] : null;
  const myScore = analyst ? analyst.score : 0;
  const cards = [["Scenario Pack", state.activePack.toUpperCase()], ["Incidents", total], ["Resolved", resolved], ["My Score", myScore], ["Open Queue", open]];
  document.getElementById("metric-cards").innerHTML = cards.map(([t, v]) => `<div class="card"><h4>${t}</h4><p>${v}</p></div>`).join("");
}

function incidentMatches(incident) {
  const status = document.getElementById("filter-status").value;
  const sev = document.getElementById("filter-severity").value;
  const q = document.getElementById("filter-search").value.trim().toLowerCase();
  const okStatus = status === "all" || incident.status === status;
  const okSev = sev === "all" || incident.severity === sev;
  const hay = `${incident.id} ${incident.subject} ${incident.sender} ${incident.url}`.toLowerCase();
  return okStatus && okSev && (!q || hay.includes(q));
}

function renderIncidentTable() {
  const rows = state.incidents.filter(incidentMatches);
  document.getElementById("incident-table").innerHTML = rows.map((i) => `
    <tr data-id="${i.id}">
      <td><strong>${i.id}</strong><br>${i.subject}</td>
      <td class="sev-${i.severity}">${i.severity.toUpperCase()}</td>
      <td><span class="status-pill status-${i.status}">${normalizeStatus(i.status)}</span></td>
      <td>${i.source}</td>
      <td>${i.receivedAt}</td>
    </tr>
  `).join("");
  document.querySelectorAll("#incident-table tr").forEach((row) => row.addEventListener("click", () => {
    selectedIncidentId = row.dataset.id;
    renderIncidentDetail();
  }));
}

function authClass(v) {
  return v === "pass" ? "auth-pass" : "auth-fail";
}

function renderIncidentDetail() {
  const panel = document.getElementById("incident-detail");
  const incident = state.incidents.find((x) => x.id === selectedIncidentId);
  if (!incident) {
    panel.innerHTML = "<h3>Select an incident</h3><p>Open an incident from the queue.</p>";
    return;
  }
  const score = scoreIncident(incident);
  panel.innerHTML = `
    <h3>${incident.id} - ${incident.subject}</h3>
    <p><strong>Sender:</strong> ${incident.sender}</p>
    <p><strong>Message-ID:</strong> <span class="mono">${incident.messageId}</span></p>
    <p><strong>Body Summary:</strong> ${incident.bodySummary}</p>
    <div class="evidence-grid">
      <div class="evidence-item">
        SPF: <span class="${authClass(incident.auth.spf)}">${incident.auth.spf}</span><br>
        DKIM: <span class="${authClass(incident.auth.dkim)}">${incident.auth.dkim}</span><br>
        DMARC: <span class="${authClass(incident.auth.dmarc)}">${incident.auth.dmarc}</span>
      </div>
      <div class="evidence-item">URL: ${incident.url}<br>Domain age: ${incident.domainAgeDays} day(s)<br>Risk score: <strong>${score}/100</strong></div>
      <div class="evidence-item"><pre class="mono">${incident.headerSnippet}</pre></div>
      <div class="evidence-item"><ul>${incident.timeline.map((t) => `<li>${t}</li>`).join("")}</ul></div>
    </div>
    <div class="action-row">
      <button class="primary" data-action="begin">Begin Work</button>
      <button data-action="benign">Mark Benign</button>
      <button data-action="quarantine">Quarantine</button>
      <button data-action="block_domain">Block Domain</button>
      <button class="danger" data-action="zap">Run ZAP</button>
      <button data-action="escalate">Escalate Tier 2</button>
      <button class="primary" data-action="resolve">Resolve</button>
    </div>
    <label>Investigation Note<textarea id="incident-note" class="note-box" placeholder="Include indicators and final rationale."></textarea></label>
    <button id="save-note">Save Note</button>
    <h4>Action Log</h4><ul>${incident.actions.map((a) => `<li>${a.ts} - ${a.text}</li>`).join("") || "<li>No actions yet</li>"}</ul>
    <h4>Notes</h4><ul>${incident.notes.map((n) => `<li>${n.ts} - ${n.text}</li>`).join("") || "<li>No notes yet</li>"}</ul>
  `;
  panel.querySelectorAll("[data-action]").forEach((btn) => btn.addEventListener("click", () => runAction(incident.id, btn.dataset.action)));
  panel.querySelector("#save-note").addEventListener("click", () => {
    const text = panel.querySelector("#incident-note").value.trim();
    if (!text || !activeUser) return;
    mutateIncident(incident.id, (item) => {
      item.notes.push({ ts: now(), text, by: activeUser.name });
      return item;
    });
    upsertScorecard(activeUser.name, activeUser.role);
    state.scorecards[activeUser.name].score += 10;
    state.scorecards[activeUser.name].notesAdded += 1;
    saveState();
    renderAll();
  });
}

function mutateIncident(id, updater) {
  state.incidents = state.incidents.map((item) => {
    if (item.id !== id) return item;
    const copy = { ...item, actions: [...item.actions], notes: [...item.notes], timeline: [...item.timeline] };
    return updater(copy);
  });
}

function runAction(id, action) {
  if (!activeUser) return;
  const actionMap = {
    begin: { text: "Analyst started ticket ownership.", status: "in_progress" },
    benign: { text: "Marked as benign and closed.", status: "resolved" },
    quarantine: { text: "Email quarantined from mailbox(es).", status: "in_progress" },
    block_domain: { text: "Sender domain blocked at tenant level.", status: "in_progress" },
    zap: { text: "ZAP executed organization-wide.", status: "in_progress" },
    escalate: { text: "Escalated to Tier 2 with evidence pack.", status: "in_progress" },
    resolve: { text: "Incident resolved and closed.", status: "resolved" }
  };
  const meta = actionMap[action];
  if (!meta) return;
  const incident = state.incidents.find((x) => x.id === id);
  if (!incident) return;
  mutateIncident(id, (item) => {
    item.actions.push({ ts: now(), text: meta.text, by: activeUser.name });
    item.status = meta.status;
    if (meta.status === "resolved") item.resolvedBy = activeUser.name;
    return item;
  });
  applyPoints(action, incident);
  saveState();
  renderAll();
}

function renderScoreboard() {
  const entries = Object.entries(state.scorecards).map(([name, s]) => ({
    name,
    role: s.role,
    score: s.score,
    resolved: s.resolved,
    accuracy: s.resolved ? Math.round((s.correctVerdicts / s.resolved) * 100) : 0
  })).sort((a, b) => b.score - a.score);
  document.getElementById("scoreboard-table").innerHTML = entries.map((e) => `
    <tr><td>${e.name}</td><td>${e.role}</td><td>${e.score}</td><td>${e.resolved}</td><td>${e.accuracy}%</td></tr>
  `).join("") || "<tr><td colspan='5'>No student activity yet.</td></tr>";
}

function renderCampaigns() {
  document.getElementById("campaign-template").innerHTML = state.templates.map((t) => `<option>${t.name}</option>`).join("");
  document.getElementById("campaign-landing").innerHTML = state.landingPages.map((p) => `<option>${p.name}</option>`).join("");
  document.getElementById("campaign-group").innerHTML = state.groups.map((g) => `<option>${g.name}</option>`).join("");
  document.getElementById("campaign-table").innerHTML = state.campaigns.map((c) => `<tr><td>${c.name}</td><td>${c.template}</td><td>${c.group}</td><td>${c.status}</td><td>${c.results}</td></tr>`).join("");
}

function renderLists() {
  document.getElementById("template-list").innerHTML = state.templates.map((t) => `<div class="list-item"><strong>${t.id}</strong> - ${t.name}<br>${t.category} | Difficulty ${t.difficulty}</div>`).join("");
  document.getElementById("landing-list").innerHTML = state.landingPages.map((p) => `<div class="list-item"><strong>${p.id}</strong> - ${p.name}<br>Capture: ${p.capture ? "Enabled" : "Disabled"} | Redirect: ${p.redirect}</div>`).join("");
  document.getElementById("group-list").innerHTML = state.groups.map((g) => `<div class="list-item"><strong>${g.id}</strong> - ${g.name}<br>Users: ${g.users}</div>`).join("");
}

function loadScenarioPack(packName) {
  const set = scenarioPacks[packName];
  if (!set) return;
  state.activePack = packName;
  state.incidents = structuredClone(set);
  selectedIncidentId = null;
  saveState();
  renderAll();
}

function exportReportCsv() {
  const rows = [["Incident ID", "Subject", "Status", "Severity", "Ground Truth", "Resolved By", "Action Count", "Note Count"]];
  state.incidents.forEach((i) => {
    rows.push([i.id, i.subject, i.status, i.severity, i.groundTruth, i.resolvedBy || "", String(i.actions.length), String(i.notes.length)]);
  });
  const csv = rows.map((r) => r.map((v) => `"${String(v).replaceAll('"', '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `phishing-sim-report-${state.activePack}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function bindNav() {
  document.querySelectorAll(".nav-link").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-link").forEach((n) => n.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      document.getElementById(btn.dataset.view).classList.add("active");
      document.getElementById("view-title").textContent = btn.textContent;
    });
  });
}

function bindInputs() {
  document.getElementById("filter-status").addEventListener("change", renderIncidentTable);
  document.getElementById("filter-severity").addEventListener("change", renderIncidentTable);
  document.getElementById("filter-search").addEventListener("input", renderIncidentTable);

  document.getElementById("campaign-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const name = document.getElementById("campaign-name").value.trim();
    if (!name) return;
    const template = document.getElementById("campaign-template").value;
    const group = document.getElementById("campaign-group").value;
    const sent = Math.floor(Math.random() * 12) + 8;
    const open = Math.floor(sent * (0.5 + Math.random() * 0.4));
    const click = Math.floor(open * (0.3 + Math.random() * 0.4));
    const submit = Math.floor(click * (0.2 + Math.random() * 0.5));
    state.campaigns.unshift({ id: `CMP-${Math.floor(Math.random() * 9000) + 1000}`, name, template, group, status: "Launched", results: `Sent ${sent} / Open ${open} / Click ${click} / Submit ${submit}` });
    document.getElementById("campaign-name").value = "";
    saveState();
    renderCampaigns();
  });

  document.getElementById("reset-lab").addEventListener("click", () => {
    state = structuredClone(defaultState);
    if (activeUser) upsertScorecard(activeUser.name, activeUser.role);
    selectedIncidentId = null;
    saveState();
    renderAll();
  });

  document.getElementById("load-pack").addEventListener("click", () => loadScenarioPack(document.getElementById("scenario-pack").value));
  document.getElementById("export-report").addEventListener("click", exportReportCsv);
  document.getElementById("logout-btn").addEventListener("click", () => {
    activeUser = null;
    saveActiveUser();
    setAppVisibility();
  });

  document.getElementById("login-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const name = document.getElementById("login-name").value.trim();
    const role = document.getElementById("login-role").value;
    if (!name) return;
    activeUser = { name, role };
    upsertScorecard(name, role);
    saveActiveUser();
    saveState();
    setAppVisibility();
    renderAll();
  });
}

function renderAll() {
  document.getElementById("scenario-pack").value = state.activePack;
  renderMetrics();
  renderIncidentTable();
  renderIncidentDetail();
  renderScoreboard();
  renderCampaigns();
  renderLists();
}

bindNav();
bindInputs();
setAppVisibility();
if (activeUser) renderAll();
