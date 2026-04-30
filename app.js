const scenarioPacks = {
  easy: [
    { id: "E-1001", subject: "Security awareness newsletter", sender: "Security Team <security@academy.local>", source: "User Reported", severity: "low", status: "requires_attention", receivedAt: "2026-05-01 09:10", messageId: "<easy1001@academy.local>", auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, url: "https://academy.local/security-news", domainAgeDays: 2500, bodySummary: "Monthly awareness newsletter from internal team.", headerSnippet: "Return-Path: security@academy.local\nReceived-SPF: pass", timeline: ["Delivered to all staff"], groundTruth: "benign", actions: [], notes: [], resolvedBy: null },
    { id: "E-1002", subject: "Your mailbox is full - verify now", sender: "IT Admin <it-help@secure-mailbox-now.com>", source: "Defender Email", severity: "high", status: "requires_attention", receivedAt: "2026-05-01 09:14", messageId: "<easy1002@secure-mailbox-now.com>", auth: { spf: "fail", dkim: "fail", dmarc: "fail" }, url: "https://secure-mailbox-now.com/auth", domainAgeDays: 4, bodySummary: "Mailbox suspension lure with credential prompt.", headerSnippet: "Return-Path: it-help@secure-mailbox-now.com\nReceived-SPF: fail", timeline: ["Delivered to 12 users"], groundTruth: "phishing", actions: [], notes: [], resolvedBy: null }
  ],
  medium: [
    { id: "M-3001", subject: "Action required: Re-authenticate your Microsoft account", sender: "Microsoft Security <noreply@ms-secure-auth.com>", source: "Defender Email", severity: "critical", status: "requires_attention", receivedAt: "2026-05-01 10:11", messageId: "<med3001@ms-secure-auth.com>", auth: { spf: "fail", dkim: "fail", dmarc: "fail" }, url: "https://microsoft365-secure-auth.net/session", domainAgeDays: 3, bodySummary: "User told account will be disabled in 30 minutes unless they sign in.", headerSnippet: "Return-Path: security@ms-secure-auth.com\nReceived-SPF: fail", timeline: ["Delivered to 17 inboxes", "1 credential submission"], groundTruth: "phishing", actions: [], notes: [], resolvedBy: null },
    { id: "M-3002", subject: "IT Maintenance Window Notification", sender: "IT Operations <itops@academy.local>", source: "Reported by user", severity: "low", status: "requires_attention", receivedAt: "2026-05-01 10:00", messageId: "<med3002@academy.local>", auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, url: "https://status.academy.local", domainAgeDays: 3200, bodySummary: "Maintenance notification.", headerSnippet: "Return-Path: itops@academy.local\nReceived-SPF: pass", timeline: ["No suspicious click pattern"], groundTruth: "benign", actions: [], notes: [], resolvedBy: null },
    { id: "M-3003", subject: "Invoice overdue - immediate payment required", sender: "Finance Desk <billing@pay-support-now.com>", source: "Defender Email", severity: "high", status: "requires_attention", receivedAt: "2026-05-01 10:22", messageId: "<med3003@pay-support-now.com>", auth: { spf: "softfail", dkim: "fail", dmarc: "fail" }, url: "https://shared-invoice-docs.net/open", domainAgeDays: 1, bodySummary: "Invoice lure containing suspicious payment link.", headerSnippet: "Return-Path: billing@pay-support-now.com\nReceived-SPF: softfail", timeline: ["Delivered to finance list"], groundTruth: "phishing", actions: [], notes: [], resolvedBy: null }
  ],
  hard: [
    { id: "H-5001", subject: "MFA registration issue - manual fix needed", sender: "Identity Desk <identity@corp-security.help>", source: "Defender Email", severity: "high", status: "requires_attention", receivedAt: "2026-05-01 11:03", messageId: "<hard5001@corp-security.help>", auth: { spf: "pass", dkim: "fail", dmarc: "fail" }, url: "https://sso-check-security.help/recover", domainAgeDays: 16, bodySummary: "Looks internal, but asks to validate MFA seed externally.", headerSnippet: "Return-Path: identity@corp-security.help\nDKIM-Signature: missing", timeline: ["Delivered to 9 privileged users"], groundTruth: "phishing", actions: [], notes: [], resolvedBy: null },
    { id: "H-5002", subject: "SharePoint file access request", sender: "Collab Bot <no-reply@sharepointonline.com>", source: "User Reported", severity: "medium", status: "requires_attention", receivedAt: "2026-05-01 11:07", messageId: "<hard5002@sharepointonline.com>", auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, url: "https://tenant.sharepoint.com/sites/finance", domainAgeDays: 5000, bodySummary: "Legitimate sharing workflow.", headerSnippet: "Return-Path: no-reply@sharepointonline.com\nReceived-SPF: pass", timeline: ["Single recipient"], groundTruth: "benign", actions: [], notes: [], resolvedBy: null },
    { id: "H-5003", subject: "Payroll adjustment confirmation", sender: "HR Service <hr@academy-payroll.co>", source: "Defender Email", severity: "critical", status: "requires_attention", receivedAt: "2026-05-01 11:19", messageId: "<hard5003@academy-payroll.co>", auth: { spf: "neutral", dkim: "fail", dmarc: "fail" }, url: "https://academy-payroll.co/portal/login", domainAgeDays: 8, bodySummary: "Well-crafted BEC lure with urgency.", headerSnippet: "Return-Path: hr@academy-payroll.co\nReceived-SPF: neutral", timeline: ["3 clicks", "1 credential submission"], groundTruth: "phishing", actions: [], notes: [], resolvedBy: null },
    { id: "H-5004", subject: "Vendor renewal contract draft", sender: "Legal Team <legal@academy.local>", source: "Mailflow", severity: "low", status: "requires_attention", receivedAt: "2026-05-01 11:25", messageId: "<hard5004@academy.local>", auth: { spf: "pass", dkim: "pass", dmarc: "pass" }, url: "https://docusign.com/session/contract", domainAgeDays: 9000, bodySummary: "Legitimate legal workflow.", headerSnippet: "Return-Path: legal@academy.local\nReceived-SPF: pass", timeline: ["No suspicious indicators"], groundTruth: "benign", actions: [], notes: [], resolvedBy: null }
  ]
};

const defaultState = {
  activePack: "medium",
  incidents: structuredClone(scenarioPacks.medium),
  templates: [{ id: "TPL-1", name: "M365 Security Alert", category: "Credential Harvest", difficulty: "High" }],
  landingPages: [{ id: "LP-1", name: "Microsoft Login Clone", capture: true, redirect: "https://office.com" }],
  groups: [{ id: "GRP-1", name: "SOC Class A", users: 14 }],
  campaigns: [{ id: "CMP-9001", name: "Week 2 Drill", template: "M365 Security Alert", group: "SOC Class A", status: "Completed", results: "Sent 14 / Open 12 / Click 7 / Submit 3" }],
  scorecards: {},
  sections: ["Section A", "Section B", "Section C"],
  exam: { active: false, startedAt: null, endsAt: null, submittedUsers: [], gradesReleased: false },
  attempts: []
};

let state = loadState();
let activeUser = loadActiveUser();
let selectedIncidentId = null;
let examTimerInterval = null;

function normalizeIncident(raw, idx) {
  const phishing = raw.groundTruth === "phishing";
  return {
    ...raw,
    reporter: raw.reporter || `user${idx + 1}@academy.local`,
    phishml: raw.phishml || (phishing ? "threat" : "clean"),
    priority: raw.priority || raw.severity || (phishing ? "high" : "low"),
    attachments: raw.attachments || (phishing ? ["invoice.docm"] : ["policy.pdf"]),
    links: raw.links || [raw.url],
    tags: raw.tags || [],
    assignee: raw.assignee || null,
    discussion: raw.discussion || []
  };
}

function normalizeState() {
  state.incidents = (state.incidents || []).map(normalizeIncident);
}

function loadState() {
  try {
    const parsed = JSON.parse(localStorage.getItem("kb4sim-phase3-state")) || structuredClone(defaultState);
    parsed.exam = parsed.exam || {};
    if (typeof parsed.exam.gradesReleased !== "boolean") parsed.exam.gradesReleased = false;
    parsed.attempts = parsed.attempts || [];
    parsed.incidents = (parsed.incidents || []).map(normalizeIncident);
    return parsed;
  } catch {
    return structuredClone(defaultState);
  }
}
function saveState() { localStorage.setItem("kb4sim-phase3-state", JSON.stringify(state)); }
function loadActiveUser() { try { return JSON.parse(localStorage.getItem("kb4sim-active-user")) || null; } catch { return null; } }
function saveActiveUser() { if (!activeUser) localStorage.removeItem("kb4sim-active-user"); else localStorage.setItem("kb4sim-active-user", JSON.stringify(activeUser)); }
function now() { return new Date().toLocaleString(); }
function isInstructor() { return activeUser?.role === "instructor"; }
function examSubmitted() { return !!activeUser && state.exam.submittedUsers.includes(activeUser.name); }
function examLocked() { return !!activeUser && state.exam.active && activeUser.role === "student" && examSubmitted(); }
function inExamForStudent() { return !!activeUser && state.exam.active && activeUser.role === "student"; }

function scoreIncident(incident) {
  let score = 0;
  if (incident.auth.spf !== "pass") score += 20;
  if (incident.auth.dkim !== "pass") score += 20;
  if (incident.auth.dmarc !== "pass") score += 20;
  if (incident.domainAgeDays <= 30) score += 20;
  if (/urgent|payment|required|verify|disable/i.test(incident.subject)) score += 20;
  return Math.min(score, 100);
}

function upsertScorecard(name, role, section = "Section A") {
  if (!state.scorecards[name]) state.scorecards[name] = { role, section, score: 0, resolved: 0, correctVerdicts: 0, notesAdded: 0, containmentActions: 0, beginWorkCount: 0 };
  if (state.scorecards[name] && !state.scorecards[name].section) state.scorecards[name].section = section;
}

function applyPoints(action, incident) {
  if (!activeUser) return;
  upsertScorecard(activeUser.name, activeUser.role, activeUser.section || "Section A");
  const s = state.scorecards[activeUser.name];
  if (action === "begin") { s.score += 5; s.beginWorkCount += 1; }
  if (["quarantine", "block_domain", "zap"].includes(action)) { s.containmentActions += 1; s.score += incident.groundTruth === "phishing" ? 15 : -10; }
  if (action === "benign" || action === "resolve") {
    s.resolved += 1;
    const ok = (action === "benign" && incident.groundTruth === "benign") || (action === "resolve" && incident.groundTruth === "phishing");
    if (ok) { s.correctVerdicts += 1; s.score += 40; } else s.score = Math.max(0, s.score - 15);
  }
}

function setAppVisibility() {
  document.getElementById("login-screen").classList.toggle("hidden", !!activeUser);
  document.getElementById("app-root").classList.toggle("hidden", !activeUser);
  if (!activeUser) return;
  document.getElementById("active-user-pill").textContent = `${activeUser.role.toUpperCase()}: ${activeUser.name} (${activeUser.section || "Section A"})`;
  document.querySelector('[data-view="answer-key"]').classList.toggle("hidden", !isInstructor());
}

function renderMetrics() {
  const my = activeUser ? state.scorecards[activeUser.name] : null;
  const cards = [["Pack", state.activePack.toUpperCase()], ["Incidents", state.incidents.length], ["Resolved", state.incidents.filter((i) => i.status === "resolved").length], ["My Score", my ? my.score : 0], ["Exam", state.exam.active ? "Running" : "Off"]];
  document.getElementById("metric-cards").innerHTML = cards.map(([t, v]) => `<div class="card"><h4>${t}</h4><p>${v}</p></div>`).join("");
}

function incidentMatches(i) {
  const phishml = document.getElementById("filter-phishml").value;
  const priority = document.getElementById("filter-priority").value;
  const st = document.getElementById("filter-status").value;
  const sev = document.getElementById("filter-severity").value;
  const q = document.getElementById("filter-search").value.trim().toLowerCase();
  const ok = (st === "all" || i.status === st) &&
    (sev === "all" || i.severity === sev) &&
    (phishml === "all" || i.phishml === phishml) &&
    (priority === "all" || i.priority === priority);
  return ok && (!q || `${i.id} ${i.subject} ${i.sender} ${i.reporter} ${i.url}`.toLowerCase().includes(q));
}

function renderIncidentTable() {
  document.getElementById("incident-table").innerHTML = state.incidents.filter(incidentMatches).map((i) => `
    <tr data-id="${i.id}">
      <td>${i.reporter}</td>
      <td><strong>${i.subject}</strong><br><span class="muted">${i.sender}</span></td>
      <td><span class="phishml-badge phishml-${i.phishml}">${i.phishml.toUpperCase()}</span></td>
      <td class="sev-${i.priority}">${i.priority.toUpperCase()}</td>
      <td><span class="status-pill status-${i.status}">${i.status.replaceAll("_", " ")}</span></td>
      <td>${i.receivedAt}</td>
    </tr>`).join("");
  document.querySelectorAll("#incident-table tr").forEach((r) => r.addEventListener("click", () => { selectedIncidentId = r.dataset.id; renderIncidentDetail(); }));
}

function renderIncidentDetail() {
  const panel = document.getElementById("incident-detail");
  const i = state.incidents.find((x) => x.id === selectedIncidentId);
  if (!i) { panel.innerHTML = "<h3>Select an incident</h3>"; return; }
  const hideAnswers = inExamForStudent();
  const locked = examLocked();
  panel.innerHTML = `
    <h3>${i.subject}</h3>
    <p><strong>Reporter:</strong> ${i.reporter} | <strong>Source:</strong> ${i.source}</p>
    <div class="detail-two-col">
      <div>
        <div class="tabs">
          <button class="tab-btn active" data-tab="body">Body</button>
          <button class="tab-btn" data-tab="headers">Headers</button>
          <button class="tab-btn" data-tab="auth">Auth</button>
          <button class="tab-btn" data-tab="attachments">Attachments</button>
        </div>
        <div id="tab-body" class="tab-panel active"><p>${i.bodySummary}</p><p><strong>Links:</strong> ${i.links.map((l) => `<span class="mono">${l}</span>`).join("<br>")}</p></div>
        <div id="tab-headers" class="tab-panel"><pre class="mono">${i.headerSnippet}</pre><p><strong>From:</strong> ${i.sender}<br><strong>Reply-To:</strong> ${i.sender.split("<")[1]?.replace(">", "") || i.sender}</p></div>
        <div id="tab-auth" class="tab-panel"><p>SPF: ${i.auth.spf}<br>DKIM: ${i.auth.dkim}<br>DMARC: ${i.auth.dmarc}<br>Risk: ${hideAnswers ? "Hidden in exam mode" : `${scoreIncident(i)}/100`}</p></div>
        <div id="tab-attachments" class="tab-panel"><ul>${i.attachments.map((a) => `<li>${a}</li>`).join("")}</ul></div>
      </div>
      <div>
        <p><strong>Assignee:</strong> ${i.assignee || "Unassigned"}</p>
        <div class="action-row">
          <button data-action="assign" ${locked ? "disabled" : ""}>Assign</button>
          <button data-action="begin" ${locked ? "disabled" : ""}>In Review</button>
          <button data-action="phishrip" ${locked ? "disabled" : ""}>PhishRIP</button>
          <button data-action="block_domain" ${locked ? "disabled" : ""}>Blocklist</button>
          <button data-action="phishflip" ${locked ? "disabled" : ""}>PhishFlip</button>
          <button data-action="quarantine" ${locked ? "disabled" : ""}>Quarantine</button>
          <button data-action="resolve" class="primary" ${locked ? "disabled" : ""}>Resolve</button>
          <button data-action="benign" ${locked ? "disabled" : ""}>Mark Clean</button>
        </div>
        <label>Add Tag<input id="incident-tag-input" placeholder="e.g. Credential Harvesting" ${locked ? "disabled" : ""} /></label>
        <button id="add-tag-btn" ${locked ? "disabled" : ""}>Add Tag</button>
        <p><strong>Tags:</strong> ${(i.tags || []).join(", ") || "None"}</p>
        <label>Discussion<textarea id="incident-note" class="note-box" ${locked ? "disabled" : ""}></textarea></label>
        <button id="save-note" ${locked ? "disabled" : ""}>Post Comment</button>
      </div>
    </div>
    <h4>Action Log</h4><ul>${i.actions.map((a) => `<li>${a.ts} - ${a.text} (${a.by || "n/a"})</li>`).join("") || "<li>No actions yet</li>"}</ul>
    <h4>Discussion</h4><ul>${i.notes.map((n) => `<li>${n.ts} - ${n.text} (${n.by || "n/a"})</li>`).join("") || "<li>No comments yet</li>"}</ul>
  `;
  panel.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      panel.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      panel.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      panel.querySelector(`#tab-${btn.dataset.tab}`).classList.add("active");
    });
  });
  panel.querySelectorAll("[data-action]").forEach((b) => b.addEventListener("click", () => runAction(i.id, b.dataset.action)));
  const addTagBtn = panel.querySelector("#add-tag-btn");
  if (addTagBtn) {
    addTagBtn.addEventListener("click", () => {
      const val = panel.querySelector("#incident-tag-input").value.trim();
      if (!val || !activeUser || examLocked()) return;
      mutateIncident(i.id, (x) => {
        x.tags = x.tags || [];
        if (!x.tags.includes(val)) x.tags.push(val);
        return x;
      });
      saveState();
      renderAll();
    });
  }
  panel.querySelector("#save-note").addEventListener("click", () => {
    if (!activeUser || examLocked()) return;
    const text = panel.querySelector("#incident-note").value.trim();
    if (!text) return;
    mutateIncident(i.id, (x) => { x.notes.push({ ts: now(), text, by: activeUser.name }); return x; });
    upsertScorecard(activeUser.name, activeUser.role, activeUser.section || "Section A");
    state.scorecards[activeUser.name].score += 10;
    state.scorecards[activeUser.name].notesAdded += 1;
    saveState();
    renderAll();
  });
}

function mutateIncident(id, fn) { state.incidents = state.incidents.map((i) => (i.id === id ? fn({ ...i, actions: [...i.actions], notes: [...i.notes], timeline: [...i.timeline] }) : i)); }

function runAction(id, action) {
  if (!activeUser || examLocked()) return;
  const incident = state.incidents.find((x) => x.id === id);
  if (!incident) return;
  const map = {
    assign: [`Assigned to ${activeUser.name}.`, incident.status],
    begin: ["Status changed to In Review.", "in_progress"],
    benign: ["Marked clean and closed.", "resolved"],
    quarantine: ["Email quarantined from reported mailbox.", "in_progress"],
    phishrip: ["PhishRIP initiated: searched tenant and removed matching messages.", "in_progress"],
    phishflip: ["PhishFlip created simulation template from this threat.", incident.status],
    block_domain: ["Sender domain added to blocklist.", "in_progress"],
    zap: ["ZAP executed.", "in_progress"],
    escalate: ["Escalated Tier 2.", "in_progress"],
    resolve: ["Incident resolved as malicious.", "resolved"]
  };
  if (!map[action]) return;
  mutateIncident(id, (i) => {
    i.actions.push({ ts: now(), text: map[action][0], by: activeUser.name });
    i.status = map[action][1];
    if (action === "assign") i.assignee = activeUser.name;
    if (i.status === "resolved") i.resolvedBy = activeUser.name;
    return i;
  });
  applyPoints(action, incident);
  saveState();
  renderAll();
}

function renderScoreboard() {
  const selectedSection = document.getElementById("scoreboard-section-filter").value;
  const rows = Object.entries(state.scorecards).map(([name, s]) => ({ name, role: s.role, section: s.section || "Section A", score: s.score, resolved: s.resolved, accuracy: s.resolved ? Math.round((s.correctVerdicts / s.resolved) * 100) : 0 }))
    .filter((r) => selectedSection === "all" || r.section === selectedSection)
    .sort((a, b) => b.score - a.score);
  const canSeeGrades = isInstructor() || state.exam.gradesReleased;
  document.getElementById("scoreboard-table").innerHTML = rows.map((r) => {
    const scoreCell = canSeeGrades ? r.score : "Hidden";
    const accCell = canSeeGrades ? `${r.accuracy}%` : "Hidden";
    return `<tr><td>${r.name}</td><td>${r.section}</td><td>${r.role}</td><td>${scoreCell}</td><td>${r.resolved}</td><td>${accCell}</td></tr>`;
  }).join("") || "<tr><td colspan='6'>No activity yet.</td></tr>";

  const attempts = state.attempts || [];
  document.getElementById("attempt-history-table").innerHTML = attempts.filter((a) => selectedSection === "all" || a.section === selectedSection).map((a) => {
    const score = canSeeGrades ? a.score : "Hidden";
    const accuracy = canSeeGrades ? `${a.accuracy}%` : "Hidden";
    return `<tr><td>${a.student}</td><td>${a.section || "Section A"}</td><td>${a.pack}</td><td>${a.submittedAt}</td><td>${score}</td><td>${a.resolved}</td><td>${accuracy}</td></tr>`;
  }).join("") || "<tr><td colspan='7'>No submissions yet.</td></tr>";
}

function renderAnalytics() {
  const scoreRows = Object.values(state.scorecards || {});
  const sectionData = (state.sections || ["Section A", "Section B", "Section C"]).map((section) => {
    const members = scoreRows.filter((s) => (s.section || "Section A") === section);
    const avgScore = members.length ? Math.round(members.reduce((sum, s) => sum + s.score, 0) / members.length) : 0;
    const avgAccuracy = members.length ? Math.round(members.reduce((sum, s) => sum + (s.resolved ? (s.correctVerdicts / s.resolved) * 100 : 0), 0) / members.length) : 0;
    return { section, students: members.length, avgScore, avgAccuracy };
  });
  document.getElementById("analytics-sections-table").innerHTML = sectionData.map((s) => `<tr><td>${s.section}</td><td>${s.students}</td><td>${s.avgScore}</td><td>${s.avgAccuracy}%</td></tr>`).join("");

  const attempts = state.attempts || [];
  let wrongVerdictCount = 0;
  let lowDocumentationCount = 0;
  let overContainmentCount = 0;
  attempts.forEach((a) => {
    if ((a.accuracy || 0) < 70) wrongVerdictCount += 1;
    if ((a.notesAdded || 0) < 1) lowDocumentationCount += 1;
    if ((a.falseContainmentActions || 0) > 0) overContainmentCount += 1;
  });
  document.getElementById("analytics-trends-table").innerHTML = [
    ["Low verdict accuracy submissions (<70%)", wrongVerdictCount],
    ["Submissions with weak documentation", lowDocumentationCount],
    ["Potential over-containment events", overContainmentCount]
  ].map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join("");
}

function renderAnswerKey() {
  const tb = document.getElementById("answer-key-table");
  if (!isInstructor()) { tb.innerHTML = "<tr><td colspan='4'>Instructor access required.</td></tr>"; return; }
  tb.innerHTML = state.incidents.map((i) => {
    const rec = i.groundTruth === "phishing" ? "Contain + Resolve" : "Mark Benign";
    const reason = i.groundTruth === "phishing" ? "Auth failures, suspicious domain/URL, social engineering lure." : "Trusted sender/auth and legitimate business context.";
    return `<tr><td>${i.id} - ${i.subject}</td><td>${i.groundTruth}</td><td>${rec}</td><td>${reason}</td></tr>`;
  }).join("");
}

function renderCampaigns() {
  document.getElementById("campaign-template").innerHTML = state.templates.map((t) => `<option>${t.name}</option>`).join("");
  document.getElementById("campaign-landing").innerHTML = state.landingPages.map((p) => `<option>${p.name}</option>`).join("");
  document.getElementById("campaign-group").innerHTML = state.groups.map((g) => `<option>${g.name}</option>`).join("");
  document.getElementById("campaign-table").innerHTML = state.campaigns.map((c) => `<tr><td>${c.name}</td><td>${c.template}</td><td>${c.group}</td><td>${c.status}</td><td>${c.results}</td></tr>`).join("");
}

function renderLists() {
  document.getElementById("template-list").innerHTML = state.templates.map((t) => `<div class="list-item"><strong>${t.id}</strong> - ${t.name}</div>`).join("");
  document.getElementById("landing-list").innerHTML = state.landingPages.map((p) => `<div class="list-item"><strong>${p.id}</strong> - ${p.name}</div>`).join("");
  document.getElementById("group-list").innerHTML = state.groups.map((g) => `<div class="list-item"><strong>${g.id}</strong> - ${g.name}<br>Users: ${g.users}</div>`).join("");
}

function loadScenarioPack(name) {
  if (!scenarioPacks[name]) return;
  state.activePack = name;
  state.incidents = structuredClone(scenarioPacks[name]).map(normalizeIncident);
  selectedIncidentId = null;
  saveState();
  renderAll();
}

function exportReportCsv() {
  const includeTruth = isInstructor();
  const rows = [[ "Incident ID", "Subject", "Status", "Severity", includeTruth ? "Ground Truth" : "Ground Truth", "Resolved By", "Actions", "Notes" ]];
  state.incidents.forEach((i) => rows.push([i.id, i.subject, i.status, i.severity, includeTruth ? i.groundTruth : "hidden", i.resolvedBy || "", String(i.actions.length), String(i.notes.length)]));
  const csv = rows.map((r) => r.map((v) => `"${String(v).replaceAll('"', '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `phishing-sim-report-${state.activePack}.csv`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

function exportReportPdf() {
  const includeTruth = isInstructor() || state.exam.gradesReleased;
  const entries = Object.entries(state.scorecards).map(([name, s]) => ({
    name,
    role: s.role,
    score: includeTruth ? s.score : "Hidden",
    resolved: s.resolved,
    accuracy: includeTruth ? `${s.resolved ? Math.round((s.correctVerdicts / s.resolved) * 100) : 0}%` : "Hidden"
  }));
  const win = window.open("", "_blank");
  if (!win) return;
  win.document.write(`
    <html><head><title>Phishing Simulator Report</title>
    <style>body{font-family:Arial,sans-serif;padding:20px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ccc;padding:8px;text-align:left}h1,h2{margin:0 0 10px 0}</style>
    </head><body>
    <h1>KnowB4 Phishing Simulator Report</h1>
    <p>Pack: ${state.activePack.toUpperCase()} | Generated: ${now()}</p>
    <h2>Scoreboard</h2>
    <table><thead><tr><th>Analyst</th><th>Role</th><th>Score</th><th>Resolved</th><th>Accuracy</th></tr></thead>
    <tbody>${entries.map((e) => `<tr><td>${e.name}</td><td>${e.role}</td><td>${e.score}</td><td>${e.resolved}</td><td>${e.accuracy}</td></tr>`).join("")}</tbody></table>
    </body></html>
  `);
  win.document.close();
  win.focus();
  win.print();
}

function updateExamTimerUi() {
  const el = document.getElementById("exam-timer");
  if (!state.exam.active || !state.exam.endsAt) { el.textContent = "Exam: Off"; return; }
  const left = state.exam.endsAt - Date.now();
  if (left <= 0) {
    state.exam.active = false;
    saveState();
    el.textContent = "Exam: Finished";
    clearInterval(examTimerInterval);
    return;
  }
  const m = Math.floor(left / 60000);
  const s = Math.floor((left % 60000) / 1000);
  el.textContent = `Exam: ${m}:${String(s).padStart(2, "0")}`;
}

function startExam(minutes) {
  state.exam.active = true;
  state.exam.startedAt = Date.now();
  state.exam.endsAt = Date.now() + minutes * 60000;
  state.exam.submittedUsers = [];
  state.exam.gradesReleased = false;
  saveState();
  if (examTimerInterval) clearInterval(examTimerInterval);
  examTimerInterval = setInterval(updateExamTimerUi, 1000);
  updateExamTimerUi();
  renderAll();
}

function submitExamForActiveUser() {
  if (!activeUser || !state.exam.active) return;
  if (!state.exam.submittedUsers.includes(activeUser.name)) {
    state.exam.submittedUsers.push(activeUser.name);
    upsertScorecard(activeUser.name, activeUser.role);
    const s = state.scorecards[activeUser.name];
    const accuracy = s.resolved ? Math.round((s.correctVerdicts / s.resolved) * 100) : 0;
    state.attempts = state.attempts || [];
    state.attempts.unshift({
      student: activeUser.name,
      section: activeUser.section || "Section A",
      pack: state.activePack.toUpperCase(),
      submittedAt: now(),
      score: s.score,
      resolved: s.resolved,
      accuracy,
      notesAdded: s.notesAdded || 0,
      falseContainmentActions: Math.max(0, (s.containmentActions || 0) - (s.correctVerdicts || 0))
    });
  }
  saveState();
  renderAll();
}

function toggleGradeRelease() {
  if (!isInstructor()) return;
  state.exam.gradesReleased = !state.exam.gradesReleased;
  saveState();
  renderAll();
}

function bindNav() {
  document.querySelectorAll(".nav-link").forEach((btn) => btn.addEventListener("click", () => {
    if (btn.classList.contains("hidden")) return;
    document.querySelectorAll(".nav-link").forEach((n) => n.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    document.getElementById(btn.dataset.view).classList.add("active");
    document.getElementById("view-title").textContent = btn.textContent;
  }));
}

function bindInputs() {
  ["filter-phishml", "filter-priority", "filter-status", "filter-severity"].forEach((id) => document.getElementById(id).addEventListener("change", renderIncidentTable));
  document.getElementById("filter-search").addEventListener("input", renderIncidentTable);
  document.getElementById("load-pack").addEventListener("click", () => loadScenarioPack(document.getElementById("scenario-pack").value));
  document.getElementById("export-report").addEventListener("click", exportReportCsv);
  document.getElementById("export-pdf").addEventListener("click", exportReportPdf);
  document.getElementById("start-exam").addEventListener("click", () => { if (!isInstructor()) return; startExam(Number(document.getElementById("exam-minutes").value || 30)); });
  document.getElementById("submit-exam").addEventListener("click", submitExamForActiveUser);
  document.getElementById("release-grades").addEventListener("click", toggleGradeRelease);
  document.getElementById("scoreboard-section-filter").addEventListener("change", renderScoreboard);
  document.getElementById("reset-lab").addEventListener("click", () => { state = structuredClone(defaultState); if (activeUser) upsertScorecard(activeUser.name, activeUser.role, activeUser.section || "Section A"); saveState(); renderAll(); });
  document.getElementById("logout-btn").addEventListener("click", () => { activeUser = null; saveActiveUser(); setAppVisibility(); });
  document.getElementById("campaign-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("campaign-name").value.trim();
    if (!name) return;
    state.campaigns.unshift({ id: `CMP-${Math.floor(Math.random() * 9000) + 1000}`, name, template: document.getElementById("campaign-template").value, group: document.getElementById("campaign-group").value, status: "Launched", results: "Sent 10 / Open 6 / Click 3 / Submit 1" });
    saveState(); renderCampaigns(); document.getElementById("campaign-name").value = "";
  });
  document.getElementById("login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("login-name").value.trim();
    const role = document.getElementById("login-role").value;
    const section = document.getElementById("login-section").value;
    if (!name) return;
    activeUser = { name, role, section };
    upsertScorecard(name, role, section);
    saveState(); saveActiveUser(); setAppVisibility(); renderAll();
  });
}

function renderAll() {
  if (!activeUser) return;
  document.getElementById("scenario-pack").value = state.activePack;
  document.getElementById("release-grades").textContent = state.exam.gradesReleased ? "Hide Grades" : "Release Grades";
  document.getElementById("release-grades").disabled = !isInstructor();
  renderMetrics();
  renderIncidentTable();
  renderIncidentDetail();
  renderScoreboard();
  renderAnalytics();
  renderAnswerKey();
  renderCampaigns();
  renderLists();
  updateExamTimerUi();
}

bindNav();
bindInputs();
setAppVisibility();
normalizeState();
if (activeUser) {
  if (state.exam.active) {
    if (examTimerInterval) clearInterval(examTimerInterval);
    examTimerInterval = setInterval(updateExamTimerUi, 1000);
  }
  renderAll();
}
