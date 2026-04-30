const statusFlow = {
  received: ["in_review"],
  in_review: ["resolved"],
  resolved: []
};

const scenarioPacks = {
  medium: [
    {
      id: "M-3001",
      reporter: "emma.j@academy.local",
      subject: "Action required: Re-authenticate your Microsoft account",
      sender: "Microsoft Security <noreply@ms-secure-auth.com>",
      returnPath: "support@micros0ft-safety.net",
      source: "Defender Email",
      severity: "critical",
      priority: "critical",
      phishml: "threat",
      status: "received",
      receivedAt: "2026-05-01 10:11",
      messageId: "<med3001@ms-secure-auth.com>",
      auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
      url: "https://microsoft365-secure-auth.net/session",
      links: ["https://microsoft365-secure-auth.net/session"],
      attachments: ["security_update.html"],
      domainAgeDays: 3,
      bodySummary: "Urgent sign-in request claiming account disablement in 30 minutes.",
      headerSnippet: "From: Microsoft Security <noreply@ms-secure-auth.com>\nReturn-Path: support@micros0ft-safety.net\nReceived-SPF: fail",
      timeline: ["Delivered to 17 inboxes", "2 link clicks in 3 minutes", "1 credential submission observed"],
      ioc: { vt: "42/72 malicious", urlscan: "High risk", talos: "Poor reputation" },
      groundTruth: "phishing",
      tags: [],
      assignee: null,
      actions: [],
      notes: [],
      resolvedBy: null
    },
    {
      id: "M-3002",
      reporter: "liam.s@academy.local",
      subject: "IT Maintenance Window Notification",
      sender: "IT Operations <itops@academy.local>",
      returnPath: "itops@academy.local",
      source: "User Reported",
      severity: "low",
      priority: "low",
      phishml: "clean",
      status: "received",
      receivedAt: "2026-05-01 10:00",
      messageId: "<med3002@academy.local>",
      auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
      url: "https://status.academy.local",
      links: ["https://status.academy.local"],
      attachments: ["maintenance-policy.pdf"],
      domainAgeDays: 3200,
      bodySummary: "Legitimate maintenance advisory from internal IT.",
      headerSnippet: "From: IT Operations <itops@academy.local>\nReturn-Path: itops@academy.local\nReceived-SPF: pass",
      timeline: ["Delivered to all staff", "No suspicious click behavior"],
      ioc: { vt: "0/72 malicious", urlscan: "Benign", talos: "Trusted" },
      groundTruth: "benign",
      tags: [],
      assignee: null,
      actions: [],
      notes: [],
      resolvedBy: null
    }
  ]
};

const defaultState = {
  activePack: "medium",
  incidents: structuredClone(scenarioPacks.medium),
  templates: [{ id: "TPL-1", name: "M365 Security Alert" }],
  landingPages: [{ id: "LP-1", name: "Microsoft Login Clone" }],
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

function loadState() {
  try {
    const parsed = JSON.parse(localStorage.getItem("kb4sim-phase3-state")) || structuredClone(defaultState);
    parsed.exam = parsed.exam || {};
    parsed.exam.gradesReleased = !!parsed.exam.gradesReleased;
    parsed.attempts = parsed.attempts || [];
    parsed.incidents = (parsed.incidents || []).map(normalizeIncident);
    return parsed;
  } catch {
    return structuredClone(defaultState);
  }
}

function normalizeIncident(raw) {
  return {
    ...raw,
    status: ["received", "in_review", "resolved"].includes(raw.status) ? raw.status : "received",
    tags: raw.tags || [],
    actions: raw.actions || [],
    notes: raw.notes || [],
    assignee: raw.assignee || null
  };
}

function saveState() { localStorage.setItem("kb4sim-phase3-state", JSON.stringify(state)); }
function loadActiveUser() { try { return JSON.parse(localStorage.getItem("kb4sim-active-user")) || null; } catch { return null; } }
function saveActiveUser() { if (!activeUser) localStorage.removeItem("kb4sim-active-user"); else localStorage.setItem("kb4sim-active-user", JSON.stringify(activeUser)); }
function now() { return new Date().toLocaleString(); }
function isInstructor() { return activeUser?.role === "instructor"; }
function examSubmitted() { return !!activeUser && state.exam.submittedUsers.includes(activeUser.name); }
function examLocked() { return !!activeUser && state.exam.active && activeUser.role === "student" && examSubmitted(); }
function inExamForStudent() { return !!activeUser && state.exam.active && activeUser.role === "student"; }

function upsertScorecard(name, role, section = "Section A") {
  if (!state.scorecards[name]) {
    state.scorecards[name] = { role, section, score: 0, resolved: 0, correctVerdicts: 0, notesAdded: 0, containmentActions: 0, beginWorkCount: 0 };
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
  const mine = activeUser ? state.scorecards[activeUser.name] : null;
  const cards = [["Pack", state.activePack.toUpperCase()], ["Incidents", state.incidents.length], ["Received", state.incidents.filter((i) => i.status === "received").length], ["In Review", state.incidents.filter((i) => i.status === "in_review").length], ["My Score", mine ? mine.score : 0]];
  document.getElementById("metric-cards").innerHTML = cards.map(([k, v]) => `<div class="card"><h4>${k}</h4><p>${v}</p></div>`).join("");
}

function incidentMatches(i) {
  const phishml = document.getElementById("filter-phishml").value;
  const priority = document.getElementById("filter-priority").value;
  const status = document.getElementById("filter-status").value;
  const severity = document.getElementById("filter-severity").value;
  const q = document.getElementById("filter-search").value.trim().toLowerCase();
  const ok = (phishml === "all" || i.phishml === phishml) &&
    (priority === "all" || i.priority === priority) &&
    (status === "all" || i.status === status) &&
    (severity === "all" || i.severity === severity);
  return ok && (!q || `${i.reporter} ${i.subject} ${i.sender}`.toLowerCase().includes(q));
}

function renderIncidentTable() {
  document.getElementById("incident-table").innerHTML = state.incidents.filter(incidentMatches).map((i) => `
    <tr data-id="${i.id}">
      <td>${i.reporter}</td>
      <td><strong>${i.subject}</strong><br><span class="muted">${i.sender}</span></td>
      <td><span class="phishml-badge phishml-${i.phishml}">${i.phishml.toUpperCase()}</span></td>
      <td class="sev-${i.priority}">${i.priority.toUpperCase()}</td>
      <td><span class="status-pill status-${i.status}">${i.status.replaceAll("_", " ").toUpperCase()}</span></td>
      <td>${i.receivedAt}</td>
    </tr>
  `).join("");
  document.querySelectorAll("#incident-table tr").forEach((row) => row.addEventListener("click", () => { selectedIncidentId = row.dataset.id; renderIncidentDetail(); }));
}

function isFromReturnPathMismatch(i) {
  const fromDomain = (i.sender.match(/@([^>]+)/) || [])[1] || "";
  const replyDomain = (i.returnPath.match(/@([^>]+)/) || [])[1] || "";
  return fromDomain && replyDomain && fromDomain.toLowerCase() !== replyDomain.toLowerCase();
}

function renderIncidentDetail() {
  const panel = document.getElementById("incident-detail");
  const i = state.incidents.find((x) => x.id === selectedIncidentId);
  if (!i) { panel.innerHTML = "<h3>Select a message</h3>"; return; }
  const locked = examLocked();
  const mismatch = isFromReturnPathMismatch(i);
  const risk = inExamForStudent() ? "Hidden in exam mode" : `${i.ioc?.vt || "N/A"} | ${i.ioc?.urlscan || "N/A"}`;
  panel.innerHTML = `
    <h3>${i.subject}</h3>
    <p><strong>Reporter:</strong> ${i.reporter} | <strong>Assignee:</strong> ${i.assignee || "Unassigned"}</p>
    <div class="detail-two-col">
      <div>
        <div class="tabs">
          <button class="tab-btn active" data-tab="body">Body</button>
          <button class="tab-btn" data-tab="headers">Headers</button>
          <button class="tab-btn" data-tab="auth">Auth</button>
          <button class="tab-btn" data-tab="attachments">Attachments</button>
          <button class="tab-btn" data-tab="ioc">IOC</button>
        </div>
        <div id="tab-body" class="tab-panel active"><p>${i.bodySummary}</p><p><strong>Links (hover-only):</strong><br>${i.links.map((l) => `<span class="mono">${l}</span>`).join("<br>")}</p></div>
        <div id="tab-headers" class="tab-panel">
          <pre class="mono">${i.headerSnippet}</pre>
          <p><strong>From:</strong> ${i.sender}<br><strong>Return-Path:</strong> ${i.returnPath}</p>
          ${mismatch ? '<p class="alert-bad">From / Return-Path mismatch detected (likely spoofing).</p>' : '<p class="alert-good">From / Return-Path aligned.</p>'}
        </div>
        <div id="tab-auth" class="tab-panel"><p>SPF: ${i.auth.spf}<br>DKIM: ${i.auth.dkim}<br>DMARC: ${i.auth.dmarc}</p></div>
        <div id="tab-attachments" class="tab-panel"><ul>${i.attachments.map((a) => `<li>${a}</li>`).join("")}</ul></div>
        <div id="tab-ioc" class="tab-panel"><p><strong>VirusTotal:</strong> ${i.ioc?.vt || "n/a"}<br><strong>URLScan:</strong> ${i.ioc?.urlscan || "n/a"}<br><strong>Talos:</strong> ${i.ioc?.talos || "n/a"}<br><strong>IOC Summary:</strong> ${risk}</p></div>
      </div>
      <div>
        <div class="action-row">
          <button data-action="assign" ${locked ? "disabled" : ""}>Assign</button>
          <button data-action="begin" ${locked ? "disabled" : ""}>Set In Review</button>
          <button data-action="phishrip" ${locked ? "disabled" : ""}>Run PhishRIP</button>
          <button data-action="block_domain" ${locked ? "disabled" : ""}>Blocklist Domain</button>
          <button data-action="phishflip" ${locked ? "disabled" : ""}>PhishFlip</button>
          <button data-action="resolve" class="primary" ${locked ? "disabled" : ""}>Resolve</button>
          <button data-action="benign" ${locked ? "disabled" : ""}>Mark Clean</button>
        </div>
        <label>Add Tag<input id="incident-tag-input" ${locked ? "disabled" : ""} placeholder="Credential Harvesting / Malware / Spam" /></label>
        <button id="add-tag-btn" ${locked ? "disabled" : ""}>Add Tag</button>
        <p><strong>Tags:</strong> ${i.tags.length ? i.tags.join(", ") : "None"}</p>
        <label>Discussion<textarea id="incident-note" class="note-box" ${locked ? "disabled" : ""} placeholder="Document findings and final decision."></textarea></label>
        <button id="save-note" ${locked ? "disabled" : ""}>Post Comment</button>
      </div>
    </div>
    <h4>Action Log (Audit)</h4>
    <ul>${i.actions.map((a) => `<li>${a.ts} - ${a.text} | Tool: ${a.tool} | By: ${a.by || "n/a"}</li>`).join("") || "<li>No actions yet</li>"}</ul>
    <h4>Discussion</h4>
    <ul>${i.notes.map((n) => `<li>${n.ts} - ${n.text} (${n.by || "n/a"})</li>`).join("") || "<li>No comments yet</li>"}</ul>
  `;

  panel.querySelectorAll(".tab-btn").forEach((btn) => btn.addEventListener("click", () => {
    panel.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    panel.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    panel.querySelector(`#tab-${btn.dataset.tab}`).classList.add("active");
  }));
  panel.querySelectorAll("[data-action]").forEach((btn) => btn.addEventListener("click", () => runAction(i.id, btn.dataset.action)));
  panel.querySelector("#add-tag-btn").addEventListener("click", () => {
    const tag = panel.querySelector("#incident-tag-input").value.trim();
    if (!tag || !activeUser || examLocked()) return;
    mutateIncident(i.id, (x) => { if (!x.tags.includes(tag)) x.tags.push(tag); return x; });
    saveState();
    renderIncidentDetail();
  });
  panel.querySelector("#save-note").addEventListener("click", () => {
    const text = panel.querySelector("#incident-note").value.trim();
    if (!text || !activeUser || examLocked()) return;
    mutateIncident(i.id, (x) => { x.notes.push({ ts: now(), text, by: activeUser.name }); return x; });
    upsertScorecard(activeUser.name, activeUser.role, activeUser.section || "Section A");
    state.scorecards[activeUser.name].score += 10;
    state.scorecards[activeUser.name].notesAdded += 1;
    saveState();
    renderIncidentDetail();
  });
}

function mutateIncident(id, updater) {
  state.incidents = state.incidents.map((i) => (i.id === id ? updater({ ...i, actions: [...i.actions], notes: [...i.notes], tags: [...i.tags] }) : i));
}

function transitionAllowed(current, next) {
  return statusFlow[current]?.includes(next);
}

function logAction(i, text, tool) {
  i.actions.push({ ts: now(), text, tool, by: activeUser?.name || "system" });
}

function runAction(id, action) {
  if (!activeUser || examLocked()) return;
  const incident = state.incidents.find((x) => x.id === id);
  if (!incident) return;

  mutateIncident(id, (i) => {
    if (action === "assign") {
      i.assignee = activeUser.name;
      logAction(i, `Case assigned to ${activeUser.name}.`, "PhishER Assign");
    } else if (action === "begin") {
      if (transitionAllowed(i.status, "in_review")) {
        i.status = "in_review";
        logAction(i, "Status moved to In Review.", "PhishER Status");
      } else {
        logAction(i, "Status transition blocked by lifecycle policy.", "Lifecycle Guard");
      }
    } else if (action === "resolve") {
      if (transitionAllowed(i.status, "resolved")) {
        i.status = "resolved";
        i.resolvedBy = activeUser.name;
        logAction(i, "Incident resolved as malicious after review.", "PhishER Resolve");
      } else {
        logAction(i, "Cannot resolve directly from Received. Move to In Review first.", "Lifecycle Guard");
      }
    } else if (action === "benign") {
      if (transitionAllowed(i.status, "resolved")) {
        i.status = "resolved";
        i.resolvedBy = activeUser.name;
        logAction(i, "Incident resolved as clean false positive.", "PhishER Resolve");
      } else {
        logAction(i, "Cannot mark clean directly from Received. Move to In Review first.", "Lifecycle Guard");
      }
    } else if (action === "block_domain") {
      logAction(i, `Sender domain blocked (${(i.returnPath.split("@")[1] || "unknown")}).`, "Blocklist");
    } else if (action === "phishflip") {
      logAction(i, "PhishFlip created awareness template from this message.", "PhishFlip");
    } else if (action === "phishrip") {
      const found = Math.floor(Math.random() * 12) + 3;
      const removed = Math.max(1, found - Math.floor(Math.random() * 3));
      logAction(i, `PhishRIP completed: ${found} matches found, ${removed} messages removed.`, "PhishRIP");
      openPhishRipModal(found, removed);
    }
    return i;
  });

  applyPoints(action, incident);
  saveState();
  renderAll();
}

function applyPoints(action, incident) {
  if (!activeUser) return;
  upsertScorecard(activeUser.name, activeUser.role, activeUser.section || "Section A");
  const s = state.scorecards[activeUser.name];
  if (action === "begin") s.beginWorkCount += 1;
  if (action === "phishrip" || action === "block_domain") s.containmentActions += 1;
  if (action === "resolve" || action === "benign") {
    s.resolved += 1;
    const correct = (action === "resolve" && incident.groundTruth === "phishing") || (action === "benign" && incident.groundTruth === "benign");
    if (correct) {
      s.correctVerdicts += 1;
      s.score += 40;
    } else {
      s.score = Math.max(0, s.score - 15);
    }
  }
}

function openPhishRipModal(found, removed) {
  const modal = document.getElementById("phishrip-modal");
  const text = document.getElementById("phishrip-result-text");
  text.textContent = `Tenant search complete. ${found} matching messages found. ${removed} messages quarantined/removed.`;
  modal.classList.remove("hidden");
}

function closePhishRipModal() {
  document.getElementById("phishrip-modal").classList.add("hidden");
}

function renderScoreboard() {
  const selectedSection = document.getElementById("scoreboard-section-filter").value;
  const rows = Object.entries(state.scorecards).map(([name, s]) => ({ name, ...s, accuracy: s.resolved ? Math.round((s.correctVerdicts / s.resolved) * 100) : 0 }))
    .filter((r) => selectedSection === "all" || r.section === selectedSection)
    .sort((a, b) => b.score - a.score);
  const canSee = isInstructor() || state.exam.gradesReleased;
  document.getElementById("scoreboard-table").innerHTML = rows.map((r) => `<tr><td>${r.name}</td><td>${r.section}</td><td>${r.role}</td><td>${canSee ? r.score : "Hidden"}</td><td>${r.resolved}</td><td>${canSee ? `${r.accuracy}%` : "Hidden"}</td></tr>`).join("") || "<tr><td colspan='6'>No activity yet.</td></tr>";
  const attempts = state.attempts || [];
  document.getElementById("attempt-history-table").innerHTML = attempts.filter((a) => selectedSection === "all" || a.section === selectedSection).map((a) => `<tr><td>${a.student}</td><td>${a.section}</td><td>${a.pack}</td><td>${a.submittedAt}</td><td>${canSee ? a.score : "Hidden"}</td><td>${a.resolved}</td><td>${canSee ? `${a.accuracy}%` : "Hidden"}</td></tr>`).join("") || "<tr><td colspan='7'>No submissions yet.</td></tr>";
}

function renderAnalytics() {
  const rows = Object.values(state.scorecards || {});
  const sectionRows = (state.sections || []).map((sec) => {
    const members = rows.filter((r) => (r.section || "Section A") === sec);
    const avgScore = members.length ? Math.round(members.reduce((sum, s) => sum + s.score, 0) / members.length) : 0;
    const avgAcc = members.length ? Math.round(members.reduce((sum, s) => sum + (s.resolved ? (s.correctVerdicts / s.resolved) * 100 : 0), 0) / members.length) : 0;
    return `<tr><td>${sec}</td><td>${members.length}</td><td>${avgScore}</td><td>${avgAcc}%</td></tr>`;
  }).join("");
  document.getElementById("analytics-sections-table").innerHTML = sectionRows;
  const attempts = state.attempts || [];
  const trends = [
    ["Low verdict accuracy submissions (<70%)", attempts.filter((a) => a.accuracy < 70).length],
    ["Submissions with weak documentation", attempts.filter((a) => (a.notesAdded || 0) < 1).length],
    ["Potential over-containment events", attempts.filter((a) => (a.falseContainmentActions || 0) > 0).length]
  ];
  document.getElementById("analytics-trends-table").innerHTML = trends.map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join("");
}

function renderAnswerKey() {
  const body = document.getElementById("answer-key-table");
  if (!isInstructor()) { body.innerHTML = "<tr><td colspan='4'>Instructor access required.</td></tr>"; return; }
  body.innerHTML = state.incidents.map((i) => `<tr><td>${i.id} - ${i.subject}</td><td>${i.groundTruth}</td><td>${i.groundTruth === "phishing" ? "In Review -> PhishRIP/Blocklist -> Resolve" : "In Review -> Mark Clean"}</td><td>${i.groundTruth === "phishing" ? "PhishML threat + auth/header/IOC indicators." : "Legitimate sender/auth and context."}</td></tr>`).join("");
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
  const rows = [["Incident ID", "Subject", "Status", "Severity", "Ground Truth", "Resolved By", "Actions", "Notes"]];
  state.incidents.forEach((i) => rows.push([i.id, i.subject, i.status, i.severity, includeTruth ? i.groundTruth : "hidden", i.resolvedBy || "", i.actions.length, i.notes.length]));
  const csv = rows.map((r) => r.map((v) => `"${String(v).replaceAll('"', '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `phishing-sim-report-${state.activePack}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function exportReportPdf() {
  const include = isInstructor() || state.exam.gradesReleased;
  const entries = Object.entries(state.scorecards).map(([name, s]) => ({ name, ...s, accuracy: s.resolved ? Math.round((s.correctVerdicts / s.resolved) * 100) : 0 }));
  const win = window.open("", "_blank");
  if (!win) return;
  win.document.write(`<html><body><h1>Phishing Simulator Report</h1><p>Generated: ${now()}</p><table border="1" cellspacing="0" cellpadding="6"><tr><th>Analyst</th><th>Section</th><th>Score</th><th>Resolved</th><th>Accuracy</th></tr>${entries.map((e) => `<tr><td>${e.name}</td><td>${e.section}</td><td>${include ? e.score : "Hidden"}</td><td>${e.resolved}</td><td>${include ? `${e.accuracy}%` : "Hidden"}</td></tr>`).join("")}</table></body></html>`);
  win.document.close();
  win.focus();
  win.print();
}

function updateExamTimerUi() {
  const el = document.getElementById("exam-timer");
  if (!state.exam.active || !state.exam.endsAt) { el.textContent = "Exam: Off"; return; }
  const left = state.exam.endsAt - Date.now();
  if (left <= 0) { state.exam.active = false; saveState(); el.textContent = "Exam: Finished"; clearInterval(examTimerInterval); return; }
  el.textContent = `Exam: ${Math.floor(left / 60000)}:${String(Math.floor((left % 60000) / 1000)).padStart(2, "0")}`;
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
  renderAll();
}

function submitExamForActiveUser() {
  if (!activeUser || !state.exam.active) return;
  if (!state.exam.submittedUsers.includes(activeUser.name)) {
    state.exam.submittedUsers.push(activeUser.name);
    upsertScorecard(activeUser.name, activeUser.role, activeUser.section || "Section A");
    const s = state.scorecards[activeUser.name];
    const accuracy = s.resolved ? Math.round((s.correctVerdicts / s.resolved) * 100) : 0;
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
  document.getElementById("scoreboard-section-filter").addEventListener("change", renderScoreboard);
  document.getElementById("load-pack").addEventListener("click", () => loadScenarioPack(document.getElementById("scenario-pack").value));
  document.getElementById("export-report").addEventListener("click", exportReportCsv);
  document.getElementById("export-pdf").addEventListener("click", exportReportPdf);
  document.getElementById("start-exam").addEventListener("click", () => { if (!isInstructor()) return; startExam(Number(document.getElementById("exam-minutes").value || 30)); });
  document.getElementById("submit-exam").addEventListener("click", submitExamForActiveUser);
  document.getElementById("release-grades").addEventListener("click", toggleGradeRelease);
  document.getElementById("reset-lab").addEventListener("click", () => { state = structuredClone(defaultState); if (activeUser) upsertScorecard(activeUser.name, activeUser.role, activeUser.section || "Section A"); saveState(); renderAll(); });
  document.getElementById("logout-btn").addEventListener("click", () => { activeUser = null; saveActiveUser(); setAppVisibility(); });
  document.getElementById("close-phishrip-modal").addEventListener("click", closePhishRipModal);
  document.getElementById("campaign-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("campaign-name").value.trim();
    if (!name) return;
    state.campaigns.unshift({ id: `CMP-${Math.floor(Math.random() * 9000) + 1000}`, name, template: document.getElementById("campaign-template").value, group: document.getElementById("campaign-group").value, status: "Launched", results: "Sent 10 / Open 6 / Click 3 / Submit 1" });
    saveState();
    renderCampaigns();
    document.getElementById("campaign-name").value = "";
  });
  document.getElementById("login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("login-name").value.trim();
    const role = document.getElementById("login-role").value;
    const section = document.getElementById("login-section").value;
    if (!name) return;
    activeUser = { name, role, section };
    upsertScorecard(name, role, section);
    saveState();
    saveActiveUser();
    setAppVisibility();
    renderAll();
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
if (activeUser) {
  if (state.exam.active) {
    if (examTimerInterval) clearInterval(examTimerInterval);
    examTimerInterval = setInterval(updateExamTimerUi, 1000);
  }
  renderAll();
}
