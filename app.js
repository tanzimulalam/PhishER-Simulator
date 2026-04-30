const defaultState = {
  incidents: [
    {
      id: "INC-1001",
      subject: "Urgent: Payroll discrepancy needs approval",
      sender: "Payroll Team <payroll-update@hr-payroll-check.com>",
      severity: "high",
      status: "requires_attention",
      receivedAt: "2026-04-30 09:07",
      auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
      url: "https://microsoft365-auth-secure-login.com",
      domainAgeDays: 2,
      hasAttachment: false,
      bodySummary: "Requests immediate action and asks recipient to verify payroll details via link.",
      groundTruth: "phishing",
      actions: [],
      notes: []
    },
    {
      id: "INC-1002",
      subject: "Quarterly benefits policy update",
      sender: "HR Communications <hr@academy.local>",
      severity: "low",
      status: "requires_attention",
      receivedAt: "2026-04-30 08:45",
      auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
      url: "https://intranet.academy.local/benefits",
      domainAgeDays: 2200,
      hasAttachment: true,
      attachmentHash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      bodySummary: "Internal update with policy PDF attachment.",
      groundTruth: "benign",
      actions: [],
      notes: []
    },
    {
      id: "INC-1003",
      subject: "Doc shared with you: Invoice_44192",
      sender: "Drive Share <noreply@secure-doc-view.net>",
      severity: "critical",
      status: "requires_attention",
      receivedAt: "2026-04-30 09:18",
      auth: { spf: "softfail", dkim: "fail", dmarc: "fail" },
      url: "https://view-doc-login-secure.net/preview",
      domainAgeDays: 1,
      hasAttachment: true,
      attachmentHash: "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      bodySummary: "Shared file lure with macro-enabled invoice attachment and urgent payment wording.",
      groundTruth: "phishing",
      actions: [],
      notes: []
    }
  ],
  templates: [
    { id: "TPL-1", name: "Microsoft 365 Password Expiry", risk: "high" },
    { id: "TPL-2", name: "HR Benefits Enrollment Reminder", risk: "medium" }
  ],
  landingPages: [
    { id: "LP-1", name: "M365 Login Clone", capture: true, redirect: "https://office.com" },
    { id: "LP-2", name: "Awareness Training Landing", capture: false, redirect: "https://academy.local/training" }
  ],
  groups: [
    { id: "GRP-1", name: "Class Section A", users: 12 },
    { id: "GRP-2", name: "Class Section B", users: 10 }
  ],
  campaigns: [
    { id: "CMP-1", name: "Week1 Credential Harvest Drill", template: "Microsoft 365 Password Expiry", group: "Class Section A", status: "Completed", results: "Sent 12 / Click 6 / Submit 4" }
  ]
};

let state = loadState();
let selectedIncidentId = null;

function loadState() {
  const raw = localStorage.getItem("kb4sim-state");
  if (!raw) return structuredClone(defaultState);
  try {
    return JSON.parse(raw);
  } catch {
    return structuredClone(defaultState);
  }
}

function saveState() {
  localStorage.setItem("kb4sim-state", JSON.stringify(state));
}

function formatStatus(status) {
  return status.replaceAll("_", " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function renderMetrics() {
  const total = state.incidents.length;
  const open = state.incidents.filter((i) => i.status !== "resolved").length;
  const phishing = state.incidents.filter((i) => i.groundTruth === "phishing").length;
  const resolved = state.incidents.filter((i) => i.status === "resolved").length;
  const cards = [
    ["Incidents Total", total],
    ["Open Queue", open],
    ["Known Phishing Cases", phishing],
    ["Resolved", resolved]
  ];
  const container = document.getElementById("metric-cards");
  container.innerHTML = cards.map(([title, value]) => `<div class="card"><h4>${title}</h4><p>${value}</p></div>`).join("");
}

function renderIncidentTable() {
  const statusFilter = document.getElementById("filter-status").value;
  const sevFilter = document.getElementById("filter-severity").value;
  const incidents = state.incidents.filter((i) => {
    const byStatus = statusFilter === "all" || i.status === statusFilter;
    const bySev = sevFilter === "all" || i.severity === sevFilter;
    return byStatus && bySev;
  });
  const tbody = document.getElementById("incident-table");
  tbody.innerHTML = incidents.map((i) => `
    <tr data-id="${i.id}">
      <td><strong>${i.id}</strong><br/>${i.subject}</td>
      <td>${i.sender}</td>
      <td class="sev-${i.severity}">${i.severity.toUpperCase()}</td>
      <td><span class="status-pill">${formatStatus(i.status)}</span></td>
      <td>${i.receivedAt}</td>
    </tr>
  `).join("");

  tbody.querySelectorAll("tr").forEach((row) => {
    row.addEventListener("click", () => {
      selectedIncidentId = row.dataset.id;
      renderIncidentDetail();
    });
  });
}

function incidentScore(incident) {
  let score = 0;
  if (incident.auth.spf !== "pass") score += 20;
  if (incident.auth.dkim !== "pass") score += 20;
  if (incident.auth.dmarc !== "pass") score += 20;
  if (incident.domainAgeDays < 30) score += 20;
  if (incident.attachmentHash && incident.attachmentHash.startsWith("ed01")) score += 20;
  return Math.min(score, 100);
}

function actionButton(label, action, cssClass = "") {
  return `<button data-action="${action}" class="${cssClass}">${label}</button>`;
}

function renderIncidentDetail() {
  const pane = document.getElementById("incident-detail");
  const incident = state.incidents.find((i) => i.id === selectedIncidentId);
  if (!incident) {
    pane.innerHTML = "<h3>Select an incident</h3><p>Click a row to begin triage.</p>";
    return;
  }
  const score = incidentScore(incident);
  pane.innerHTML = `
    <h3>${incident.id} - ${incident.subject}</h3>
    <p><strong>Sender:</strong> ${incident.sender}</p>
    <p><strong>Summary:</strong> ${incident.bodySummary}</p>
    <p><strong>Authentication:</strong> SPF ${incident.auth.spf}, DKIM ${incident.auth.dkim}, DMARC ${incident.auth.dmarc}</p>
    <p><strong>URL:</strong> ${incident.url}</p>
    <p><strong>Domain Age:</strong> ${incident.domainAgeDays} day(s)</p>
    <p><strong>Attachment:</strong> ${incident.hasAttachment ? "Yes" : "No"} ${incident.attachmentHash ? `(${incident.attachmentHash})` : ""}</p>
    <p><strong>Risk Score:</strong> ${score}/100</p>
    <div class="action-row">
      ${actionButton("Begin Work", "begin")}
      ${actionButton("Mark Benign", "benign", "secondary")}
      ${actionButton("Quarantine Email", "quarantine")}
      ${actionButton("Block Sender Domain", "block_domain")}
      ${actionButton("Run ZAP", "zap")}
      ${actionButton("Escalate to Tier 2", "escalate")}
      ${actionButton("Resolve", "resolve")}
    </div>
    <label style="margin-top:10px;">
      Investigation Note
      <textarea id="incident-note" class="note-box" placeholder="Write why you chose the action, include evidence and decision rationale."></textarea>
    </label>
    <button id="save-note" style="margin-top:8px;">Save Note</button>
    <h4>Action Log</h4>
    <ul>
      ${incident.actions.map((a) => `<li>${a.ts} - ${a.text}</li>`).join("") || "<li>No actions yet</li>"}
    </ul>
    <h4>Notes</h4>
    <ul>
      ${incident.notes.map((n) => `<li>${n.ts} - ${n.text}</li>`).join("") || "<li>No notes yet</li>"}
    </ul>
  `;

  pane.querySelectorAll("[data-action]").forEach((btn) => {
    btn.addEventListener("click", () => {
      applyAction(incident.id, btn.dataset.action);
    });
  });
  document.getElementById("save-note").addEventListener("click", () => {
    const note = document.getElementById("incident-note").value.trim();
    if (!note) return;
    addNote(incident.id, note);
    renderAll();
  });
}

function now() {
  return new Date().toLocaleString();
}

function updateIncident(id, updater) {
  state.incidents = state.incidents.map((i) => (i.id === id ? updater(i) : i));
  saveState();
}

function addAction(id, text) {
  updateIncident(id, (i) => ({
    ...i,
    actions: [...i.actions, { ts: now(), text }]
  }));
}

function addNote(id, text) {
  updateIncident(id, (i) => ({
    ...i,
    notes: [...i.notes, { ts: now(), text }]
  }));
}

function applyAction(id, action) {
  const incident = state.incidents.find((i) => i.id === id);
  if (!incident) return;
  if (action === "begin") {
    updateIncident(id, (i) => ({ ...i, status: "in_progress" }));
    addAction(id, "Analyst began investigation.");
  } else if (action === "benign") {
    addAction(id, "Marked as benign after IOC review.");
    updateIncident(id, (i) => ({ ...i, status: "resolved" }));
  } else if (action === "quarantine") {
    addAction(id, "Email quarantined in mailbox.");
    updateIncident(id, (i) => ({ ...i, status: "in_progress" }));
  } else if (action === "block_domain") {
    addAction(id, "Sender domain added to blocklist.");
    updateIncident(id, (i) => ({ ...i, status: "in_progress" }));
  } else if (action === "zap") {
    addAction(id, "ZAP action executed across tenant.");
    updateIncident(id, (i) => ({ ...i, status: "in_progress" }));
  } else if (action === "escalate") {
    addAction(id, "Escalated to Tier 2 with collected evidence.");
    updateIncident(id, (i) => ({ ...i, status: "in_progress" }));
  } else if (action === "resolve") {
    addAction(id, "Incident resolved and closed.");
    updateIncident(id, (i) => ({ ...i, status: "resolved" }));
  }
  saveState();
  renderAll();
}

function renderCampaigns() {
  const templateSel = document.getElementById("campaign-template");
  const landingSel = document.getElementById("campaign-landing");
  const groupSel = document.getElementById("campaign-group");

  templateSel.innerHTML = state.templates.map((t) => `<option>${t.name}</option>`).join("");
  landingSel.innerHTML = state.landingPages.map((p) => `<option>${p.name}</option>`).join("");
  groupSel.innerHTML = state.groups.map((g) => `<option>${g.name}</option>`).join("");

  document.getElementById("campaign-table").innerHTML = state.campaigns.map((c) => `
    <tr>
      <td>${c.name}</td>
      <td>${c.template}</td>
      <td>${c.group}</td>
      <td>${c.status}</td>
      <td>${c.results}</td>
    </tr>
  `).join("");
}

function renderStaticLists() {
  document.getElementById("template-list").innerHTML = state.templates
    .map((t) => `<div class="list-item"><strong>${t.id}</strong> - ${t.name} <span class="status-pill">Risk ${t.risk}</span></div>`)
    .join("");
  document.getElementById("landing-list").innerHTML = state.landingPages
    .map((p) => `<div class="list-item"><strong>${p.id}</strong> - ${p.name} | Capture: ${p.capture ? "On" : "Off"} | Redirect: ${p.redirect}</div>`)
    .join("");
  document.getElementById("group-list").innerHTML = state.groups
    .map((g) => `<div class="list-item"><strong>${g.id}</strong> - ${g.name} | Users: ${g.users}</div>`)
    .join("");
}

function bindNav() {
  const nav = document.querySelectorAll(".nav-link");
  nav.forEach((btn) => {
    btn.addEventListener("click", () => {
      nav.forEach((n) => n.classList.remove("active"));
      btn.classList.add("active");
      const view = btn.dataset.view;
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      document.getElementById(view).classList.add("active");
      document.getElementById("view-title").textContent = btn.textContent;
    });
  });
}

function bindForms() {
  document.getElementById("campaign-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("campaign-name").value.trim();
    if (!name) return;
    const template = document.getElementById("campaign-template").value;
    const group = document.getElementById("campaign-group").value;
    state.campaigns.unshift({
      id: `CMP-${Math.floor(Math.random() * 9000) + 1000}`,
      name,
      template,
      group,
      status: "Launched",
      results: "Sent 0 / Click 0 / Submit 0"
    });
    document.getElementById("campaign-name").value = "";
    saveState();
    renderAll();
  });

  document.getElementById("filter-status").addEventListener("change", renderIncidentTable);
  document.getElementById("filter-severity").addEventListener("change", renderIncidentTable);
  document.getElementById("reset-lab").addEventListener("click", () => {
    state = structuredClone(defaultState);
    selectedIncidentId = null;
    saveState();
    renderAll();
  });
}

function renderAll() {
  renderMetrics();
  renderIncidentTable();
  renderIncidentDetail();
  renderCampaigns();
  renderStaticLists();
}

bindNav();
bindForms();
renderAll();
