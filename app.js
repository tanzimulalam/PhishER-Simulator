const defaultState = {
  incidents: [
    {
      id: "INC-3001",
      subject: "Action required: Re-authenticate your Microsoft account",
      sender: "Microsoft Security <noreply@ms-secure-auth.com>",
      source: "Defender Email",
      severity: "critical",
      status: "requires_attention",
      receivedAt: "2026-04-30 09:11",
      messageId: "<892211.ms-secure-auth.com>",
      auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
      url: "https://microsoft365-secure-auth.net/session",
      domainAgeDays: 3,
      bodySummary: "User told account will be disabled in 30 minutes unless they sign in.",
      headerSnippet: "Return-Path: security@ms-secure-auth.com\nX-Originating-IP: 185.33.17.20\nReceived-SPF: fail",
      timeline: ["Delivered to 17 inboxes", "2 users clicked within 4 minutes", "1 user submitted credentials"],
      groundTruth: "phishing",
      actions: [],
      notes: []
    },
    {
      id: "INC-3002",
      subject: "IT Maintenance Window Notification",
      sender: "IT Operations <itops@academy.local>",
      source: "Reported by user",
      severity: "low",
      status: "requires_attention",
      receivedAt: "2026-04-30 08:50",
      messageId: "<1032.itops.academy.local>",
      auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
      url: "https://status.academy.local",
      domainAgeDays: 3200,
      bodySummary: "Maintenance notification and expected downtime.",
      headerSnippet: "Return-Path: itops@academy.local\nX-Originating-IP: 10.10.2.12\nReceived-SPF: pass",
      timeline: ["Delivered to all staff", "No suspicious click pattern", "Ticket raised by cautious employee"],
      groundTruth: "benign",
      actions: [],
      notes: []
    },
    {
      id: "INC-3003",
      subject: "Invoice overdue - immediate payment required",
      sender: "Finance Desk <billing@pay-support-now.com>",
      source: "Defender Email",
      severity: "high",
      status: "requires_attention",
      receivedAt: "2026-04-30 09:22",
      messageId: "<99122.pay-support-now.com>",
      auth: { spf: "softfail", dkim: "fail", dmarc: "fail" },
      url: "https://shared-invoice-docs.net/open",
      domainAgeDays: 1,
      bodySummary: "Invoice lure containing suspicious payment link and urgent language.",
      headerSnippet: "Return-Path: billing@pay-support-now.com\nX-Originating-IP: 91.204.12.9\nReceived-SPF: softfail",
      timeline: ["Delivered to finance distribution list", "Attachment downloaded 3 times", "Auto-detection queued as high risk"],
      groundTruth: "phishing",
      actions: [],
      notes: []
    }
  ],
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
  ]
};

let state = loadState();
let selectedIncidentId = null;

function loadState() {
  const raw = localStorage.getItem("kb4sim-state-v2");
  if (!raw) return structuredClone(defaultState);
  try {
    return JSON.parse(raw);
  } catch {
    return structuredClone(defaultState);
  }
}

function saveState() {
  localStorage.setItem("kb4sim-state-v2", JSON.stringify(state));
}

function now() {
  return new Date().toLocaleString();
}

function normalizeStatus(status) {
  return status.replaceAll("_", " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function scoreIncident(incident) {
  let score = 0;
  if (incident.auth.spf !== "pass") score += 20;
  if (incident.auth.dkim !== "pass") score += 20;
  if (incident.auth.dmarc !== "pass") score += 20;
  if (incident.domainAgeDays <= 30) score += 20;
  if (/urgent|disable|payment|required/i.test(incident.subject)) score += 20;
  return Math.min(score, 100);
}

function renderMetrics() {
  const total = state.incidents.length;
  const open = state.incidents.filter((i) => i.status !== "resolved").length;
  const inProgress = state.incidents.filter((i) => i.status === "in_progress").length;
  const resolved = state.incidents.filter((i) => i.status === "resolved").length;
  const cards = [
    ["Total Incidents", total],
    ["Open Queue", open],
    ["In Progress", inProgress],
    ["Resolved", resolved]
  ];
  document.getElementById("metric-cards").innerHTML = cards
    .map(([title, value]) => `<div class="card"><h4>${title}</h4><p>${value}</p></div>`)
    .join("");
}

function incidentMatchesFilters(incident) {
  const statusFilter = document.getElementById("filter-status").value;
  const severityFilter = document.getElementById("filter-severity").value;
  const query = document.getElementById("filter-search").value.trim().toLowerCase();
  const statusOk = statusFilter === "all" || incident.status === statusFilter;
  const severityOk = severityFilter === "all" || incident.severity === severityFilter;
  if (!query) return statusOk && severityOk;
  const haystack = `${incident.id} ${incident.subject} ${incident.sender} ${incident.url}`.toLowerCase();
  return statusOk && severityOk && haystack.includes(query);
}

function renderIncidentTable() {
  const rows = state.incidents.filter(incidentMatchesFilters);
  const tbody = document.getElementById("incident-table");
  tbody.innerHTML = rows
    .map(
      (i) => `
    <tr data-id="${i.id}">
      <td><strong>${i.id}</strong><br>${i.subject}</td>
      <td class="sev-${i.severity}">${i.severity.toUpperCase()}</td>
      <td><span class="status-pill status-${i.status}">${normalizeStatus(i.status)}</span></td>
      <td>${i.source}</td>
      <td>${i.receivedAt}</td>
    </tr>
  `
    )
    .join("");
  tbody.querySelectorAll("tr").forEach((row) => {
    row.addEventListener("click", () => {
      selectedIncidentId = row.dataset.id;
      renderIncidentDetail();
    });
  });
}

function authClass(value) {
  return value === "pass" ? "auth-pass" : "auth-fail";
}

function actionButton(label, action, cssClass = "") {
  return `<button class="${cssClass}" data-action="${action}">${label}</button>`;
}

function renderIncidentDetail() {
  const panel = document.getElementById("incident-detail");
  const incident = state.incidents.find((x) => x.id === selectedIncidentId);
  if (!incident) {
    panel.innerHTML = "<h3>Select an incident</h3><p>Open a row from the queue to start triage.</p>";
    return;
  }

  const score = scoreIncident(incident);
  panel.innerHTML = `
    <div class="detail-header">
      <h3>${incident.id} - ${incident.subject}</h3>
      <p><strong>Sender:</strong> ${incident.sender}</p>
      <p><strong>Message-ID:</strong> <span class="mono">${incident.messageId}</span></p>
      <p><strong>Body Summary:</strong> ${incident.bodySummary}</p>
    </div>

    <div class="evidence-grid">
      <div class="evidence-item">
        <strong>Authentication</strong><br>
        SPF: <span class="${authClass(incident.auth.spf)}">${incident.auth.spf}</span><br>
        DKIM: <span class="${authClass(incident.auth.dkim)}">${incident.auth.dkim}</span><br>
        DMARC: <span class="${authClass(incident.auth.dmarc)}">${incident.auth.dmarc}</span>
      </div>
      <div class="evidence-item">
        <strong>Threat Indicators</strong><br>
        URL: ${incident.url}<br>
        Domain age: ${incident.domainAgeDays} day(s)<br>
        Risk score: <strong>${score}/100</strong>
      </div>
      <div class="evidence-item">
        <strong>Header Preview</strong>
        <pre class="mono">${incident.headerSnippet}</pre>
      </div>
      <div class="evidence-item">
        <strong>Timeline</strong>
        <ul>${incident.timeline.map((t) => `<li>${t}</li>`).join("")}</ul>
      </div>
    </div>

    <div class="action-row">
      ${actionButton("Begin Work", "begin", "primary")}
      ${actionButton("Mark Benign", "benign")}
      ${actionButton("Quarantine", "quarantine")}
      ${actionButton("Block Domain", "block_domain")}
      ${actionButton("Run ZAP", "zap", "danger")}
      ${actionButton("Escalate Tier 2", "escalate")}
      ${actionButton("Resolve", "resolve", "primary")}
    </div>

    <label>Investigation Note
      <textarea id="incident-note" class="note-box" placeholder="Evidence, decision, and action rationale."></textarea>
    </label>
    <button id="save-note">Save Note</button>

    <h4>Action Log</h4>
    <ul>${incident.actions.map((a) => `<li>${a.ts} - ${a.text}</li>`).join("") || "<li>No actions yet</li>"}</ul>
    <h4>Notes</h4>
    <ul>${incident.notes.map((n) => `<li>${n.ts} - ${n.text}</li>`).join("") || "<li>No notes yet</li>"}</ul>
  `;

  panel.querySelectorAll("[data-action]").forEach((btn) => {
    btn.addEventListener("click", () => runAction(incident.id, btn.dataset.action));
  });
  panel.querySelector("#save-note").addEventListener("click", () => {
    const text = panel.querySelector("#incident-note").value.trim();
    if (!text) return;
    mutateIncident(incident.id, (item) => {
      item.notes.push({ ts: now(), text });
      return item;
    });
    renderAll();
  });
}

function mutateIncident(id, updater) {
  state.incidents = state.incidents.map((item) => {
    if (item.id !== id) return item;
    const copy = { ...item, actions: [...item.actions], notes: [...item.notes], timeline: [...item.timeline] };
    return updater(copy);
  });
  saveState();
}

function runAction(id, action) {
  const actionMap = {
    begin: { text: "Analyst started ticket ownership.", status: "in_progress" },
    benign: { text: "Marked as benign after evidence review.", status: "resolved" },
    quarantine: { text: "Email quarantined from affected mailbox(es).", status: "in_progress" },
    block_domain: { text: "Sender domain added to tenant block list.", status: "in_progress" },
    zap: { text: "ZAP executed to remove email organization-wide.", status: "in_progress" },
    escalate: { text: "Escalated to Tier 2 with evidence package.", status: "in_progress" },
    resolve: { text: "Incident resolved and closure documented.", status: "resolved" }
  };
  const selected = actionMap[action];
  if (!selected) return;

  mutateIncident(id, (incident) => {
    incident.actions.push({ ts: now(), text: selected.text });
    incident.status = selected.status;
    return incident;
  });
  renderAll();
}

function renderCampaigns() {
  const templateSelect = document.getElementById("campaign-template");
  const landingSelect = document.getElementById("campaign-landing");
  const groupSelect = document.getElementById("campaign-group");

  templateSelect.innerHTML = state.templates.map((t) => `<option value="${t.name}">${t.name}</option>`).join("");
  landingSelect.innerHTML = state.landingPages.map((p) => `<option value="${p.name}">${p.name}</option>`).join("");
  groupSelect.innerHTML = state.groups.map((g) => `<option value="${g.name}">${g.name}</option>`).join("");

  document.getElementById("campaign-table").innerHTML = state.campaigns
    .map(
      (c) => `
      <tr>
        <td>${c.name}</td>
        <td>${c.template}</td>
        <td>${c.group}</td>
        <td>${c.status}</td>
        <td>${c.results}</td>
      </tr>
    `
    )
    .join("");
}

function renderLists() {
  document.getElementById("template-list").innerHTML = state.templates
    .map((t) => `<div class="list-item"><strong>${t.id}</strong> - ${t.name}<br>${t.category} | Difficulty ${t.difficulty}</div>`)
    .join("");

  document.getElementById("landing-list").innerHTML = state.landingPages
    .map((p) => `<div class="list-item"><strong>${p.id}</strong> - ${p.name}<br>Capture: ${p.capture ? "Enabled" : "Disabled"} | Redirect: ${p.redirect}</div>`)
    .join("");

  document.getElementById("group-list").innerHTML = state.groups
    .map((g) => `<div class="list-item"><strong>${g.id}</strong> - ${g.name}<br>Users: ${g.users}</div>`)
    .join("");
}

function bindNavigation() {
  const links = document.querySelectorAll(".nav-link");
  links.forEach((btn) => {
    btn.addEventListener("click", () => {
      links.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
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
    const opens = Math.floor(Math.random() * 10) + 1;
    const clicks = Math.max(0, opens - Math.floor(Math.random() * 4));
    const submits = Math.max(0, clicks - Math.floor(Math.random() * 3));
    state.campaigns.unshift({
      id: `CMP-${Math.floor(Math.random() * 9000) + 1000}`,
      name,
      template,
      group,
      status: "Launched",
      results: `Sent ${opens + 4} / Open ${opens} / Click ${clicks} / Submit ${submits}`
    });
    document.getElementById("campaign-name").value = "";
    saveState();
    renderCampaigns();
  });

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
  renderLists();
}

bindNavigation();
bindInputs();
renderAll();
