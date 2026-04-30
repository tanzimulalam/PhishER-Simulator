const STORAGE_KEY = "phisher-realism-v3";
const STATUS_FLOW = { received: ["in_review"], in_review: ["resolved"], resolved: [] };
const tabs = ["message", "headers", "raw", "attachments", "discussion"];

let state = loadState();
let selectedId = state.incidents[0]?.id || null;

function loadState() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return { incidents: buildScenarioEngine(60), filters: defaultFilters(), query: "" };
  try {
    const parsed = JSON.parse(raw);
    parsed.filters = parsed.filters || defaultFilters();
    parsed.query = parsed.query || "";
    parsed.incidents = (parsed.incidents || []).map(normalizeIncident);
    if (!parsed.incidents.length) parsed.incidents = buildScenarioEngine(60);
    return parsed;
  } catch {
    return { incidents: buildScenarioEngine(60), filters: defaultFilters(), query: "" };
  }
}

function saveState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function defaultFilters() {
  return { phishml: "all", priority: "all", status: "all", severity: "all" };
}

function now() {
  return new Date().toLocaleString();
}

function normalizeIncident(i) {
  return {
    ...i,
    status: i.status || "received",
    tags: i.tags || [],
    discussion: i.discussion || [],
    actions: i.actions || [],
    selectedTab: i.selectedTab || "message"
  };
}

function buildScenarioEngine(count) {
  const templates = [];
  for (let i = 0; i < count; i += 1) {
    const type = i % 4;
    templates.push(generateIncident(type, i + 1));
  }
  return templates;
}

function generateIncident(type, idx) {
  const id = `INC-${String(idx).padStart(4, "0")}`;
  if (type === 0) return buildCeoFraud(id, idx);
  if (type === 1) return buildQuishing(id, idx);
  if (type === 2) return buildCredentialHarvest(id, idx);
  return buildBenign(id, idx);
}

function authStrings(idx, malicious) {
  if (malicious) {
    return {
      spf: `v=spf1 include:_spf.fake-${idx}.net -all (fail)`,
      dkim: `dkim=fail header.d=fake-${idx}.net`,
      dmarc: `v=DMARC1; p=reject; pct=100 (fail)`
    };
  }
  return {
    spf: `v=spf1 include:_spf.academy.local -all (pass)`,
    dkim: `dkim=pass header.d=academy.local`,
    dmarc: `v=DMARC1; p=quarantine; pct=100 (pass)`
  };
}

function rawHeaders(from, replyTo, auth, idx) {
  return [
    `Return-Path: <${replyTo}>`,
    `Received: from mx${idx}.mailgw.net (mx${idx}.mailgw.net [185.31.${idx % 255}.19]) by mail.academy.local`,
    `X-Sender-IP: 185.31.${idx % 255}.19`,
    `From: ${from}`,
    `Reply-To: ${replyTo}`,
    `Authentication-Results: ${auth.spf}; ${auth.dkim}; ${auth.dmarc}`,
    `Message-ID: <${idx}.${Math.floor(Math.random() * 99999)}@mailgw.net>`,
    `MIME-Version: 1.0`,
    `Content-Type: text/html; charset=UTF-8`,
    `X-Originating-IP: [185.31.${idx % 255}.19]`,
    `X-Mailer: custom-mailer-${idx}`
  ].join("\n");
}

function buildCeoFraud(id, idx) {
  const from = `CEO Office <ceo.office@academy-leadership.com>`;
  const reply = `payments@academy-payroll-update${idx}.net`;
  const auth = authStrings(idx, true);
  return normalizeIncident({
    id,
    category: "CEO Fraud",
    reporter: `finance${idx % 7}@academy.local`,
    subject: `Urgent wire approval needed #${idx}`,
    fromDisplay: from,
    fromAddress: "ceo.office@academy-leadership.com",
    replyTo: reply,
    source: "User Reported",
    phishmlScore: 92,
    phishmlLabel: "threat",
    priority: "critical",
    severity: "critical",
    status: "received",
    receivedAt: now(),
    body: "Please process this wire transfer before end of day. Keep this confidential and confirm once done.",
    links: [`https://secure-wire-approval${idx}.net/portal`],
    attachments: ["wire_instructions.pdf"],
    auth,
    domainAgeDays: 4,
    rawHeaders: rawHeaders(from, reply, auth, idx)
  });
}

function buildQuishing(id, idx) {
  const from = `IT Service Desk <it-support@academy-ithelp.com>`;
  const reply = `it-support@academy-ithelp.com`;
  const auth = authStrings(idx, true);
  return normalizeIncident({
    id,
    category: "Quishing",
    reporter: `staff${idx % 12}@academy.local`,
    subject: `MFA Update Required - Scan QR Code #${idx}`,
    fromDisplay: from,
    fromAddress: "it-support@academy-ithelp.com",
    replyTo: reply,
    source: "Mailflow",
    phishmlScore: 88,
    phishmlLabel: "threat",
    priority: "high",
    severity: "high",
    status: "received",
    receivedAt: now(),
    body: "Your MFA token expires today. Scan the attached QR image to renew.",
    links: [`https://mfa-renew-${idx}.security-check.net`],
    attachments: ["mfa_qr_code.png"],
    auth,
    domainAgeDays: 9,
    rawHeaders: rawHeaders(from, reply, auth, idx)
  });
}

function buildCredentialHarvest(id, idx) {
  const from = `Microsoft Security Team <account-security@microsoft-mail-alert${idx}.com>`;
  const reply = `support@micr0soft-alert${idx}.net`;
  const auth = authStrings(idx, true);
  return normalizeIncident({
    id,
    category: "Credential Harvesting",
    reporter: `user${idx % 20}@academy.local`,
    subject: `Password Expiry Notice #${idx}`,
    fromDisplay: from,
    fromAddress: `account-security@microsoft-mail-alert${idx}.com`,
    replyTo: reply,
    source: "Defender Email",
    phishmlScore: 95,
    phishmlLabel: "threat",
    priority: "high",
    severity: "high",
    status: "received",
    receivedAt: now(),
    body: "Your account password expires in 15 minutes. Validate now to prevent lockout.",
    links: [`https://microsoft-security-login${idx}.com/session`],
    attachments: ["security_notice.html"],
    auth,
    domainAgeDays: 2,
    rawHeaders: rawHeaders(from, reply, auth, idx)
  });
}

function buildBenign(id, idx) {
  const from = `HR Newsletter <hr-news@academy.local>`;
  const reply = "hr-news@academy.local";
  const auth = authStrings(idx, false);
  return normalizeIncident({
    id,
    category: "Benign False Positive",
    reporter: `employee${idx % 25}@academy.local`,
    subject: `Monthly HR Newsletter ${idx}`,
    fromDisplay: from,
    fromAddress: "hr-news@academy.local",
    replyTo: reply,
    source: "User Reported",
    phishmlScore: 12,
    phishmlLabel: "clean",
    priority: "low",
    severity: "low",
    status: "received",
    receivedAt: now(),
    body: "This month highlights policy updates, wellness events, and upcoming training.",
    links: [`https://intranet.academy.local/hr/news/${idx}`],
    attachments: ["hr-newsletter.pdf"],
    auth,
    domainAgeDays: 4200,
    rawHeaders: rawHeaders(from, reply, auth, idx)
  });
}

function mismatch(i) {
  const fromDomain = i.fromAddress.split("@")[1] || "";
  const replyDomain = i.replyTo.split("@")[1] || "";
  return fromDomain && replyDomain && fromDomain.toLowerCase() !== replyDomain.toLowerCase();
}

function confidenceColor(score) {
  if (score >= 70) return "var(--threat)";
  if (score >= 40) return "var(--spam)";
  return "var(--clean)";
}

function confidenceText(score) {
  if (score >= 70) return "High Threat Likelihood";
  if (score >= 40) return "Suspicious / Needs Review";
  return "Likely Clean";
}

function phishmlBadge(label) {
  if (label === "threat") return "badge-threat";
  if (label === "spam") return "badge-spam";
  return "badge-clean";
}

function filteredIncidents() {
  return state.incidents.filter((i) => {
    const f = state.filters;
    const q = state.query.toLowerCase();
    const matchQuery = !q || `${i.reporter} ${i.subject} ${i.fromAddress} ${i.replyTo}`.toLowerCase().includes(q);
    return (f.phishml === "all" || i.phishmlLabel === f.phishml) &&
      (f.priority === "all" || i.priority === f.priority) &&
      (f.status === "all" || i.status === f.status) &&
      (f.severity === "all" || i.severity === f.severity) &&
      matchQuery;
  });
}

function appendAudit(i, text, icon, actor = "system") {
  const entry = { ts: now(), icon, actor, text };
  i.discussion.push(entry);
  i.actions.push(entry);
}

function renderInbox() {
  const target = document.getElementById("inbox-list");
  const incidents = filteredIncidents();
  target.innerHTML = incidents.map((i) => `
    <article class="inbox-row ${i.id === selectedId ? "active" : ""}" data-id="${i.id}" role="listitem" aria-label="Incident ${i.subject}">
      <div class="meta">${i.reporter}</div>
      <div><strong>${i.subject}</strong></div>
      <div class="meta">${i.fromAddress}</div>
      <div>
        <span class="badge ${phishmlBadge(i.phishmlLabel)}">${i.phishmlLabel.toUpperCase()}</span>
        <span class="badge">${i.priority.toUpperCase()}</span>
        <span class="badge">${i.status.replaceAll("_", " ").toUpperCase()}</span>
      </div>
    </article>
  `).join("");
  target.querySelectorAll(".inbox-row").forEach((row) => row.addEventListener("click", () => {
    selectedId = row.dataset.id;
    renderAll();
  }));
}

function tabButton(tab, active) {
  return `<button class="tab-btn ${active ? "active" : ""}" data-tab="${tab}" aria-label="Open ${tab} tab">${tab[0].toUpperCase() + tab.slice(1)}</button>`;
}

function renderMessagePane() {
  const target = document.getElementById("message-view");
  const i = state.incidents.find((x) => x.id === selectedId);
  if (!i) {
    target.innerHTML = '<div class="message"><h3>No message selected</h3></div>';
    return;
  }
  const barColor = confidenceColor(i.phishmlScore);
  const activeTab = i.selectedTab || "message";
  const rawPanel = `<pre class="mono">${i.rawHeaders}\n\nX-Sender: ${i.fromAddress}\nReturn-Path: ${i.replyTo}\nReceived: by edge.mail.academy.local\nReceived: from relay${i.id}.mailgw.net</pre>`;
  target.innerHTML = `
    <div class="message">
      <h2>${i.subject}</h2>
      <p class="meta">From: ${i.fromDisplay} | Reply-To: ${i.replyTo} | Received: ${i.receivedAt}</p>
      <div class="confidence-wrap">
        <div class="confidence-label">
          <span>PhishML Confidence: ${i.phishmlScore}%</span>
          <span>${confidenceText(i.phishmlScore)}</span>
        </div>
        <div class="confidence-bar" style="width:${i.phishmlScore}%; background:${barColor};"></div>
      </div>
      <div class="tabs">${tabs.map((t) => tabButton(t, t === activeTab)).join("")}</div>
      <section class="tab-panel ${activeTab === "message" ? "active" : ""}" id="panel-message">
        <p>${i.body}</p>
        <p><strong>URL(s):</strong><br>${i.links.map((l) => `<span class="mono">${l}</span>`).join("<br>")}</p>
      </section>
      <section class="tab-panel ${activeTab === "headers" ? "active" : ""}" id="panel-headers">
        <p><strong>From Address:</strong> ${i.fromAddress}</p>
        <p><strong>Reply-To:</strong> ${i.replyTo}</p>
        <p><strong>SPF:</strong> ${i.auth.spf}<br><strong>DKIM:</strong> ${i.auth.dkim}<br><strong>DMARC:</strong> ${i.auth.dmarc}</p>
        ${mismatch(i) ? `<div class="warn">Mismatch detected between From and Reply-To domain.</div>` : `<div class="ok">From and Reply-To are aligned.</div>`}
      </section>
      <section class="tab-panel ${activeTab === "raw" ? "active" : ""}" id="panel-raw">${rawPanel}</section>
      <section class="tab-panel ${activeTab === "attachments" ? "active" : ""}" id="panel-attachments">
        <ul>${i.attachments.map((a) => `<li>${a}</li>`).join("")}</ul>
        <p class="meta">Domain age: ${i.domainAgeDays} days</p>
      </section>
      <section class="tab-panel ${activeTab === "discussion" ? "active" : ""}" id="panel-discussion">
        <div class="log">${i.discussion.map((d) => `<div class="log-item">${d.icon} ${d.ts} - ${d.text} (${d.actor})</div>`).join("") || "No discussion yet."}</div>
      </section>
    </div>
  `;
  target.querySelectorAll(".tab-btn").forEach((btn) => btn.addEventListener("click", () => {
    i.selectedTab = btn.dataset.tab;
    saveState();
    renderMessagePane();
  }));
}

function allowedTransitions(status) {
  return STATUS_FLOW[status] || [];
}

function renderActionPane() {
  const target = document.getElementById("action-sidebar");
  const i = state.incidents.find((x) => x.id === selectedId);
  if (!i) {
    target.innerHTML = '<div class="sidebar">No incident selected.</div>';
    return;
  }
  const transitions = allowedTransitions(i.status);
  target.innerHTML = `
    <div class="sidebar">
      <label>Status
        <select id="status-select" aria-label="Change incident status">
          <option value="${i.status}">${i.status.replaceAll("_", " ").toUpperCase()}</option>
          ${transitions.map((s) => `<option value="${s}">${s.replaceAll("_", " ").toUpperCase()}</option>`).join("")}
        </select>
      </label>
      <label>Disposition
        <select id="disposition-select" aria-label="Set incident disposition">
          <option value="unknown">Unknown</option>
          <option value="threat">Threat</option>
          <option value="spam">Spam</option>
          <option value="clean">Clean</option>
        </select>
      </label>
      <label>Tag
        <input id="tag-input" aria-label="Add tag input" placeholder="Credential Harvesting" />
      </label>
      <button id="add-tag" aria-label="Add incident tag">Add Tag</button>
      <div class="meta">Tags: ${i.tags.join(", ") || "None"}</div>

      <div class="action-grid">
        <button id="assign-btn" aria-label="Assign incident to analyst">Assign to Me</button>
        <button id="phishrip-btn" aria-label="Run PhishRIP action">Run PhishRIP</button>
        <button id="blocklist-btn" aria-label="Block sender domain">Blocklist Domain</button>
        <button id="phishflip-btn" aria-label="Convert to PhishFlip template">PhishFlip</button>
      </div>

      <label>Analyst Note
        <textarea id="note-input" aria-label="Add analyst note" rows="5" placeholder="Document analysis and remediation."></textarea>
      </label>
      <button id="post-note" aria-label="Post note to discussion">Post Note</button>

      <div class="log">${i.actions.slice().reverse().slice(0, 12).map((a) => `<div class="log-item">${a.icon} ${a.ts} - ${a.text}</div>`).join("") || "No audit actions yet."}</div>
    </div>
  `;

  document.getElementById("status-select").value = i.status;
  document.getElementById("disposition-select").value = i.disposition || "unknown";

  document.getElementById("status-select").addEventListener("change", (e) => {
    const next = e.target.value;
    if (next !== i.status && allowedTransitions(i.status).includes(next)) {
      i.status = next;
      appendAudit(i, `Status changed to ${next.replaceAll("_", " ")}`, "🛠", "analyst");
      saveState();
      renderAll();
    }
  });
  document.getElementById("disposition-select").addEventListener("change", (e) => {
    i.disposition = e.target.value;
    appendAudit(i, `Disposition set to ${i.disposition}`, "🏷", "analyst");
    saveState();
    renderAll();
  });
  document.getElementById("add-tag").addEventListener("click", () => {
    const val = document.getElementById("tag-input").value.trim();
    if (!val) return;
    if (!i.tags.includes(val)) i.tags.push(val);
    appendAudit(i, `Tag added: ${val}`, "🏷", "analyst");
    saveState();
    renderAll();
  });
  document.getElementById("assign-btn").addEventListener("click", () => {
    i.assignee = "Current Analyst";
    appendAudit(i, "Case assigned to Current Analyst", "👤", "system");
    saveState();
    renderAll();
  });
  document.getElementById("blocklist-btn").addEventListener("click", () => {
    const domain = i.replyTo.split("@")[1] || "unknown";
    appendAudit(i, `Domain blocklist applied for ${domain}`, "⛔", "system");
    saveState();
    renderAll();
  });
  document.getElementById("phishflip-btn").addEventListener("click", () => {
    appendAudit(i, "PhishFlip template generated from incident", "🔁", "system");
    saveState();
    renderAll();
  });
  document.getElementById("post-note").addEventListener("click", () => {
    const note = document.getElementById("note-input").value.trim();
    if (!note) return;
    appendAudit(i, note, "🗒", "analyst");
    saveState();
    renderAll();
  });
  document.getElementById("phishrip-btn").addEventListener("click", () => runPhishRip(i));
}

function runPhishRip(i) {
  const modal = document.getElementById("phishrip-modal");
  const statusText = document.getElementById("phishrip-status");
  const bar = document.getElementById("phishrip-progress");
  modal.classList.remove("hidden");
  let progress = 0;
  bar.style.width = "0%";
  statusText.textContent = "Searching organization mailboxes...";
  const timer = setInterval(() => {
    progress += 12;
    bar.style.width = `${Math.min(progress, 100)}%`;
    if (progress >= 100) {
      clearInterval(timer);
      const found = Math.floor(Math.random() * 18) + 3;
      const removed = Math.max(1, found - Math.floor(Math.random() * 4));
      statusText.textContent = `Search complete. ${found} matching messages found, ${removed} deleted/quarantined.`;
      appendAudit(i, `PhishRIP executed: ${found} found / ${removed} removed`, "🧹", "system");
      saveState();
      renderActionPane();
      renderMessagePane();
    }
  }, 220);
}

function bindControls() {
  document.getElementById("global-search").addEventListener("input", (e) => {
    state.query = e.target.value;
    saveState();
    renderInbox();
  });
  document.getElementById("reset-data").addEventListener("click", () => {
    state = { incidents: buildScenarioEngine(60), filters: defaultFilters(), query: "" };
    selectedId = state.incidents[0]?.id || null;
    saveState();
    renderAll();
  });
  document.getElementById("filter-phishml").addEventListener("change", (e) => { state.filters.phishml = e.target.value; saveState(); renderInbox(); });
  document.getElementById("filter-priority").addEventListener("change", (e) => { state.filters.priority = e.target.value; saveState(); renderInbox(); });
  document.getElementById("filter-status").addEventListener("change", (e) => { state.filters.status = e.target.value; saveState(); renderInbox(); });
  document.getElementById("filter-severity").addEventListener("change", (e) => { state.filters.severity = e.target.value; saveState(); renderInbox(); });
  document.getElementById("close-modal").addEventListener("click", () => document.getElementById("phishrip-modal").classList.add("hidden"));
}

function hydrateControls() {
  document.getElementById("global-search").value = state.query || "";
  document.getElementById("filter-phishml").value = state.filters.phishml;
  document.getElementById("filter-priority").value = state.filters.priority;
  document.getElementById("filter-status").value = state.filters.status;
  document.getElementById("filter-severity").value = state.filters.severity;
}

function renderAll() {
  hydrateControls();
  renderInbox();
  renderMessagePane();
  renderActionPane();
}

bindControls();
renderAll();
