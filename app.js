const STORE = "phisher-enterprise-v4";
const SHIFT_SECONDS = 30 * 60;
const TABS = ["preview", "headers", "auth", "links", "attachments"];

let state = load();
let selected = state.incidents[0]?.id || null;
let answerKey = false;
let shiftTimer = null;

function load() {
  const raw = localStorage.getItem(STORE);
  if (!raw) {
    return {
      incidents: generateIncidents(55),
      filters: { room: "all", phishml: "all", priority: "all", status: "all", query: "" },
      shiftEndsAt: Date.now() + SHIFT_SECONDS * 1000
    };
  }
  try {
    const parsed = JSON.parse(raw);
    parsed.incidents = (parsed.incidents || []).map(normalizeIncident);
    parsed.filters = parsed.filters || { room: "all", phishml: "all", priority: "all", status: "all", query: "" };
    if (!parsed.shiftEndsAt) parsed.shiftEndsAt = Date.now() + SHIFT_SECONDS * 1000;
    return parsed;
  } catch {
    return {
      incidents: generateIncidents(55),
      filters: { room: "all", phishml: "all", priority: "all", status: "all", query: "" },
      shiftEndsAt: Date.now() + SHIFT_SECONDS * 1000
    };
  }
}

function save() {
  localStorage.setItem(STORE, JSON.stringify(state));
}

function now() {
  return new Date().toLocaleString();
}

function normalizeIncident(i) {
  return {
    ...i,
    status: i.status || "received",
    tab: i.tab || "preview",
    tags: i.tags || [],
    noteDraft: i.noteDraft || "",
    discussion: i.discussion || []
  };
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
    noteDraft: ""
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
      links: [`https://wire-portal-${idx}.net/approve`],
      attachments: ["wire_details.pdf"],
      auth: a,
      raw: rawHeaders(from, reply, a, idx),
      redFlag: "Reply-To domain does not match executive sender domain."
    });
  }
  if (type === "quishing") {
    const from = "IT Service Desk <it-support@academy-ithelp.com>";
    const reply = `security${idx}@academy-ithelp.com`;
    const a = auth(true, idx);
    return normalizeIncident({
      ...base,
      category: "Quishing",
      priority: "high",
      reporter: `user${idx % 20}@academy.local`,
      subject: `MFA Re-Enrollment Required (QR) ${idx}`,
      phishml: "threat",
      phishmlScore: rand(75, 96),
      from,
      replyTo: reply,
      preview: "Scan attached QR code to avoid account lock.",
      links: [`https://mfa-qr-renew-${idx}.security-check.net`],
      attachments: ["mfa_update_qr.png"],
      auth: a,
      raw: rawHeaders(from, reply, a, idx),
      redFlag: "QR lure + failing DKIM/DMARC indicates phishing infrastructure."
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
      links: [`https://identity-approve-${idx}.secure-now.net`],
      attachments: [],
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
      links: [`https://password-reset-${idx}.helpdesk-auth.net`],
      attachments: ["reset_notice.html"],
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
    links: [`https://intranet.academy.local/hr/news/${idx}`],
    attachments: ["hr_newsletter.pdf"],
    auth: a,
    raw: rawHeaders(from, reply, a, idx),
    redFlag: "No significant red flag. Legitimate internal communication."
  });
}

function generateIncidents(total) {
  const kinds = ["ceo_fraud", "quishing", "mfa_fatigue", "password_reset", "clean"];
  const out = [];
  for (let i = 1; i <= total; i += 1) {
    out.push(generateIncidentByType(kinds[(i - 1) % kinds.length], i));
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

function renderTriage() {
  const pane = document.getElementById("triage-pane");
  const i = state.incidents.find((x) => x.id === selected);
  if (!i) {
    pane.innerHTML = "<p>No incident selected.</p>";
    return;
  }
  const tab = i.tab || "preview";
  const locked = isLocked();
  const fromDomain = i.from.split("@")[1]?.replace(">", "") || "";
  const replyDomain = i.replyTo.split("@")[1] || "";
  const mismatch = fromDomain !== replyDomain;
  const headerLines = [
    { text: `From: ${i.from}`, flag: mismatch ? "Display sender domain does not align with reply route." : "" },
    { text: `Reply-To: ${i.replyTo}`, flag: mismatch ? "Reply-To points to different domain than From." : "" },
    { text: `X-Sender: ${i.replyTo}`, flag: mismatch ? "X-Sender corroborates redirected reply path." : "" },
    { text: `SPF: ${i.auth.spf}`, flag: i.auth.spf.includes("fail") ? "SPF failure indicates unauthorized sending host." : "" },
    { text: `DKIM: ${i.auth.dkim}`, flag: i.auth.dkim.includes("fail") ? "DKIM failure suggests signing mismatch or tampering." : "" },
    { text: `DMARC: ${i.auth.dmarc}`, flag: i.auth.dmarc.includes("fail") ? "DMARC failure indicates policy violation/spoofing risk." : "" }
  ];
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
      ${tab === "preview" ? `<p>${i.preview}</p>${answerKey ? `<p class="${mismatch ? "warn" : "ok"}">Red Flag: ${i.redFlag}</p>` : ""}` : ""}
      ${tab === "headers" ? `
        <div class="hover-hint">Hover suspicious header lines to inspect red flags.</div>
        <div class="headers-lab">
          ${headerLines.map((line) => `<div class="header-line ${line.flag ? "suspicious" : ""}" data-flag="${line.flag || ""}" aria-label="Header line">${line.text}</div>`).join("")}
        </div>
        <div id="header-flag-detail" class="${mismatch ? "warn" : "ok"}">${mismatch ? "Hover a highlighted line to view specific red-flag rationale." : "No critical mismatches detected in primary headers."}</div>
      ` : ""}
      ${tab === "auth" ? `<p>SPF: ${i.auth.spf}<br>DKIM: ${i.auth.dkim}<br>DMARC: ${i.auth.dmarc}</p>` : ""}
      ${tab === "links" ? `<ul>${i.links.map((l) => `<li class="mono">${l}</li>`).join("")}</ul>` : ""}
      ${tab === "attachments" ? `<ul>${i.attachments.map((a) => `<li>${a}</li>`).join("")}</ul><pre class="mono">${i.raw}</pre>` : ""}
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
    <div class="log">${i.discussion.slice().reverse().map((d) => `<div>${d.icon} ${d.ts} - ${d.text}</div>`).join("") || "No logs yet."}</div>
  `;

  pane.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
    i.tab = b.dataset.tab;
    save();
    renderTriage();
  }));
  const headerDetail = pane.querySelector("#header-flag-detail");
  if (headerDetail) {
    pane.querySelectorAll(".header-line.suspicious").forEach((line) => {
      line.addEventListener("mouseenter", () => {
        pane.querySelectorAll(".header-line").forEach((x) => x.classList.remove("active-flag"));
        line.classList.add("active-flag");
        headerDetail.textContent = line.dataset.flag;
      });
      line.addEventListener("mouseleave", () => {
        line.classList.remove("active-flag");
      });
    });
  }
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
    state = { incidents: generateIncidents(55), filters: { room: "all", phishml: "all", priority: "all", status: "all", query: "" }, shiftEndsAt: Date.now() + SHIFT_SECONDS * 1000 };
    selected = state.incidents[0]?.id || null;
    answerKey = false;
    save();
    renderAll();
  });
  document.getElementById("close-modal").addEventListener("click", () => document.getElementById("phishrip-modal").classList.add("hidden"));
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
