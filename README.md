# KnowB4 Phishing Simulator

A practical, browser-based SOC training lab inspired by real workflows in GoPhish and KnowBe4 PhishER.

This simulator is designed for classroom use to help students practice phishing triage, evidence-based decision making, and incident documentation under realistic conditions.

## What This Simulator Includes

- **Role-based login** (Instructor / Student session mode)
- **Dashboard** with live incident and resolution metrics
- **PhishER-style Inbox** with severity/status filtering
- **Incident Investigation Panel** with:
  - Sender and subject analysis
  - SPF/DKIM/DMARC results
  - URL and domain age indicators
  - Header preview and message timeline
  - Risk scoring
- **SOC Response Actions**:
  - Begin Work
  - Mark Benign
  - Quarantine Email
  - Block Sender Domain
  - Run ZAP
  - Escalate to Tier 2
  - Resolve
- **Action Log + Analyst Notes** for audit-ready decision tracking
- **Campaign Builder Module** (template + landing page + group workflow)
- **PICERL-aligned IR Playbook View**
- **One-click Reset Lab** to restore clean training state
- **Scenario packs** (`easy`, `medium`, `hard`) for progressive difficulty
- **Leaderboard + rubric-based scoring** for student assessment
- **CSV report export** for after-class review
- **Timed exam mode** with countdown and student submission lock
- **Instructor-only answer key view** for debrief and grading
- **Attempt history tracking** per student submission
- **Instructor grade release toggle** (hide/reveal assessment grades)
- **PDF report export** (print-ready instructor report)
- **Multi-section support** (A/B/C) with section-specific leaderboard filtering
- **Instructor analytics** for section performance and mistake trends

## Quick Start

No install or build is required.

1. Open `index.html` in any modern browser.
2. Navigate to **PhishER Inbox**.
3. Select an incident and begin triage.
4. Add analyst notes and apply response actions.
5. Use **Reset Lab** to restart for a new class/cohort.

## GitHub Pages Deployment

This repository is configured with a GitHub Actions workflow to publish the simulator to GitHub Pages on every push to `main`.

- Workflow file: `.github/workflows/deploy-pages.yml`
- Expected site URL: `https://tanzimulalam.github.io/PhishER-Simulator/`

If this is your first deployment, ensure in repo settings:

1. `Settings` -> `Pages`
2. Source is set to **GitHub Actions**
3. Wait for the `Deploy static site to GitHub Pages` workflow to complete

## Classroom Usage Model

Recommended 30-45 minute lab:

1. Prioritize incidents by severity.
2. For each incident, determine whether it is phishing or benign.
3. Justify the decision using email authentication, URL/domain intelligence, and message context.
4. Apply the most appropriate containment/response action.
5. Record structured notes as if writing a real SOC ticket.
6. Debrief false positives, true positives, and escalation quality.

## Phase 2 Features

This version adds structured classroom operations:

1. Sign in as instructor or student.
2. Select scenario difficulty pack.
3. Run triage and response actions.
4. Track student scores on the leaderboard.
5. Export incident report as CSV for grading evidence.

## Phase 3 Features

1. Start timed exam windows (instructor-only control).
2. Students can submit exam attempts; submission locks further actions.
3. Exam mode hides answer-like hints for students.
4. Instructor answer key panel shows recommended verdict/action rationale.

## Phase 4 Features

1. Track per-student attempt history at exam submission time.
2. Keep grades hidden from students until instructor releases them.
3. Toggle grade visibility using `Release Grades` / `Hide Grades`.
4. Export print-ready PDF report from the browser.

## Phase 5 Features

1. Assign students to class sections at login.
2. Filter leaderboard and attempt history by section.
3. Track section on all exam submissions.
4. Analytics panel shows section averages and mistake trend counters.

## Realism Upgrade

Inbox and investigation flow now better mirrors operational PhishER handling:

1. Inbox triage includes Reporter, Subject, PhishML, Priority, Status, and Date.
2. Message details use tabbed analysis (Body, Headers, Auth, Attachments).
3. Action sidebar supports assignment, tagging, status updates, PhishRIP, Blocklist, and PhishFlip simulation actions.
4. Discussion thread and action log capture analyst decisions.

## Deep Realism Pass V2

1. Three-pane SOC density layout (Inbox / Message / Action Sidebar) with PhishER-style operational flow.
2. Dynamic PhishML confidence bar with percentage and threat likelihood tiering.
3. Scenario engine now generates 50+ incidents (current: 60) across CEO fraud, quishing, credential harvest, and benign categories.
4. Every incident includes realistic SPF/DKIM/DMARC auth objects and massive raw-header blocks.
5. PhishRIP workflow includes live progress modal and completion counts.
6. Audit/discussion persistence captures every control click with icon, timestamp, and actor attribution.

## Learning Outcomes

By the end of the exercise, students should be able to:

- Differentiate true positives vs false positives quickly
- Interpret SPF, DKIM, and DMARC in context
- Choose proportionate response actions
- Document incident decisions clearly for audit and handoff
- Map phishing triage behavior to PICERL phases

## Project Structure

- `index.html` - Application layout and module views
- `styles.css` - Admin-style simulator UI theme
- `app.js` - Training data, state logic, triage actions, campaign simulation

## Attribution

This simulator is independently implemented and inspired by phishing training workflows from:

- [GoPhish](https://github.com/gophish/gophish)
- [KnowBe4 PhishER](https://www.knowbe4.com/products/phisher)

Brand names and workflow concepts remain the property of their respective owners.

## Roadmap (Phase 2+)

- Instructor/student role-based access
- Scoring engine and rubric export
- Scenario packs (easy/medium/hard)
- Multi-user backend (Node + SQLite)
- CSV/PDF incident report export

## Important Disclaimer

This project is for **authorized security awareness training and simulation only**.
Do not use it to target people or organizations without explicit written permission.
