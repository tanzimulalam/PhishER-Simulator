# KnowB4 Phishing Simulator

A practical, browser-based SOC training lab inspired by real workflows in GoPhish and KnowBe4 PhishER.

This simulator is designed for classroom use to help students practice phishing triage, evidence-based decision making, and incident documentation under realistic conditions.

## What This Simulator Includes

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
