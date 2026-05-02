# PhishER Simulator

A browser-based phishing incident response training platform for SOC classrooms, modeled after enterprise triage workflows.

## Features

- Three-pane SOC interface: filters, inbox queue, and triage sidebar
- **Playbook** tab: interactive triage guide (workflow, SPF/DKIM/DMARC, recipes including PhishRIP vs ZAP, dispositions, actions)
- **Analyst notes**: typing no longer triggers T/S/C shortcuts (fixed focus/re-render behavior)
- **URLs**: clean incidents use real vendor homepages; simulated malicious destinations use reserved `.invalid` domains for safe classroom use
- Realistic incident dataset (threat, spam, clean, quishing, surge events)
- PhishML scoring, status lifecycle, audit log, and analyst notes
- Threat actions: PhishRIP, ZAP, PhishFlip, blocklist, and sandbox detonation
- Evidence clipping for OSINT and detonation actions
- Reason-code gated dispositions for grading integrity
- Dashboard analytics (status, disposition, accuracy, neutralization metrics)
- Shift report export for student submission
- Accessibility controls: high contrast mode, quick-start tutorial, optional audio cues
- Persistent lab state via `localStorage` with one-click `Reset Lab`

## How To Use (Instructor Flow)

1. Open `index.html` in a modern browser.
2. Let students triage incidents from `Inbox`.
3. Require disposition + reason code + evidence-backed notes.
4. Use `Instructor Key` for guided debrief in `Headers`/`Auth`.
5. Review `Dashboard` performance metrics.
6. Download `Shift Report` for grading records.
7. Use `Reset Lab` between cohorts or practical rounds.

## Technical Stack

- Vanilla JavaScript (state, rendering, simulation logic)
- CSS Grid + responsive CSS (three-pane layout and dashboard)
- Browser LocalStorage (persistence and session continuity)

## GitHub Pages

This is a static app. Deploy directly with GitHub Pages:

1. Push to `main`.
2. In repository settings, set Pages source to GitHub Actions.
3. Use the existing workflow in `.github/workflows/deploy-pages.yml`.

## Disclaimer

For authorized education and simulation only. Do not use for unauthorized testing or real-world malicious activity.
