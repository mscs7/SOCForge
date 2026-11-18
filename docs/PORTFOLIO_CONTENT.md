# Portfolio project text — copy after publishing code

## SOCForge — Automated SOC Alert Triage & Incident Response Lab

**Category:** SOC Automation · Detection Engineering · Security Tooling

**Status:** Functional local portfolio prototype (tested with synthetic data)

**Technology:** Python, FastAPI, SQLite, JavaScript, HTML/CSS, REST APIs, MITRE ATT&CK; optional Wazuh and n8n integration adapters.

### Short card description

Built a local SOC triage application that ingests security alerts, groups related activity into prioritised incidents, and supports analyst investigation, case management and safe response simulations. Includes Wazuh-format ingestion, an optional n8n webhook, an audit trail and reproducible synthetic attack scenarios.

### Full case study

SOCForge was built with AI-assisted development as a reproducible lab project to demonstrate how a SOC analyst can move from large numbers of individual detection events to a smaller, meaningful investigation queue. The application normalises Wazuh-shaped and generic JSON alerts, deduplicates repeated events, correlates activity by host and incident family, and provides transparent risk-score explanations.

The analyst interface includes an incident timeline, source-IP context, ATT&CK technique references, case ownership, status transitions, investigation notes, a simulated containment approval workflow and downloadable Markdown incident reports. Local automation can forward newly created or escalated incidents to an optional n8n webhook. No disruptive response actions are executed.

For reproducible demonstration, The project includes nine **synthetic** alerts illustrating Windows account manipulation, Linux authentication failures and web application access-control patterns. The alerts correlate into three incident cases. The local API integration tests and browser interaction flow have been exercised successfully. Real Wazuh and n8n adapters are supplied but require separate lab deployment before claiming live integration.

### Evidence to display

- Screenshot: `screenshots/05_overview_with_data.png` — triage dashboard with three synthetic cases
- Screenshot: `screenshots/03_incident_investigation.png` — incident evidence timeline and risk factors
- Screenshot: `screenshots/04_approved_simulation.png` — approval-only simulated response
- GitHub: add your repository URL after you actually publish it

### Interview explanation (30 seconds)

"I built SOCForge as an independent SOC automation lab to bridge my penetration-testing and incident-investigation experience with detection engineering. It receives alerts, normalises and correlates them, produces explainable prioritisation and gives an analyst a case workflow. I tested its API, case lifecycle and dashboard with nine synthetic alerts forming three incidents. It also includes an optional Wazuh intake adapter and an n8n notification template, without pretending to be a production SOAR."

### Important portfolio accuracy

Do not say "Microsoft Sentinel integrated", "AI-powered threat intelligence", "SOC environment used in production", "automatic isolation of endpoints", or "deployed at a customer". None are implemented or verified in this release.
