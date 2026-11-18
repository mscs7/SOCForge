# SOCForge execution plan (no manual testing required to review this release)

## Release 1.0 — DELIVERED AND AUTOMATICALLY TESTED

**Goal:** Recruiter-demonstrable SOC alert triage and automation workflow.

- Ingestion API for Wazuh-shaped JSON and generic security events
- SQLite persistence, idempotency by event ID, basic incident correlation
- Explainable risk score, severity, source-IP classification and ATT&CK hypotheses
- Case management, analyst assignment, notes, audit trail and case-report export
- Safe two-step simulated containment approval (never executes host actions)
- Optional n8n outbound webhook plus importable workflow template
- Optional Wazuh Manager Integrator script; Wazuh real-world connection still requires your deployment
- Polished, working dashboard with 9 sample alerts becoming 3 cases
- 8 automated API test cases and browser UI smoke test

## Release 1.1 — REAL WAZUH LAB VALIDATION (optional)

Run SOCForge and an already-approved Wazuh Manager/agent in the same lab. Add the custom integration, generate benign login/administration telemetry, and capture Wazuh-to-SOCForge screenshots. Verify real alert field coverage before claiming a live integration.

## Release 1.2 — n8n WORKFLOW VALIDATION (optional)

Import and publish the example workflow in an n8n instance. Confirm a real notification is received, verify retries/errors and add a non-disruptive analyst notification. Do not claim this step completed until demonstrated with the actual n8n instance.

## Release 1.3 — Azure SOC LAB (optional)

Create a low-cost Sentinel workspace, set cloud-budget alerts, learn KQL and analytics rules, and implement an incident playbook using Logic Apps. Separate Azure event telemetry from simulation data. **No Sentinel integration is shipped in 1.0**.

## Portfolio publishing

1. Create a GitHub repository called `socforge` and upload the source code, README, MIT license, synthetic examples and screenshots.
2. Do **not** commit `data/`, `.env`, API keys, real incident logs or customer data.
3. Publish a portfolio project case study using `docs/PORTFOLIO_CONTENT.md`, screenshots and an accurate capability table.
4. Link to GitHub. If you later host an interactive frontend, keep the real backend on a secured server; GitHub Pages alone cannot execute this Python backend.

## SOC-focused CV (final stage)

Update the SOC CV **only** with completed and verified work. Start with the actual current role, investigation experience and previous Wazuh/Splunk/n8n labs. Add SOCForge as a *personal laboratory project* using the bullet points in `docs/SOC_CV_BULLETS.md`. Do not turn lab experience into fictional production SOC operations.

## Scope and constraints

- This release is a local lab and a public code repository candidate, not an enterprise deployment.
- Classification and scoring are explainable heuristics, not AI detections or verified threat intelligence.
- Approval actions are simulated with a permanent audit trail; no real endpoint remediation.
- External Wazuh, n8n and Azure systems are **not required** for the built-in working demo.
