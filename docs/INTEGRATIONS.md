# Optional integrations (not required for SOCForge demo)

## 1. Wazuh alert ingestion

**Goal:** Have a Wazuh Manager forward real Wazuh JSON alerts into SOCForge's `POST /api/alerts` endpoint.

Wazuh's official Integrator executes custom scripts whose names begin with `custom-`. It passes three arguments: alert file path, configured API key and configured hook URL. SOCForge includes `integrations/custom-socforge`, implemented using only Python's standard library.

Tested locally with a synthetic Wazuh-shaped JSON alert. **Not verified on a deployed Wazuh manager.**

### Setup on an authorised Linux lab machine

1. Run SOCForge on the **same machine** as Wazuh Manager or on a trusted, appropriately secured internal route. By default SOCForge only listens on loopback, so a separate remote manager cannot reach it unless you configure a trusted tunnel/proxy. Don't expose the app publicly.
2. Configure a random API key for SOCForge (for example, in your shell before starting: `export SOCFORGE_API_KEY='YOUR_RANDOM_SECRET'`). For Docker, put the variable in a local `.env` copied from `.env.example` and restart Docker Compose. **Never commit secrets to GitHub.**
3. Copy `integrations/custom-socforge` to `/var/ossec/integrations/custom-socforge` on the manager and make it executable, following Wazuh's permission guidance:

```bash
sudo cp integrations/custom-socforge /var/ossec/integrations/custom-socforge
sudo chown root:wazuh /var/ossec/integrations/custom-socforge
sudo chmod 750 /var/ossec/integrations/custom-socforge
```

4. Add the `<integration>` block from `integrations/wazuh_ossec_example.xml` inside your manager's existing `<ossec_config>` in `/var/ossec/etc/ossec.conf`. Use a real accessible URL, e.g. `http://127.0.0.1:8080/api/alerts` if SOCForge runs on that manager. Paste the **same** API key from step 2.
5. Back up `ossec.conf` before editing it. Validate the XML and restart the manager using your standard change procedure.
6. Generate a benign test log in an authorised lab and verify the alert appears in SOCForge's Incident Queue. Do not perform this against client environments without written approval.

To test the API *without* Wazuh installed, start SOCForge and run:

```bash
python integrations/send_sample_wazuh.py
```

A synthetic Wazuh event is provided in `examples/wazuh_sample.json`.

Sources: https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html and https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html

## 2. n8n notification workflow

**Goal:** Deliver a SOCForge incident notification when a new incident is created or its priority changes.

1. Import `integrations/n8n_socforge_workflow.json` into n8n.
2. Check that the three nodes exist: **Webhook → Code → Respond to Webhook**.
3. Publish/activate the workflow in n8n. Use the **Production URL** from the Webhook node (not its temporary Test URL).
4. Set `SOCFORGE_N8N_WEBHOOK_URL` to that URL in your environment. Restart SOCForge.
5. POST a new alert (or use a *new* demo dataset) and open the Automation tab. A success or failure delivery status should appear. Existing demo event IDs are deduplicated and won't re-notify until replaced.
6. Optionally add a Discord/Teams/email notification node **after** the Code node. Configure credentials locally in n8n and avoid sending raw logs/PII to chat platforms.

The included n8n workflow is a portable **template**, not a deployed production automation. Its behaviour with your particular n8n version and credentials still needs verification. The app's outbound JSON HTTP logic has been tested against a local mock receiver.

n8n webhook docs: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/

### Notification schema

```json
{
  "event": "socforge.incident",
  "incident_id": 1,
  "title": "Suspicious endpoint / account activity on SALES-WIN11",
  "severity": "critical",
  "risk_score": 100,
  "mode": "lab",
  "action": "triage_required"
}
```

## 3. Azure / Microsoft Sentinel: roadmap, NOT implemented

For a future Azure SOC extension, use Microsoft Sentinel and Log Analytics with **KQL** to investigate security events, then deliver approved incident notifications to the SOCForge ingestion API through a separately authenticated integration. Microsoft Sentinel playbooks are built using Azure Logic Apps.

Do **not** describe this version of SOCForge as integrated with Azure, Sentinel, Microsoft Defender XDR or production SOAR. They have not been built or verified here.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/automation/run-playbooks
