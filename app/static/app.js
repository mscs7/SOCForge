'use strict';

const state = { incidents: [], metrics: null, health: null, selected: null, view: 'overview' };
const $ = (id) => document.getElementById(id);
const create = (tag, cls, value) => {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (value !== undefined) el.textContent = String(value);
  return el;
};
const capitalize = (s) => String(s || '').replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
const caseId = (id) => `INC-${String(id).padStart(4, '0')}`;
const when = (date) => {
  const parsed = new Date(date);
  return Number.isNaN(parsed.getTime()) ? date : parsed.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
};

let toastTimeout;
function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('active');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => el.classList.remove('active'), 4300);
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
  if (!response.ok) {
    let body = {};
    try { body = await response.json(); } catch (err) { /* ignore non-JSON error */ }
    throw new Error(typeof body.detail === 'string' ? body.detail : `Request failed (HTTP ${response.status})`);
  }
  return response.json();
}

function buttonLoading(button, busy, label) {
  button.disabled = busy;
  if (busy) { button.dataset.label = button.textContent; button.textContent = label || 'Working…'; }
  else if (button.dataset.label) { button.textContent = button.dataset.label; delete button.dataset.label; }
}

function severityTag(severity) {
  return create('span', `severity-tag ${severity}`, capitalize(severity));
}
function statusTag(status) {
  return create('span', `status-tag ${status}`, capitalize(status));
}

function incidentTable(items, elementId, limit = 0) {
  const container = $(elementId);
  container.replaceChildren();
  const data = limit ? items.slice(0, limit) : items;
  if (!data.length) {
    const empty = create('div', 'empty-table');
    empty.append(create('strong', null, 'Nothing in the queue yet'), create('span', null, 'Load the demo scenarios to see the alert triage workflow.'));
    container.append(empty);
    return;
  }
  const table = create('table', 'incidents-table');
  const thead = create('thead');
  const tr = create('tr');
  ['INCIDENT', 'SEVERITY', 'STATUS', 'ALERTS', 'LAST SEEN'].forEach(name => tr.append(create('th', null, name)));
  thead.append(tr);
  const tbody = create('tbody');
  data.forEach(item => {
    const row = create('tr', 'case-row');
    row.tabIndex = 0;
    row.setAttribute('role', 'button');
    row.setAttribute('aria-label', `Open ${caseId(item.id)}`);
    row.addEventListener('click', () => openIncident(item.id));
    row.addEventListener('keydown', evt => { if (evt.key === 'Enter' || evt.key === ' ') { evt.preventDefault(); openIncident(item.id); }});
    const idCell = create('td');
    idCell.append(create('span', 'case-id', caseId(item.id)), create('div', 'case-title', item.title), create('div', 'case-host', item.host));
    const severityCell = create('td'); severityCell.append(severityTag(item.severity));
    const statusCell = create('td'); statusCell.append(statusTag(item.status));
    const countCell = create('td', null, item.alert_count);
    const timeCell = create('td', null, when(item.last_seen));
    row.append(idCell, severityCell, statusCell, countCell, timeCell);
    tbody.append(row);
  });
  table.append(thead, tbody);
  container.append(table);
}

function renderChart(activity) {
  const el = $('activity-chart');
  el.replaceChildren();
  const max = Math.max(1, ...activity.map(x => x.alerts));
  activity.forEach(item => {
    const col = create('div', 'bar-col');
    const value = create('div', 'bar-value', item.alerts || '');
    const wrap = create('div', 'bar-wrap');
    const bar = create('div', `bar ${item.alerts ? '' : 'bar-zero'}`);
    bar.style.height = `${Math.max(item.alerts ? 7 : 3, (item.alerts / max) * 110)}px`;
    bar.title = `${item.day}: ${item.alerts} alerts`;
    wrap.append(bar);
    const label = create('div', 'bar-label', new Date(`${item.day}T12:00:00Z`).toLocaleDateString(undefined, { weekday: 'short' }));
    col.append(value, wrap, label);
    el.append(col);
  });
}

function renderAutomation(logs) {
  const el = $('automation-logs');
  el.replaceChildren();
  if (!logs.length) {
    el.className = 'automation-empty';
    el.textContent = state.health?.n8n_configured ? 'n8n is configured. No notifications have been delivered yet.' :
      'No automation deliveries. Optional n8n webhook integration is off by default.';
    return;
  }
  el.className = 'automation-list';
  logs.forEach(item => {
    const row = create('div', 'automation-entry');
    const text = create('div');
    text.append(create('strong', null, `${caseId(item.incident_id)} · ${item.destination}`), create('small', null, `${when(item.event_time)} · ${item.message}`));
    row.append(text, create('span', item.status, capitalize(item.status)));
    el.append(row);
  });
}

function render() {
  const m = state.metrics;
  if (!m) return;
  $('metric-open').textContent = m.open_incidents;
  $('metric-urgent').textContent = m.urgent_incidents;
  $('metric-alerts').textContent = m.total_alerts;
  $('metric-new').textContent = m.awaiting_triage;
  $('nav-queue').textContent = m.open_incidents;
  incidentTable(state.incidents, 'overview-incidents', 5);
  renderFiltered();
  $('n8n-status').textContent = state.health?.n8n_configured ? 'ON' : 'OFF';
  $('n8n-status').className = state.health?.n8n_configured ? 'ops-on' : 'ops-off';
  $('sync-time').textContent = `Updated ${new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`;
}

function renderFiltered() {
  const search = $('search-input').value.toLowerCase().trim();
  const severity = $('severity-filter').value;
  const status = $('status-filter').value;
  const items = state.incidents.filter(item => (!search || `${item.title} ${item.host} ${caseId(item.id)}`.toLowerCase().includes(search)) &&
    (!severity || item.severity === severity) && (!status || item.status === status));
  $('case-count').textContent = `${items.length} case${items.length === 1 ? '' : 's'}`;
  incidentTable(items, 'all-incidents');
}

async function refresh() {
  const [health, metrics, incidents, activity, automation] = await Promise.all([
    api('/api/health'), api('/api/metrics'), api('/api/incidents'), api('/api/activity'), api('/api/automation'),
  ]);
  state.health = health;
  state.metrics = metrics;
  state.incidents = incidents;
  $('connection').classList.remove('error');
  $('connection').replaceChildren(create('span', 'live-dot'), document.createTextNode(' Service online'));
  renderChart(activity);
  renderAutomation(automation);
  render();
}

function switchView(view) {
  if (!['overview','incidents','automation','about'].includes(view)) return;
  state.view = view;
  document.querySelectorAll('.view').forEach(el => { el.hidden = el.id !== `view-${view}`; });
  document.querySelectorAll('.nav-link').forEach(btn => { btn.classList.toggle('active', btn.dataset.view === view); });
  $('top-view').textContent = capitalize(view === 'incidents' ? 'Incident queue' : view === 'about' ? 'Lab guide' : view);
  const label = {
    overview: ['See the signal.', 'Investigate with context.', 'From raw security alerts to prioritised incidents, investigation trails and approval-only response simulations.'],
    incidents: ['Clear the noise.', 'Focus on the incidents.', 'Review and manage your security investigations in one place.'],
    automation: ['Orchestrate safely.', 'Keep analysts in control.', 'See outbound webhook delivery and the safe automation boundary.'],
    about: ['Built to learn.', 'Designed for evidence.', 'How this local-first SOC triage lab works, and what it intentionally does not do.'],
  }[view];
  $('page-title').replaceChildren(document.createTextNode(label[0]), create('br'), create('span', null, label[1]));
  $('page-subtitle').textContent = label[2];
}

function listOfText(elId, items, tag = 'li') {
  const el = $(elId);
  el.replaceChildren();
  items.forEach(text => el.append(create(tag, null, text)));
}

async function openIncident(id) {
  try {
    const inc = await api(`/api/incidents/${id}`);
    state.selected = inc;
    $('drawer-id').textContent = caseId(inc.id);
    $('drawer-title').textContent = inc.title;
    $('drawer-host').textContent = `${inc.host} · ${capitalize(inc.family)} · ${when(inc.last_seen)}`;
    $('drawer-severity').replaceWith(severityTag(inc.severity));
    $('drawer-status').replaceWith(statusTag(inc.status));
    // Preserve stable IDs for successive drawer opens.
    document.querySelector('.drawer-tags .severity-tag').id = 'drawer-severity';
    document.querySelector('.drawer-tags .status-tag').id = 'drawer-status';
    $('drawer-score').textContent = `Risk score: ${inc.score}/100`;
    $('drawer-reasons').replaceChildren();
    listOfText('drawer-reasons', inc.risk_reasons);
    $('evidence-count').textContent = `${inc.alerts.length} ALERTS`;
    const timeline = $('drawer-timeline'); timeline.replaceChildren();
    inc.alerts.forEach(alert => {
      const item = create('div', 'timeline-item');
      const label = create('strong', null, `${alert.title}`);
      const meta = create('small', null, `${when(alert.event_time)} · ${alert.source} · rule ${alert.rule_id} · level ${alert.level}`);
      const details = create('div', 'timeline-desc', `${alert.username ? `User: ${alert.username} · ` : ''}${alert.source_ip ? `Source: ${alert.source_ip}` : 'No source IP supplied'}`);
      item.append(label, meta, details);
      timeline.append(item);
    });
    const indicators = $('drawer-indicators'); indicators.replaceChildren();
    if (!inc.indicator_context.length) indicators.append(create('div', 'muted', 'No source IP indicators supplied.'));
    inc.indicator_context.forEach(ind => {
      const row = create('div', 'indicator');
      row.append(create('strong', null, ind.value), create('small', null, ind.context));
      indicators.append(row);
    });
    const techniques = $('drawer-techniques'); techniques.replaceChildren();
    if (!inc.techniques.length) techniques.append(create('span', 'muted', 'No technique reference assigned'));
    inc.techniques.forEach(code => techniques.append(create('span', 'technique', code)));
    listOfText('drawer-playbook', inc.playbook);
    $('drawer-status-input').value = inc.status;
    $('drawer-analyst').value = inc.analyst === 'Unassigned' ? '' : inc.analyst;
    $('drawer-note-input').value = '';
    const notes = $('drawer-notes'); notes.replaceChildren();
    if (!inc.notes.length) notes.append(create('div', 'muted', 'No investigation notes yet.'));
    inc.notes.forEach(n => {
      const item = create('div', 'notes-item');
      item.append(create('strong', null, n.author), create('small', null, when(n.created_at)), create('p', null, n.content));
      notes.append(item);
    });
    const audit = $('drawer-audit'); audit.replaceChildren();
    inc.audit.forEach(entry => {
      const item = create('div', 'audit-item');
      item.append(create('strong', null, capitalize(entry.event_type)), document.createTextNode(entry.description), create('small', null, `${entry.actor} · ${when(entry.event_time)}`));
      audit.append(item);
    });
    $('request-containment').disabled = inc.containment_requested;
    $('approve-containment').disabled = !inc.containment_requested || inc.containment_simulated;
    $('simulation-state').textContent = inc.containment_simulated ? 'Approved simulation recorded. No real action executed.' :
       inc.containment_requested ? 'Simulation requested; analyst approval pending.' : 'No simulation requested.';
    $('download-report').href = `/api/incidents/${inc.id}/report`;
    $('overlay').hidden = false;
    $('incident-drawer').hidden = false;
    $('close-drawer').focus();
  } catch (err) { toast(err.message); }
}

function closeDrawer() {
  $('overlay').hidden = true;
  $('incident-drawer').hidden = true;
  state.selected = null;
}

async function triageSave() {
  if (!state.selected) return;
  const analyst = $('drawer-analyst').value.trim() || 'Unassigned';
  try {
    await api(`/api/incidents/${state.selected.id}`, { method: 'PATCH', body: JSON.stringify({ status: $('drawer-status-input').value, analyst }) });
    await refresh();
    await openIncident(state.selected.id);
    toast('Case changes saved');
  } catch (err) { toast(err.message); }
}

async function noteSave() {
  if (!state.selected) return;
  const note = $('drawer-note-input').value.trim();
  if (note.length < 3) return toast('Enter at least 3 characters for the investigation note');
  try {
    await api(`/api/incidents/${state.selected.id}/notes`, { method: 'POST', body: JSON.stringify({ content: note, author: 'Analyst' }) });
    await openIncident(state.selected.id);
    toast('Investigation note saved');
  } catch (err) { toast(err.message); }
}

async function actionSubmit(action) {
  if (!state.selected) return;
  if (action === 'approve_simulation' && !window.confirm('Approve a containment SIMULATION? No network or endpoint action will be performed.')) return;
  try {
    const id = state.selected.id;
    const result = await api(`/api/incidents/${id}/actions`, { method: 'POST', body: JSON.stringify({ action }) });
    await refresh();
    await openIncident(id);
    toast(result.message);
  } catch (err) { toast(err.message); }
}

async function loadDemo() {
  const button = $('load-demo');
  buttonLoading(button, true, 'Importing scenarios…');
  try {
    const result = await api('/api/demo/load', { method: 'POST' });
    await refresh();
    toast(result.accepted ? `${result.accepted} demo alerts imported · ${result.incidents} total incidents` : 'Demo scenarios are already loaded');
    switchView('incidents');
  } catch (err) { toast(`Demo load failed: ${err.message}`); }
  finally { buttonLoading(button, false); }
}

async function resetDemo() {
  if (!window.confirm('Delete ONLY synthetic demo alerts? Other ingested data will be kept.')) return;
  try {
    const result = await api('/api/demo/reset', { method: 'POST', body: JSON.stringify({ confirm: 'RESET_DEMO' }) });
    await refresh();
    toast(`Removed ${result.alerts_removed} demo alerts and ${result.incidents_removed} demo incidents`);
    switchView('overview');
  } catch (err) { toast(err.message); }
}

async function main() {
  document.querySelectorAll('.nav-link').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
  document.querySelectorAll('[data-switch]').forEach(button => button.addEventListener('click', () => switchView(button.dataset.switch)));
  $('load-demo').addEventListener('click', loadDemo);
  $('refresh-data').addEventListener('click', async () => { try { await refresh(); toast('Dashboard refreshed'); } catch (err) { toast(err.message); }});
  $('reset-demo').addEventListener('click', resetDemo);
  $('search-input').addEventListener('input', renderFiltered);
  $('severity-filter').addEventListener('change', renderFiltered);
  $('status-filter').addEventListener('change', renderFiltered);
  $('close-drawer').addEventListener('click', closeDrawer);
  $('overlay').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', event => { if (event.key === 'Escape' && !$('incident-drawer').hidden) closeDrawer(); });
  $('save-triage').addEventListener('click', triageSave);
  $('add-note').addEventListener('click', noteSave);
  $('request-containment').addEventListener('click', () => actionSubmit('request_containment'));
  $('approve-containment').addEventListener('click', () => actionSubmit('approve_simulation'));
  try { await refresh(); } catch (err) {
    $('connection').classList.add('error');
    $('connection').textContent = 'Backend offline';
    toast(`Unable to connect to backend: ${err.message}`);
  }
}
main();
