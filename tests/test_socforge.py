from __future__ import annotations

import json
from pathlib import Path
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient
from app.main import create_app

BASE = Path(__file__).resolve().parents[1]

@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(db_path=str(tmp_path / "socforge-test.db"), api_key="", n8n_url="")) as c:
        yield c


def test_health_and_empty(client):
    r = client.get('/api/health')
    assert r.status_code == 200
    assert r.json()['real_containment_enabled'] is False
    assert client.get('/api/metrics').json()['total_alerts'] == 0
    assert len(client.get('/api/activity').json()) == 7
    assert client.get('/').status_code == 200
    assert 'SOCForge' in client.get('/').text
    assert client.get('/assets/app.js').status_code == 200
    assert client.get('/assets/unknown').status_code == 404


def test_demo_end_to_end(client):
    r = client.post('/api/demo/load')
    assert r.status_code == 200
    assert r.json()['accepted'] == 9
    assert r.json()['incidents'] == 3
    m = client.get('/api/metrics').json()
    assert m['total_alerts'] == 9
    assert m['open_incidents'] == 3
    assert m['urgent_incidents'] >= 2
    incidents = client.get('/api/incidents').json()
    assert len(incidents) == 3
    endpoint = next(x for x in incidents if x['host'] == 'SALES-WIN11')
    assert endpoint['severity'] == 'critical'
    assert endpoint['alert_count'] == 4
    detail = client.get(f"/api/incidents/{endpoint['id']}").json()
    assert len(detail['alerts']) == 4
    assert {'T1059', 'T1136', 'T1098'}.issubset(set(detail['techniques']))
    assert detail['playbook']
    assert any('not checked' in item['context'] for item in detail['indicator_context'])
    assert client.post('/api/demo/load').json()['duplicates'] == 9
    assert client.get('/api/metrics').json()['total_alerts'] == 9
    assert client.get('/api/incidents?severity=critical').json()
    assert len(client.get('/api/incidents?search=SALES').json()) == 1


def test_case_lifecycle_notes_and_safe_simulation(client):
    client.post('/api/demo/load')
    id = client.get('/api/incidents').json()[0]['id']
    assert client.post(f'/api/incidents/{id}/actions', json={'action': 'approve_simulation'}).status_code == 409
    assert client.patch(f'/api/incidents/{id}', json={'status': 'investigating', 'analyst': 'SOC Analyst'}).status_code == 200
    assert client.post(f'/api/incidents/{id}/notes', json={'author': 'Analyst', 'content': 'Reviewed relevant endpoint logs.'}).status_code == 200
    assert client.post(f'/api/incidents/{id}/actions', json={'action':'request_containment'}).status_code == 200
    assert client.post(f'/api/incidents/{id}/actions', json={'action':'approve_simulation'}).status_code == 200
    detail = client.get(f'/api/incidents/{id}').json()
    assert detail['status'] == 'contained'
    assert detail['containment_simulated'] is True
    assert len(detail['notes']) == 1
    assert any('NO real blocks' in a['description'] for a in detail['audit'])
    report = client.get(f'/api/incidents/{id}/report')
    assert report.status_code == 200
    assert 'not a forensic finding' in report.text.lower()
    assert 'Reviewed relevant endpoint logs.' in report.text
    assert 'simulated' in report.text.lower()


def test_wazuh_ingest_and_dedupe(client):
    sample = json.loads((BASE/'examples/wazuh_sample.json').read_text())
    r = client.post('/api/alerts', json=sample)
    assert r.status_code == 200 and r.json()['accepted'] == 1
    r2 = client.post('/api/alerts', json=sample)
    assert r2.json()['duplicates'] == 1
    detail = client.get('/api/incidents').json()[0]
    assert detail['family'] == 'authentication'
    assert detail['host'] == 'DEMO-LINUX'
    assert client.get(f"/api/incidents/{detail['id']}").json()['alerts'][0]['source'] == 'wazuh'


def test_generic_batch_and_validation(client):
    items = [{'id':'x1','host':'X','category':'network_scan','level':5,'title':'Scan observed'},
             {'id':'x2','host':'X','category':'network_scan','level':7,'title':'Second scan'}]
    r = client.post('/api/alerts', json=items)
    assert r.json()['accepted'] == 2
    assert client.get('/api/incidents').json()[0]['alert_count'] == 2
    assert client.post('/api/alerts', json=[]).status_code == 422
    assert client.post('/api/alerts', content='bad json', headers={'Content-Type':'application/json'}).status_code == 400
    assert client.post('/api/alerts', json=[5]).status_code == 422
    assert client.post('/api/alerts', json=[{'level': 'not-numeric'}]).status_code == 422
    assert client.get('/api/incidents?severity=invalid').status_code == 422
    assert client.get('/api/incidents/9999').status_code == 404
    assert client.post('/api/demo/reset', json={'confirm':'no'}).status_code == 422


def test_reset_demo_preserves_live(client):
    client.post('/api/demo/load')
    live = {'id':'production1','host':'LIVE-SERVER','category':'authentication_failure', 'level':5, 'title':'Repeated failures'}
    client.post('/api/alerts', json=live)
    assert client.get('/api/metrics').json()['total_incidents'] == 4
    res = client.post('/api/demo/reset', json={'confirm':'RESET_DEMO'}).json()
    assert res['alerts_removed'] == 9 and res['incidents_removed'] == 3
    assert client.get('/api/metrics').json()['total_alerts'] == 1
    assert client.get('/api/incidents').json()[0]['host'] == 'LIVE-SERVER'


def test_key_protects_ingest(tmp_path):
    with TestClient(create_app(db_path=str(tmp_path/'key.db'), api_key='super-secret', n8n_url='')) as c:
        alert = {'id':'k1','host':'HOST1', 'title':'Test'}
        assert c.post('/api/alerts', json=alert).status_code == 401
        assert c.post('/api/alerts', headers={'X-API-Key':'wrong'}, json=alert).status_code == 401
        assert c.post('/api/alerts', headers={'X-API-Key':'super-secret'}, json=alert).status_code == 200


def test_optional_n8n_webhook_delivery(tmp_path):
    received = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            received.append(json.loads(body))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
        def log_message(self, *args):
            pass
    server = HTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TestClient(create_app(db_path=str(tmp_path/'notify.db'), n8n_url=f'http://127.0.0.1:{server.server_port}/webhook/abc', api_key='')) as c:
            response = c.post('/api/alerts', json={'id':'n1','host':'S1', 'title':'Malware detected', 'category':'malware_detection','level':12})
            assert response.status_code == 200
            assert received and received[0]['event'] == 'socforge.incident'
            assert c.get('/api/automation').json()[0]['status'] == 'sent'
            c.post('/api/alerts', json={'id':'n1','host':'S1', 'title':'Malware detected', 'category':'malware_detection','level':12})
            assert len(received) == 1
    finally:
        server.shutdown()
        thread.join(timeout=2)
