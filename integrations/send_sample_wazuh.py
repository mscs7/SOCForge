"""Send an example Wazuh alert to SOCForge. Lab-only sample data."""
import json
import os
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
url = os.getenv('SOCFORGE_URL', 'http://127.0.0.1:8080/api/alerts')
key = os.getenv('SOCFORGE_API_KEY', '')
body = (ROOT / 'examples' / 'wazuh_sample.json').read_bytes()
headers = {'Content-Type': 'application/json'}
if key:
    headers['X-API-Key'] = key
request = urllib.request.Request(url, data=body, headers=headers, method='POST')
with urllib.request.urlopen(request, timeout=8) as response:
    print(json.loads(response.read()))
