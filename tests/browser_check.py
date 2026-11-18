"""Browser smoke-test UI against real FastAPI TestClient using an in-process fetch bridge.
The container Chromium policy blocks all HTTP navigation, so we inject the HTML and
route browser fetches into FastAPI's ASGI TestClient instead of opening localhost.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from app.main import create_app

ROOT=Path(__file__).resolve().parents[1]

with TemporaryDirectory() as temp:
    with TestClient(create_app(db_path=str(Path(temp)/'browser_test.db'),api_key='',n8n_url='')) as client:
        def fetch_bridge(path, options):
            method=(options or {}).get('method','GET')
            body=(options or {}).get('body')
            response=client.request(method,path,content=body,headers={'Content-Type':'application/json'})
            return {'status': response.status_code, 'body':response.text}
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
            page=browser.new_page(viewport={'width':1440,'height':980},device_scale_factor=1)
            errors=[]
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.expose_function('socForgeFetchBridge',fetch_bridge)
            page.set_content((ROOT/'app/static/index.html').read_text().replace('<link rel="stylesheet" href="/assets/app.css">','').replace('<script src="/assets/app.js" defer></script>',''),wait_until='load')
            page.add_style_tag(content=(ROOT/'app/static/app.css').read_text())
            page.evaluate('''() => {
                window.fetch = async (path, options = {}) => {
                    const result = await window.socForgeFetchBridge(path, options);
                    return new Response(result.body, {status: result.status, headers:{'Content-Type':'application/json'}});
                };
            }''')
            page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
            page.wait_for_function("document.querySelector('#connection').textContent.includes('Service online')",timeout=12000)
            page.screenshot(path=str(ROOT/'screenshots'/'01_empty_dashboard.png'),full_page=True)
            page.get_by_role('button',name='Load demo scenarios').click()
            page.wait_for_function("document.querySelector('#metric-alerts').textContent === '9'",timeout=15000)
            assert page.locator('#case-count').inner_text()=='3 cases'
            page.locator('#toast').evaluate("e => { e.classList.remove('active'); e.style.display = 'none'; }")
            page.screenshot(path=str(ROOT/'screenshots'/'02_incident_queue.png'),full_page=True)
            page.locator('#all-incidents tr.case-row').first.click()
            page.wait_for_selector('#incident-drawer:not([hidden])')
            assert page.locator('#drawer-title').inner_text()
            page.locator('#toast').evaluate("e => { e.classList.remove('active'); e.style.display = 'none'; }")
            page.screenshot(path=str(ROOT/'screenshots'/'03_incident_investigation.png'),full_page=True)
            page.locator('#drawer-status-input').select_option('investigating')
            page.locator('#drawer-analyst').fill('SOC Analyst')
            page.locator('#save-triage').click()
            page.wait_for_function("document.querySelector('#drawer-status').textContent.trim().toLowerCase()==='investigating'",timeout=12000)
            page.locator('#drawer-note-input').fill('Reviewed event correlation and validated relevant log sources.')
            page.locator('#add-note').click()
            page.wait_for_function("document.querySelector('#drawer-notes').textContent.includes('Reviewed event correlation')",timeout=12000)
            page.locator('#request-containment').click()
            page.wait_for_function("document.querySelector('#approve-containment').disabled===false",timeout=12000)
            page.once('dialog', lambda dialog: dialog.accept())
            page.locator('#approve-containment').click()
            page.wait_for_function("document.querySelector('#drawer-status').textContent.trim().toLowerCase()==='contained'",timeout=12000)
            assert 'No real action executed' in page.locator('#simulation-state').inner_text()
            page.locator('#toast').evaluate("e => { e.classList.remove('active'); e.style.display = 'none'; }")
            page.screenshot(path=str(ROOT/'screenshots'/'04_approved_simulation.png'),full_page=True)
            page.locator('#close-drawer').click()
            page.locator('[data-view=overview]').click()
            page.locator('#toast').evaluate("e => { e.classList.remove('active'); e.style.display = 'none'; }")
            page.screenshot(path=str(ROOT/'screenshots'/'05_overview_with_data.png'),full_page=True)
            assert not errors,errors
            print('Browser smoke test PASSED: UI, demo ingest, incident drawer, triage, notes, simulation; screenshots saved')
            browser.close()
