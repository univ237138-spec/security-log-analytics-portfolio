"""Render the public demo in an isolated browser and record its UI checks."""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'assets'
OUT.mkdir(exist_ok=True)

def ready(page):
    page.get_by_test_id('stApp').wait_for()
    page.locator('[data-testid="stStatusWidget"]').wait_for(state='hidden')
    page.wait_for_function("!document.querySelector('[data-testid=stSkeleton]')")
    page.evaluate('document.fonts.ready')
    page.wait_for_timeout(900)
    assert page.get_by_test_id('stException').count() == 0

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width':1440,'height':1000},device_scale_factor=1)
    page.set_default_timeout(60000)
    page.goto('http://127.0.0.1:8513')
    page.get_by_text('우선 확인할 경보',exact=True).wait_for()
    ready(page)
    expect(page.get_by_test_id('stMetricValue').first).to_have_text('9,125')
    values = page.get_by_test_id('stMetricValue').all_text_contents()
    assert values[:4] == ['9,125','146','76','4'], values
    page.screenshot(path=str(OUT/'overview.png'),full_page=False)
    page.get_by_role('link',name='경보 상세',exact=False).click()
    page.get_by_role('tab',name='사건 타임라인',exact=True).wait_for()
    ready(page)
    page.screenshot(path=str(OUT/'case-detail.png'),full_page=False)
    page.get_by_role('link',name='세션·기준선 탐색',exact=False).click()
    page.get_by_text('세션·기준선 탐색',exact=True).last.wait_for()
    ready(page)
    page.screenshot(path=str(OUT/'session-explorer.png'),full_page=False)
    report = {'status':'passed','isolated_browser':True,'input':'public pseudonymized demo',
              'metrics':values[:4], 'pages_rendered':['overview','alert_detail','session_explorer'],
              'screenshots':['assets/overview.png','assets/case-detail.png','assets/session-explorer.png']}
    (ROOT/'results/ui_validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    browser.close()
print('PASS: public dashboard rendered, aggregates match, three screenshots saved.')
