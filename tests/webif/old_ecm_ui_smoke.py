import os, re, requests, shutil
from playwright.sync_api import sync_playwright

BASE = os.environ.get('TCMG_WEBIF_URL', 'http://127.0.0.1:18080')
S = requests.Session()
r = S.post(BASE + '/login', data={'u': 'admin', 'p': 'secret'}, timeout=10, allow_redirects=False)
if r.status_code not in (200, 302): raise SystemExit(f'login failed: {r.status_code}')
ecm = '817034703264216EB6EFA65A38468DA2AC005F1CC011508CA82E3E4E0F74462096EE21A7F0DD1E57DD46FF3C5133886CB0861005D9E89C'
html = S.get(BASE + '/readers', timeout=10).text
css = S.get(BASE + '/assets/app.css', timeout=10).text
html = re.sub(r"<link[^>]+href=['\"](/assets/app\.css(?:\?[^'\"]*)?)['\"][^>]*>", lambda m: '<style>'+css+'</style>', html, count=1, flags=re.I)
for src in re.findall(r"<script[^>]+src=['\"](/assets/[^'\"]+)['\"][^>]*></script>", html, flags=re.I):
    body = S.get(BASE + src.split('?',1)[0], timeout=10).text
    html = re.sub(r"<script[^>]+src=['\"]"+re.escape(src)+r"(?:\?[^'\"]*)?['\"][^>]*></script>", lambda m, body=body: '<script>'+body+'</script>', html, count=1, flags=re.I)
with sync_playwright() as p:
    exe = shutil.which('chromium') or shutil.which('chromium-browser') or shutil.which('google-chrome')
    browser = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
    page = browser.new_page(viewport={'width': 1200, 'height': 900})
    page.set_content(html, wait_until='domcontentloaded')
    page.wait_for_timeout(150)
    page.locator("button[data-a='add']").first.click()
    page.wait_for_timeout(80)
    assert not page.locator('#rModal').is_hidden()
    assert page.locator('#rCardMaintenanceFields').is_hidden()
    for proto in ('pcsc', 'internal', 'serial'):
        page.locator('#rProtocol').select_option(proto)
        page.wait_for_timeout(30)
        assert not page.locator('#rCardMaintenanceFields').is_hidden(), proto
        assert page.locator('#rMaintMode').input_value() == 'fast_reset', proto
        page.locator('#rMaintMode').select_option('old_ecm')
        assert not page.locator('#rOldSourceWrap').is_hidden(), proto
        assert page.locator('#rOldTrigger').count() == 0, proto
        assert page.locator('#rOldInterval').count() == 0, proto
        assert not page.locator('#rOldSuccessesWrap').is_hidden(), proto
        assert page.locator('#rFastWrap').is_hidden()
        assert page.locator('#rFastIdleWrap').is_hidden()
        page.locator('#rOldSource').select_option('manual')
        assert not page.locator('#rOldEcmWrap').is_hidden(), proto
        assert not page.locator('#rOldSuccessesWrap').is_hidden()
        page.locator('#rOldEcm').fill(ecm)
        assert page.locator('#rOldEcm').input_value() == ecm
        page.locator('#rMaintMode').select_option('fast_reset')
        assert not page.locator('#rFastWrap').is_hidden()
        assert page.locator('#rOldSourceWrap').is_hidden()
        assert page.locator('#rOldEcmWrap').is_hidden()
        assert page.locator('#rOldSuccessesWrap').is_hidden()
    print('OLD_ECM_UI_SMOKE: PASS')
    browser.close()
