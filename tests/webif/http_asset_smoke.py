import os
import re
import sys
import requests

BASE = os.environ.get('TCMG_WEBIF_URL', 'http://127.0.0.1:18080').rstrip('/')
USER = os.environ.get('TCMG_WEBIF_USER', 'admin')
PASSWORD = os.environ.get('TCMG_WEBIF_PASS', 'secret')
PAGES = ['/status', '/users', '/readers', '/livelog', '/config', '/failban', '/files', '/tvcas', '/power']
FAILS = []


def ok(name, cond, detail=''):
    print(('PASS ' if cond else 'FAIL ') + name + ((' -> ' + str(detail)) if not cond else ''))
    if not cond:
        FAILS.append(name)


def is_utf8(data):
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


s = requests.Session()
r = s.post(BASE + '/login', data={'u': USER, 'p': PASSWORD}, timeout=10, allow_redirects=False)
ok('login', r.status_code in (200, 302), r.status_code)

refs = set()
for path in PAGES:
    r = s.get(BASE + path, timeout=10)
    ok(f'page {path}', r.status_code == 200 and 'text/html' in r.headers.get('Content-Type', ''), r.status_code)
    if r.status_code != 200:
        continue
    for href in re.findall(r"(?:href|src)=[\"'](/assets/[^\"']+)[\"']", r.text, flags=re.I):
        refs.add(href)

ok('asset references discovered', bool(refs), sorted(refs))
for ref in sorted(refs):
    r = s.get(BASE + ref, timeout=10)
    body = r.content
    content_type = r.headers.get('Content-Type', '')
    declared = r.headers.get('Content-Length')
    length_ok = declared is None or declared.isdigit() and int(declared) == len(body)
    non_html_error = not (r.status_code == 200 and 'text/html' in content_type and ref.rsplit('.', 1)[-1] in {'css', 'js', 'svg', 'png', 'ico', 'woff', 'woff2'})
    ok(f'asset {ref} HTTP 200', r.status_code == 200, r.status_code)
    ok(f'asset {ref} Content-Length', length_ok, (declared, len(body)))
    ok(f'asset {ref} not HTML fallback', non_html_error, content_type)
    if ref.endswith('.js') and r.status_code == 200:
        ok(f'asset {ref} non-empty', bool(body), len(body))
        ok(f'asset {ref} valid UTF-8', is_utf8(body))

ref = '/assets/readers.js'
if ref in refs:
    body = s.get(BASE + ref, timeout=10).content
    ok('readers.js keeps final newline', body.endswith(b'\n'), body[-16:])

print('FAILED:', len(FAILS), FAILS)
sys.exit(1 if FAILS else 0)

