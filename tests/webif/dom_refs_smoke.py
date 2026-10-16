import pathlib,re,sys
ROOT=pathlib.Path(__file__).resolve().parents[2]
checks=[('readers','webif/assets/js_readers.h'),('users','webif/assets/js_users.h')]
fails=[]
for page,jspath in checks:
    s=(ROOT/jspath).read_text()
    m=re.search(r'_DATA\[\].*?= \{(.*?)\};',s,re.S)
    if not m:
        print('FAIL no asset data',page); fails.append(page); continue
    arr=[int(x) for x in re.findall(r'\b\d+\b',m.group(1))]
    js=bytes(arr).decode('utf-8','replace').rstrip('\0')
    refs=set(re.findall(r"\$\('([^']+)'\)",js))
    html=(ROOT/f'webif/pages/{page}.c').read_text()
    ids=set(re.findall(r"\bid=['\"]([^'\"]+)['\"]",html))
    missing=sorted(refs-ids)
    print(f"{'PASS' if not missing else 'FAIL'} {page} DOM refs" + (f' -> {missing}' if missing else ''))
    if missing:fails.append(page)
for name in ['js_common.h','js_users.h','js_readers.h','js_livelog.h']:
    s=(ROOT/'webif/assets'/name).read_text(); m=re.search(r'_DATA\[\].*?= \{(.*?)\};',s,re.S)
    arr=[int(x) for x in re.findall(r'\b\d+\b',m.group(1))]
    if 0 in bytes(arr):
        z=0
        for x in reversed(arr):
            if x==0:z+=1
            else:break
        lm=re.search(r'_LEN \(sizeof\([^)]*\)(?:\s*-\s*(\d+)U)?\)',s)
        delta=int(lm.group(1) or 0) if lm else None
        ok=z==1 and delta==1 if z else delta==0
        print(f"{'PASS' if ok else 'FAIL'} {name} asset terminator count={z} len_delta={delta}")
        if not ok:fails.append(name)
print('FAILED',len(fails))
sys.exit(1 if fails else 0)
