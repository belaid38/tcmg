import http.client, json, socket, time, sys, urllib.parse, uuid, os
H="127.0.0.1"; P=18080
TEST_DIR = __import__("os").environ.get("TCMG_TEST_DIR", "/tmp/tcu")
fails=[]
def ok(name,cond,extra=""):
    print(("PASS " if cond else "FAIL ")+name+(("  -> "+str(extra)) if (extra!="" and not cond) else ""))
    if not cond: fails.append(name)
def req(method,path,body=None,headers=None,raw=False):
    c=http.client.HTTPConnection(H,P,timeout=10)
    h={"Connection":"close"}; h.update(headers or {})
    if body is not None and isinstance(body,dict): body=urllib.parse.urlencode(body); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    c.request(method,path,body=body,headers=h)
    r=c.getresponse(); data=r.read(); hd=dict((k.lower(),v) for k,v in r.getheaders()); c.close()
    if raw: return r.status,hd,data
    try: return r.status,hd,json.loads(data)
    except Exception: return r.status,hd,data.decode("utf-8","replace")
def rawsock(payload,read=True):
    s=socket.create_connection((H,P),timeout=10); s.sendall(payload)
    out=b""
    try:
        while True:
            d=s.recv(65536)
            if not d: break
            out+=d
    except Exception: pass
    s.close(); return out

for pg in ["/status","/users","/readers","/livelog","/config","/failban","/files","/tvcas","/power?action=restart"]:
    st,hd,b=req("GET",pg); ok("page "+pg,st==200 and len(b)>500,st)
for asset,ctype in [("/assets/app.css","text/css"),("/assets/app.js","application/javascript"),("/assets/users.js","application/javascript")]:
    st,hd,b=req("GET",asset,raw=True); ok("asset "+asset,st==200 and ctype in hd.get("content-type","") and "max-age=31536000" in hd.get("cache-control","") and len(b)>100,(st,hd,len(b)))
st,hd,b=req("GET","/users")
ok("security headers",hd.get("x-frame-options")=="DENY" and hd.get("x-content-type-options")=="nosniff" and "frame-ancestors" in hd.get("content-security-policy",""),hd)
ok("users page has rows",b.count("class='urow'")>0,b.count("class='urow'"))

st,hd,j=req("GET","/api/user/get?user=client"); ok("user get json",st==200 and j.get("user")=="client",j)
test_user="stage19_"+uuid.uuid4().hex[:8]
st,_,j=req("POST","/api/user/add",{"user":test_user,"pass":"pw1","caid":"0B00","maxconn":"2","enabled":"1","expiry":"2030-12-31","anti_share":"1","as_max_sids":"1","as_max_ecm":"30","as_ecm_window_s":"45","as_channel_timeout_s":"12","as_switch_delay_s":"2"}); ok("add valid",st==200 and j.get("ok"),j)
st,_,j=req("GET","/api/user/get?user="+urllib.parse.quote(test_user)); ok("added user roundtrip",j.get("expiry")=="2030-12-31" and j.get("max_connections")==2 and j.get("anti_share")==1 and j.get("as_max_sids")==1 and j.get("as_max_ecm")==30 and j.get("as_ecm_window_s")==45 and j.get("as_channel_timeout_s")==12 and j.get("as_switch_delay_s")==2,j)
bads={"caid zz":{"user":"b1","pass":"x","caid":"ZZZZ"},"caid long":{"user":"b2","pass":"x","caid":"0B0000"},
 "maxconn neg":{"user":"b3","pass":"x","maxconn":"-5"},"expiry impossible":{"user":"b4","pass":"x","expiry":"2026-02-31"},
 "expiry garbage":{"user":"b5","pass":"x","expiry":"tomorrow"},"name hash":{"user":"a#b","pass":"x"},
 "name newline":{"user":"a\n[server]\nweb_pass=x","pass":"x"},"pass hash":{"user":"b6","pass":"p#q"},
 "name too long":{"user":"u"*80,"pass":"x"},"empty name":{"user":"","pass":"x"},"enabled bad":{"user":"b7","pass":"x","enabled":"maybe"},"anti ecm bad":{"user":"b8","pass":"x","as_max_ecm":"100001"},"anti window bad":{"user":"b9","pass":"x","as_ecm_window_s":"0"},"anti timeout bad":{"user":"b10","pass":"x","as_channel_timeout_s":"3601"},"anti delay bad":{"user":"b11","pass":"x","as_switch_delay_s":"31"}}
for k,v in bads.items():
    st,_,j=req("POST","/api/user/add",v); ok("reject: "+k,st==400 and j.get("ok") is False,(st,j))
st,_,j=req("POST","/api/user/add",{"user":test_user,"pass":"x"}); ok("duplicate -> 409",st==409,(st,j))
st,_,j=req("POST","/api/user/save",{"user":test_user,"pass":"pw2","caid":"0604","maxconn":"3","expiry":"0","anti_share":"1","as_max_sids":"2","as_max_ecm":"60","as_ecm_window_s":"90","as_channel_timeout_s":"20","as_switch_delay_s":"0"}); ok("save w/o enabled ok",st==200,j)
st,_,j=req("GET","/api/user/get?user="+urllib.parse.quote(test_user)); ok("save w/o enabled keeps enabled=1 and antishare settings",j.get("enabled")==1 and j.get("caid")=="0604" and j.get("expiry")=="0" and j.get("as_max_sids")==2 and j.get("as_max_ecm")==60 and j.get("as_ecm_window_s")==90 and j.get("as_channel_timeout_s")==20 and j.get("as_switch_delay_s")==0,j)
st,_,j=req("POST","/api/user/toggle?user="+urllib.parse.quote(test_user)); ok("toggle off",j.get("enabled")==0,j)
for _ in range(10):
    time.sleep(0.15)
    st,_,j=req("GET","/api/user/get?user="+urllib.parse.quote(test_user))
    if st==200 and j.get("enabled")==0: break
st,_,j=req("POST","/api/user/toggle?user="+urllib.parse.quote(test_user)); ok("toggle on",st==200 and j.get("ok") is True,j)
for _ in range(10):
    time.sleep(0.15)
    st,_,j=req("GET","/api/user/get?user="+urllib.parse.quote(test_user))
    if st==200 and j.get("enabled")==1: break
ok("toggle on applied",st==200 and j.get("enabled")==1,j)
st,_,j=req("POST","/api/user/resetstats?user=client"); ok("resetstats",st==200 and j.get("ok"),j)
st,_,rj=req("GET","/api/readers"); ok("readers API returns JSON",st==200 and rj.get("ok") is True and isinstance(rj.get("readers"),list) and all("cw_ok" in r and "cw_nok" in r and "active" in r for r in rj.get("readers",[])),rj)
reader_base={"index":"-1","label":"Test EMU","protocol":"emu","enabled":"1","device":"","user":"","password":"","key":"","inactivitytimeout":"30","caid":"","sid_whitelist":"","ecmwhitelist":"37","group":"1","ecmkeys":"0B00="+"A"*64,"DO_ECM":"1","FAST_RESET":"0","FAST_RESET_IDLE":"300","POLL_MS":"250"}
large_keys=";".join("%04X="%(0x1000+i)+"A"*64 for i in range(8))
large_reader=dict(reader_base)
large_reader.update(label="Large JSON Reader",ecmkeys=large_keys)
st,_,j=req("POST","/api/reader/save",large_reader); ok("large reader JSON save",st==200 and j.get("ok"),j)
st,_,rj=req("GET","/api/readers")
large_row=next((r for r in rj.get("readers",[]) if r.get("label")=="Large JSON Reader"),None)
expected_keys="\n".join(large_keys.split(";"))
large_detail = {}
if large_row:
    st,_,large_detail=req("GET",f"/api/reader/get?index={large_row.get('index')}")
ok("large reader JSON preserved",large_row is not None and st==200 and large_detail.get("ecmkeys")==expected_keys,(len(large_detail.get("ecmkeys","")) if isinstance(large_detail,dict) else -1))
if large_row:
    st,_,j=req("POST","/api/reader/delete?index="+str(large_row.get("index"))); ok("large reader JSON cleanup",st==200 and j.get("ok"),j)
st,_,j=req("POST","/api/reader/save",reader_base); ok("add reader",st==200 and j.get("ok"),j)
st,_,_rl=req("GET","/api/readers")
reader_test_index=next((r.get("index") for r in _rl.get("readers",[]) if r.get("label")=="Test EMU"), -1) if isinstance(_rl,dict) else -1
ok("add reader returned a visible row",reader_test_index >= 0, _rl)
st,_,page=req("GET","/readers"); ok("added reader appears in page",st==200 and "Test EMU" in page,page[:120])
st,_,j=req("GET",f"/api/reader/get?index={reader_test_index}"); ok("reader add roundtrip",st==200 and j.get("label")=="Test EMU" and j.get("protocol")=="emu",j)
reader_edit=dict(reader_base); reader_edit.update(index=str(reader_test_index),label="Edited EMU",enabled="0",group="2,3",ecmkeys="0B00="+"B"*64)
st,_,j=req("POST","/api/reader/save",reader_edit); ok("edit reader",st==200 and j.get("ok"),j)
st,_,j=req("GET",f"/api/reader/get?index={reader_test_index}"); ok("reader edit roundtrip",st==200 and j.get("label")=="Edited EMU" and j.get("enabled")==0 and j.get("group")=="2,3",j)
internal_reader_base={"index":"-1","label":"Test Internal","protocol":"internal","enabled":"1","device":"/dev/sci0","user":"","password":"","key":"","inactivitytimeout":"30","caid":"0B00","sid_whitelist":"","ecmwhitelist":"37","group":"1","ecmkeys":"","DO_ECM":"1","FAST_RESET":"99","FAST_RESET_IDLE":"300"}
st,_,j=req("POST","/api/reader/save",internal_reader_base); ok("add internal without poll_ms",st==200 and j.get("ok"),j)
st,_,rj=req("GET","/api/readers"); internal_idx=next((r.get("index") for r in rj.get("readers",[]) if r.get("label")=="Test Internal"),-1)
st,_,j=req("GET",f"/api/reader/get?index={internal_idx}"); ok("internal add roundtrip",st==200 and j.get("protocol")=="internal" and j.get("FAST_RESET")==99 and j.get("FAST_RESET_IDLE")==300 and "POLL_MS" not in j,j)
internal_edit=dict(internal_reader_base); internal_edit.update(index=str(internal_idx),label="Edited Internal",enabled="0",device="/dev/sci1",FAST_RESET="123",FAST_RESET_IDLE="60")
st,_,j=req("POST","/api/reader/save",internal_edit); ok("edit internal without poll_ms",st==200 and j.get("ok"),j)
st,_,j=req("GET",f"/api/reader/get?index={internal_idx}"); ok("internal edit roundtrip",st==200 and j.get("label")=="Edited Internal" and j.get("device")=="/dev/sci1" and j.get("FAST_RESET")==123 and j.get("FAST_RESET_IDLE")==60 and "POLL_MS" not in j,j)
st,_,j=req("GET","/readers"); ok("internal status badges removed",st==200 and "LOCKED" not in j and ">OPEN<" not in j,j[:500])
if internal_idx >= 0:
    st,_,j=req("POST",f"/api/reader/delete?index={internal_idx}"); ok("internal reader cleanup",st==200 and j.get("ok"),j)
old_ecm_value="817034703264216EB6EFA65A38468DA2AC005F1CC011508CA82E3E4E0F74462096EE21A7F0DD1E57DD46FF3C5133886CB0861005D9E89C"
for _proto in ["pcsc","internal","serial"]:
    _d={"index":"-1","label":"Old ECM "+_proto,"protocol":_proto,"enabled":"0","device":"/dev/test","user":"","password":"","key":"","inactivitytimeout":"30","caid":"0B00","sid_whitelist":"","ecmwhitelist":"37","group":"1","ecmkeys":"","DO_ECM":"1","FAST_RESET":"123","FAST_RESET_IDLE":"45","POLL_MS":"250","MAINTENANCE_MODE":"old_ecm","OLD_ECM_SOURCE":"manual","OLD_ECM_SUCCESSES":"7","OLD_ECM":old_ecm_value}
    st,_,j=req("POST","/api/reader/save",_d); ok("add old ECM "+_proto,st==200 and j.get("ok"),j)
    st,_,rj=req("GET","/api/readers"); _idx=next((r.get("index") for r in rj.get("readers",[]) if r.get("label")=="Old ECM "+_proto),-1)
    st,_,j=req("GET",f"/api/reader/get?index={_idx}")
    ok("old ECM "+_proto+" roundtrip",st==200 and j.get("MAINTENANCE_MODE")=="old_ecm" and j.get("OLD_ECM_SOURCE")=="manual" and "OLD_ECM_TRIGGER" not in j and "OLD_ECM_INTERVAL" not in j and j.get("OLD_ECM_SUCCESSES")==7 and j.get("OLD_ECM")==old_ecm_value and ("POLL_MS" not in j if _proto=="internal" else "POLL_MS" in j),j)
    if _idx >= 0:
        st,_,j=req("POST",f"/api/reader/delete?index={_idx}"); ok("delete old ECM "+_proto,st==200 and j.get("ok"),j)
for k,bad in [("label",dict(reader_base, label="")), ("protocol",dict(reader_base, protocol="bogus")), ("group",dict(reader_base, group="0")), ("ecmwl",dict(reader_base, ecmwhitelist="100")), ("ecmkey",dict(reader_base, ecmkeys="0B00="+"C"*63))]:
    st,_,j=req("POST","/api/reader/save",bad); ok("reject reader "+k,st==400 and j.get("ok") is False,(st,j))
st,_,j=req("POST",f"/api/reader/delete?index={reader_test_index}"); ok("delete reader",st==200 and j.get("ok"),j)
st,_,j=req("GET",f"/api/reader/get?index={reader_test_index}"); ok("deleted reader -> 404",st==404 and j.get("ok") is False,j)
reader_protocol_base={"index":"-1","enabled":"1","device":"host:10000","user":"u","password":"p","key":"","inactivitytimeout":"30","caid":"0B00","sid_whitelist":"","ecmwhitelist":"37","group":"1","ecmkeys":"","DO_ECM":"1","FAST_RESET":"10","FAST_RESET_IDLE":"300","POLL_MS":"400"}
for _proto in ["cccam","mgcamd","newcamd","cs378x","pcsc","serial"]:
    _d=dict(reader_protocol_base)
    _d.update(label="Matrix "+_proto,protocol=_proto)
    if _proto in ("mgcamd","newcamd"):
        _d["key"]="01"*14
    elif _proto == "pcsc":
        _d.update(device="Test PCSC Reader",user="",password="",key="")
    st,_,_j=req("POST","/api/reader/save",_d); ok("add reader protocol "+_proto,st==200 and _j.get("ok"),_j)
st,_,rj=req("GET","/api/readers"); ok("all reader protocols visible",st==200 and {r.get("protocol") for r in rj.get("readers",[])} >= {"cccam","mgcamd","newcamd","cs378x","pcsc","serial"},rj)
st,_,page=req("GET","/readers"); ok("reader matrix appears in page",st==200 and all(("Matrix "+_p) in page for _p in ["cccam","mgcamd","newcamd","cs378x","pcsc","serial"]),len(page) if isinstance(page,str) else page)
st,_,rj=req("GET","/api/readers")
for _r in list(rj.get("readers",[])) if isinstance(rj,dict) else []:
    if str(_r.get("label","")).startswith("Matrix "):
        _i=_r.get("index")
        st2,_,_j=req("POST",f"/api/reader/delete?index={_i}"); ok("delete matrix reader %s"%_r.get("label"),st2==200 and _j.get("ok"),_j)
st,_,rj=req("GET","/api/readers"); ok("reader matrix cleanup",st==200 and all(not str(r.get("label","")).startswith("Matrix ") for r in rj.get("readers",[])),rj)
st,_,s=req("GET","/api/status")
cl=s.get("clients",[]) if isinstance(s,dict) else []
ok("status clients response sane",isinstance(cl,list),cl[:1])
if cl:
    tid=cl[0].get("thread_id"); uname=cl[0].get("user","")
    st,_,j=req("POST","/api/client/kill?tid="+urllib.parse.quote(str(tid))+"&user="+urllib.parse.quote(uname)); ok("client kill API",st==200 and j.get("ok"),j)
else:
    ok("client kill API",True,"no active client fixture")
online_user=cl[0].get("user") if cl else ""
if online_user:
    st,_,j=req("POST","/api/user/delete?user="+urllib.parse.quote(online_user)); ok("delete active user",st==200,j)
else:
    ok("delete active user",True,"no active client fixture")
for i in range(3):
    st1,_,_=req("GET","/api/status"); st2,_,_=req("GET","/users"); st3,_,_=req("GET","/status")
ok("no crash after deleting active user",st1==200 and st2==200 and st3==200)
st,_,j=req("POST","/api/user/delete?user=nobody"); ok("delete unknown -> 404",st==404,j)

st,_,c=req("GET","/api/config/get"); ok("config get omits reader-only pcsc settings","pcsc_poll_ms" not in c and "pcsc_reader" not in c,c)
c2=dict(c)
d=dict((k, str(v)) for k,v in c.items() if isinstance(v, (int, str)))
def cfgbody(**kw):
    x=dict(d); x.update(kw); return x
st,_,j=req("POST","/api/config/save",cfgbody()); ok("config save ok",st==200 and j.get("ok"),(st,j))
orig_cccam=c2.get("cccam_port"); orig_webif_user=c2.get("webif_user"); orig_logfile=c2.get("logfile")
st,_,jr=req("POST","/api/config/save",{"cccam_port":str((orig_cccam or 0)+1)}); ok("listener config reports restart required",st==200 and jr.get("ok") and jr.get("restart_required") is True,jr)
for k,v in {"bad port":{"cccam_port":"70000"},"bad key":{"newcamd_key":"XYZ"},"bad ip":{"webif_bindaddr":"not-an-ip"},"hash in logfile":{"logfile":"/tmp/a#b"},"bad flag":{"ecm_log":"7"}}.items():
    st,_,j=req("POST","/api/config/save",cfgbody(**v)); ok("config reject: "+k,st==400 and "invalid" in str(j.get("msg","")),(st,j))
st,_,j=req("POST","/api/config/save",cfgbody(logfile="/tmp/tcmg_test.log")); st,_,j=req("POST","/api/config/save",cfgbody(logfile=""))
st,_,c3=req("GET","/api/config/get"); ok("logfile can be cleared",c3.get("logfile")=="",c3.get("logfile"))
st,_,j=req("POST","/api/config/save",cfgbody(newcamd_port="5050")); st,_,j=req("POST","/api/config/save",cfgbody(newcamd_port="0"))
st,_,c4=req("GET","/api/config/get"); ok("newcamd_port can be set to 0 (disabled)",c4.get("newcamd_port")==0,c4.get("newcamd_port"))

st,_,b=req("GET","/files"); import re, html
ok("files page exposes config tabs", all(x in b for x in ("tcmg.conf","tcmg.users","tcmg.readers","tcmg.srvid2")), len(b))
ok("files page exposes keyboard tabs", "role='tablist'" in b and "aria-selected='true'" in b, None)
ok("files page exposes download", "downloadCurrentFile" in b, None)
m=re.search(r"<textarea[^>]*id='fileArea'[^>]*>(.*?)</textarea>",b,re.S); conf=html.unescape(m.group(1)) if m else ""
ok("initial config editor found",bool(m),None)
big=conf+"\n"+"".join("# padding line %05d ............................................................\n"%i for i in range(220))
ok("test file is reasonably large",len(big)>14000,len(big))
orig_users=open(TEST_DIR + "/tcmg.users").read()
orig_readers=open(TEST_DIR + "/tcmg.readers").read()
st,_,j=req("POST","/api/config/file/save",{"file":"conf","content":big}); ok("save large conf",st==200 and j.get("ok"),(st,j))
disk=open(TEST_DIR + "/tcmg.conf").read(); ok("large conf written completely",disk==big,(len(disk),len(big)))
srv="".join("0B00:%04X|Channel %d\n"%(i,i) for i in range(6000))
st,_,j=req("POST","/api/config/file/save",{"file":"srv","content":srv}); ok("save big srvid2",st==200,(st,j))
ok("srvid2 written completely",open(TEST_DIR + "/tcmg.srvid2").read()==srv)
file_user=test_user+"_file"
users_edit=orig_users.rstrip()+"\n\n[account]\nuser = "+file_user+"\npwd = z\nenabled = 1\ngroup = 1\ncaid = 0B00\nexpiration = 0\n"
st,_,j=req("POST","/api/config/file/save",{"file":"usr","content":users_edit}); ok("save users file",st==200 and j.get("ok"),(st,j))
st,_,j=req("GET","/api/config/file/get?file=usr"); ok("users file roundtrip",st==200 and file_user in j.get("content",""),j)
users_bad=users_edit+"\n[account]\nuser = "+file_user+"\npwd = duplicate\n"
st,_,j=req("POST","/api/config/file/save",{"file":"usr","content":users_bad}); ok("invalid users file rejected",st==400 and j.get("ok") is False,j)
st,_,j=req("POST","/api/config/file/save",{"file":"usr","content":orig_users}); ok("restore users file",st==200 and j.get("ok"),j)
reader_edit="[reader]\nlabel = File Editor EMU\nprotocol = emu\nenabled = 0\ncaid = 0B00\ngroup = 1\ndo_ecm = 1\n"
st,_,j=req("POST","/api/config/file/save",{"file":"rdr","content":reader_edit}); ok("save readers file",st==200 and j.get("ok"),j)
st,_,j=req("GET","/api/config/file/get?file=rdr"); ok("readers file roundtrip",st==200 and "File Editor EMU" in j.get("content",""),j)
reader_bad="[reader]\nlabel =\nprotocol = bogus\nenabled = 0\n"
st,_,j=req("POST","/api/config/file/save",{"file":"rdr","content":reader_bad}); ok("invalid readers file rejected",st==400 and j.get("ok") is False,j)
st,_,j=req("POST","/api/config/file/save",{"file":"rdr","content":orig_readers}); ok("restore readers file",st==200 and j.get("ok"),j)
st,_,j=req("POST","/api/config/file/save",{"file":"conf","content":"[account\nuser=\n\x00"});
st,_,j=req("POST","/api/config/file/save",{"file":"conf","content":""}); ok("empty content rejected",st==400,(st,j))
st,_,j=req("POST","/api/config/file/save",{"file":"other","content":"x"}); ok("bad file name rejected",st==400)
huge="a="+"x"*(2*1024*1024)
st,_,j=req("POST","/api/config/file/save",{"file":"srv","content":huge}); ok("2MB body -> 413 (not silently truncated)",st==413,(st,str(j)[:80]))
ok("srvid2 untouched after 413",open(TEST_DIR + "/tcmg.srvid2").read()==srv)
import os; ok("no leftover .new/.chk files",not any(f.endswith((".new",".chk",".tmp")) for f in os.listdir(TEST_DIR)),os.listdir(TEST_DIR))

body=urllib.parse.urlencode({"user":"lc1","pass":"x"})
body=urllib.parse.urlencode({"user":"stage_http_"+uuid.uuid4().hex[:6],"pass":"x"})
out=rawsock(("POST /api/user/add HTTP/1.1\r\nHost: x\r\ncontent-length: %d\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\n%s"%(len(body),body)).encode())
ok("lowercase content-length header works",b" 200 " in out.split(b"\r\n")[0] and b'"ok":true' in out,out[:120])
out=rawsock(b"GET /api/user/get?user=lc%00zz HTTP/1.1\r\nHost: x\r\n\r\n"); ok("%00 in query handled (no crash)",b"HTTP/1.1" in out)
out=rawsock(b"GET /"+b"a"*600+b" HTTP/1.1\r\nHost: x\r\n\r\n"); ok("long URI -> 414",b" 414 " in out.split(b"\r\n")[0],out[:60])
out=rawsock(b"POST /api/user/add HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\nx"); ok("bad Content-Length -> 400",b" 400 " in out.split(b"\r\n")[0],out[:60])
out=rawsock(b"POST /api/user/add HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\nx"); ok("huge Content-Length -> 413",b" 413 " in out.split(b"\r\n")[0],out[:60])
out=rawsock(b"POST /api/user/add HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nuser=short"); ok("short body -> 400",b" 400 " in out.split(b"\r\n")[0] or out==b"",out[:60])
out=rawsock(b"GET /users HTTP/1.1\r\nX-Junk: "+b"j"*20000+b"\r\n\r\n"); ok("oversize headers -> 431 (or handled)",b" 431 " in out[:40] or b"HTTP/1.1" in out[:10] or out==b"",out[:60])
st,_,b=req("GET","/users"); ok("server still alive after abuse",st==200)

st,_,j=req("POST","/api/user/toggle?user="+urllib.parse.quote(test_user),headers={"Sec-Fetch-Site":"cross-site"}); ok("cross-site state change blocked",st==403,(st,j))
st,_,j=req("POST","/api/user/toggle?user="+urllib.parse.quote(test_user),headers={"Sec-Fetch-Site":"same-origin"}); ok("same-origin allowed",st==200,(st,j))
time.sleep(0.2)
st,_,j=req("POST","/api/user/toggle?user="+urllib.parse.quote(test_user)); ok("no Sec-Fetch header (curl/bookmark) allowed",st==200,(st,j))
st,_,j=req("GET","/api/user/toggle?user="+urllib.parse.quote(test_user)); ok("GET mutation rejected",st in (404,405),(st,j))
csrf_foreign="csrf1_"+uuid.uuid4().hex[:6]
st,_,j=req("POST","/api/user/add",{"user":csrf_foreign,"pass":"x"},headers={"Origin":"http://evil.example","Host":"127.0.0.1:18080"}); ok("foreign Origin POST blocked",st==403,(st,j))
csrf_same="csrf2_"+uuid.uuid4().hex[:6]
st,_,j=req("POST","/api/user/add",{"user":csrf_same,"pass":"x"},headers={"Origin":"http://127.0.0.1:18080","Host":"127.0.0.1:18080"}); ok("same Origin POST allowed",st==200,(st,j))
st,_,j=req("GET","/api/status",headers={"Sec-Fetch-Site":"cross-site"}); ok("read-only GET not blocked",st==200)
st,_,j=req("POST","/api/user/delete?user="+urllib.parse.quote(test_user)); ok("cleanup test user",st in (200,404),j)

st,_,b=req("GET","/power?action=bogus&confirm=yes"); time.sleep(0.6)
st2,_,_=req("GET","/status"); ok("bogus action does NOT shut the server down",st2==200)
st,_,b=req("GET","/power?action=bogus"); ok("bogus action shows normal power page",st==200 and "Confirm" not in b)
print("\nFAILED: %d"%len(fails), fails)
sys.exit(1 if fails else 0)
