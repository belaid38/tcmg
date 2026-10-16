#define MODULE_LOG_PREFIX "webif"
#include "../service/service.h"
#include "../../src/core/runtime_state.h"
#include "../../src/core/utils.h"
#include "../../src/platform/platform.h"
#include "../internal/proto.h"
#include <sys/stat.h>

#define FILE_TRUNC_BANNER \
	"<div class='ib2' style='color:var(--or2);border-color:var(--ors);margin-bottom:8px'>" \
	ICO_WARN " File is larger than 512 KB &mdash; shown read-only so that a truncated copy " \
	"can never be saved over it. Edit it on disk.</div>"

void send_page_config(int fd)
{
	PAGE_INIT(16384)

	S_WEBIF_CONFIG_VIEW cfg = {0};
	webif_config_snapshot(&cfg);

	pos = emit_header(&buf, &bsz, pos, "Config", "config");

	char key_hex[29];
	for (int i = 0; i < 14; i++)
		snprintf(key_hex + i * 2, 3, "%02X", cfg.newcamd_key[i]);
	key_hex[28] = '\0';

	char esc_nm_bind[256], esc_cs_bind[256], esc_cm_bind[256], esc_logfile[512], esc_wi_bind[256];
	char esc_wi_user[256], esc_wi_pass[256], esc_failban_allow[CFGVAL_LEN*2];

	html_escape(cfg.newcamd_bindaddr, esc_nm_bind, sizeof(esc_nm_bind));
	html_escape(cfg.cs378x_bindaddr, esc_cs_bind, sizeof(esc_cs_bind));
	html_escape(cfg.camd35_bindaddr, esc_cm_bind, sizeof(esc_cm_bind));
	html_escape(cfg.logfile, esc_logfile, sizeof(esc_logfile));
	html_escape(cfg.webif_bindaddr, esc_wi_bind, sizeof(esc_wi_bind));
	html_escape(cfg.webif_user, esc_wi_user, sizeof(esc_wi_user));
	html_escape(cfg.webif_pass, esc_wi_pass, sizeof(esc_wi_pass));
		html_escape(cfg.failban_allowlist, esc_failban_allow, sizeof(esc_failban_allow));

	char esc_sname[CFGVAL_LEN * 6], esc_shost[CFGKEY_LEN * 6], esc_dvuser[CFGKEY_LEN * 6], esc_dvsock[CFGPATH_LEN * 6];
	html_escape(cfg.dvbapi_user, esc_dvuser, sizeof(esc_dvuser));
	html_escape(cfg.dvbapi_socket, esc_dvsock, sizeof(esc_dvsock));
	html_escape(cfg.seller_name, esc_sname, sizeof(esc_sname));
	html_escape(cfg.seller_host, esc_shost, sizeof(esc_shost));

#define CFG_NUM(id, label, mn, mx, fmt, cls) \
	"<div class='cfg-field" cls "'><label class='cfg-label' for='" id "'>" label "</label>" \
	"<input class='cfg-input mono' id='" id "' type='number' min='" mn "' max='" mx "' value='" fmt "'></div>"
#define CFG_TXT(id, label, ph, cls) \
	"<div class='cfg-field" cls "'><label class='cfg-label' for='" id "'>" label "</label>" \
	"<input class='cfg-input mono' id='" id "' placeholder='" ph "' autocomplete='off' value='%s'></div>"
#define CFG_CHK(id, label) \
	"<label class='cfg-toggle'><input type='checkbox' id='" id "'%s> " label "</label>"

	pos = buf_printf(&buf, &bsz, pos,
		"<div class='cfg-page'>"
		"<div id='cfgMsg' class='cfg-msg' role='status' aria-live='polite'></div>"
		"<div class='cfg-cols'><div class='cfg-col'>"

		"<section class='cfg-card'><div class='cfg-title'>Servers</div><div class='cfg-grid'>"
		CFG_NUM("cf_newcamd_port", "Newcamd port", "0", "65535", "%d", "")
		CFG_NUM("cf_cccam_port",   "CCcam port",   "0", "65535", "%d", "")
		CFG_NUM("cf_cs378x_port",  "CS378X port",  "0", "65535", "%d", "")
		CFG_NUM("cf_camd35_port",  "CAMD35 UDP port", "0", "65535", "%d", "")
		CFG_TXT("cf_newcamd_bindaddr", "Newcamd bind", "0.0.0.0", "")
		CFG_TXT("cf_cs378x_bindaddr",  "CS378X bind",  "0.0.0.0", "")
		CFG_TXT("cf_camd35_bindaddr", "CAMD35 UDP bind", "0.0.0.0", "")
		CFG_NUM("cf_sock_timeout",  "Socket timeout (s)", "5", "600",  "%d", "")
		CFG_NUM("cf_server_keepalive", "Keepalive (s)",   "0", "3600", "%d", "")
		CFG_NUM("cf_server_keepalive_misses", "Keepalive misses", "1", "20", "%d", "")
		"<div class='cfg-field w3'><label class='cfg-label' for='cf_newcamd_key'>Newcamd DES key</label>"
		"<input class='cfg-input mono' id='cf_newcamd_key' maxlength='28' spellcheck='false' autocomplete='off' value='%s'></div>"
		"<div class='cfg-checks w3'>"
		CFG_CHK("cf_keepalive", "Newcamd keepalive")
		CFG_CHK("cf_mgclient",  "MGcamd client mode")
		"</div></div></section>"

		"<section class='cfg-card'><div class='cfg-title'>Fail-Ban</div><div class='cfg-grid'>"
		CFG_TXT("cf_failban_allowlist", "Allowlist", "", " w3")
		CFG_NUM("cf_failban_max_fails", "Max failed attempts", "1", "1000", "%d", " w2")
		CFG_NUM("cf_failban_ban_secs",  "Ban duration (s)",    "10", "604800", "%d", " w1")
		"<div class='cfg-checks w3'>" CFG_CHK("cf_failban_enabled", "Enabled") "</div>"
		"</div></section>"

		"</div><div class='cfg-col'>"

		"<section class='cfg-card'><div class='cfg-title'>Web interface</div><div class='cfg-grid'>"
		CFG_NUM("cf_webif_port", "Port", "1", "65535", "%d", "")
		CFG_TXT("cf_webif_bindaddr", "Bind address", "0.0.0.0", " w2")
		"<div class='cfg-field'><label class='cfg-label' for='cf_webif_user'>Admin username</label>"
		"<input class='cfg-input' id='cf_webif_user' autocomplete='off' value='%s'></div>"
		"<div class='cfg-field'><label class='cfg-label' for='cf_webif_pass'>Admin password</label>"
		"<input class='cfg-input' id='cf_webif_pass' type='text' autocomplete='off' value='%s'></div>"
		CFG_NUM("cf_webif_refresh", "Auto-refresh (s)", "0", "3600", "%d", "")
		"</div></section>"

		"<section class='cfg-card'><div class='cfg-title'>Logging &amp; restart</div><div class='cfg-grid'>"
		CFG_TXT("cf_logfile", "Log file", "", " w3")
		"<div class='cfg-field'><label class='cfg-label' for='cf_restart_time'>Restart time</label>"
		"<input class='cfg-input mono' id='cf_restart_time' type='time' step='60' value='%s'></div>"
		"<div class='cfg-checks w2'>"
		CFG_CHK("cf_ecm_log", "ECM log")
		CFG_CHK("cf_restart_enabled", "Daily restart")
		"</div></div></section>"

		"<section class='cfg-card'><div class='cfg-title'>Seller &amp; subscription card</div><div class='cfg-grid'>"
		"<div class='cfg-field w3'><label class='cfg-label' for='cf_seller_name'>Provider name</label>"
		"<input class='cfg-input' id='cf_seller_name' maxlength='80' autocomplete='off' placeholder='Your service name' value='%s'></div>"
		"<div class='cfg-field'><label class='cfg-label' for='cf_seller_type'>Server type</label>"
		"<select class='cfg-input' id='cf_seller_type' onchange='sellerAuto()'>"
		"<option value='cccam'%s>CCcam</option><option value='newcamd'%s>Newcamd</option><option value='cs378x'%s>CS378X</option><option value='camd35'%s>CAMD35 UDP</option></select></div>"
		"<div class='cfg-field w2'><label class='cfg-label' for='cf_seller_host'>Host</label>"
		"<input class='cfg-input mono' id='cf_seller_host' maxlength='60' autocomplete='off' spellcheck='false' value='%s'></div>"
		"</div></section>"

		"<section class='cfg-card'><div class='cfg-title'>DVBAPI (this receiver)</div><div class='cfg-grid'>"
		"<div class='cfg-checks w3'>" CFG_CHK("cf_dvbapi_enabled", "Enable DVBAPI (descramble directly on this device)") "</div>"
		"<div class='cfg-field'><label class='cfg-label' for='cf_dvbapi_user'>Account</label>"
		"<input class='cfg-input mono' id='cf_dvbapi_user' maxlength='60' autocomplete='off' spellcheck='false' value='%s'></div>"
		"<div class='cfg-field'><label class='cfg-label' for='cf_dvbapi_boxtype'>Box type</label>"
		"<select class='cfg-input' id='cf_dvbapi_boxtype'>"
		"<option value='auto'%s>Auto (Enigma2 / Linux DVB)</option><option value='dreambox'%s>Dreambox</option>"
		"<option value='duckbox'%s>Duckbox (ca offset 1)</option><option value='ufs910'%s>UFS910 (ca offset 1)</option></select></div>"
		 CFG_NUM("cf_dvbapi_max_services", "Max services", "1", "32", "%d", "")
		"<div class='cfg-field w2'><label class='cfg-label' for='cf_dvbapi_socket'>Socket</label>"
		"<input class='cfg-input mono' id='cf_dvbapi_socket' maxlength='200' autocomplete='off' spellcheck='false' value='%s'></div>"
		 CFG_NUM("cf_dvbapi_delay", "ECM delay (ms)", "0", "60000", "%d", "")
		"</div></section>"

		"</div></div>",
		cfg.newcamd_port, cfg.cccam_port, cfg.cs378x_port, cfg.camd35_port,
		esc_nm_bind, esc_cs_bind, esc_cm_bind,
		cfg.sock_timeout, cfg.server_keepalive, cfg.server_keepalive_misses,
		key_hex,
		cfg.newcamd_keepalive ? " checked" : "",
		cfg.newcamd_mgclient ? " checked" : "",
		esc_failban_allow, cfg.failban_max_fails, cfg.failban_ban_secs,
		cfg.failban_enabled ? " checked" : "",
		cfg.webif_port, esc_wi_bind, esc_wi_user, esc_wi_pass, cfg.webif_refresh,
		esc_logfile, cfg.scheduled_restart_time,
		cfg.ecm_log ? " checked" : "",
		cfg.scheduled_restart_enabled ? " checked" : "",
		esc_sname,
		!strcmp(cfg.seller_type, "cccam") ? " selected" : "",
		!strcmp(cfg.seller_type, "newcamd") ? " selected" : "",
		!strcmp(cfg.seller_type, "cs378x") ? " selected" : "",
		!strcmp(cfg.seller_type, "camd35") ? " selected" : "",
		esc_shost,
		cfg.dvbapi_enabled ? " checked" : "",
		esc_dvuser,
		!strcmp(cfg.dvbapi_boxtype, "auto") ? " selected" : "",
		!strcmp(cfg.dvbapi_boxtype, "dreambox") ? " selected" : "",
		!strcmp(cfg.dvbapi_boxtype, "duckbox") ? " selected" : "",
		!strcmp(cfg.dvbapi_boxtype, "ufs910") ? " selected" : "",
		cfg.dvbapi_max_services, esc_dvsock, cfg.dvbapi_delay_ms);

	pos = buf_printf(&buf, &bsz, pos,
		"<div class='cfg-save'>"
		"<button type='button' class='tool pri' id='cfgSaveBtn' onclick='saveCfg()'>"
		ICON("i-save") "Save &amp; Reload</button>"
		"</div>"
		"</div>");

	pos = buf_printf(&buf, &bsz, pos,
		"<script>"
		"function cfgEl(id){return document.getElementById(id);}"
		"function cfgSetMessage(ok,msg){"
		"  var e=cfgEl('cfgMsg');"
		"  e.className='cfg-msg '+(ok?'ok':'err');"
		"  e.textContent=msg;"
		"  e.style.display='flex';"
		"}"

		"function cfgHex28(s){return /^[0-9a-fA-F]{28}$/.test(s);}"
		"function cfgValidate(){"
		"  var nk=cfgEl('cf_newcamd_key').value.trim();"
		"  if(!cfgHex28(nk)){cfgSetMessage(false,'Newcamd DES key must contain 28 hexadecimal characters.');cfgEl('cf_newcamd_key').focus();return false;}"
		"  return true;"
		"}"
		"function sellerAuto(){"
		"  cfgEl('cf_seller_host').placeholder=location.hostname||'';"
		"}"
		"sellerAuto();"
		"function saveCfg(){"
		"  if(window._cfgSaving||!cfgValidate())return;"
		"  window._cfgSaving=true;"
		"  var b=cfgEl('cfgSaveBtn');"
		"  b.disabled=true;"
		"  b.dataset.cfgOriginal=b.innerHTML;"
		"  b.textContent='Saving...';"
		"  var p=new URLSearchParams();"
		"  p.set('newcamd_port',cfgEl('cf_newcamd_port').value);"
		"  p.set('newcamd_bindaddr',cfgEl('cf_newcamd_bindaddr').value);"
		"  p.set('newcamd_key',cfgEl('cf_newcamd_key').value.trim());"
		"  p.set('newcamd_keepalive',cfgEl('cf_keepalive').checked?'1':'0');"
		"  p.set('newcamd_mgclient',cfgEl('cf_mgclient').checked?'1':'0');"
		"  p.set('cccam_port',cfgEl('cf_cccam_port').value);"
		"  p.set('cs378x_port',cfgEl('cf_cs378x_port').value);"
		"  p.set('cs378x_bindaddr',cfgEl('cf_cs378x_bindaddr').value);"
		"  p.set('camd35_port',cfgEl('cf_camd35_port').value);"
		"  p.set('camd35_bindaddr',cfgEl('cf_camd35_bindaddr').value);"
		"  p.set(\'sock_timeout\',cfgEl(\'cf_sock_timeout\').value);"
		"  p.set(\'server_keepalive\',cfgEl(\'cf_server_keepalive\').value);"
		"  p.set(\'server_keepalive_misses\',cfgEl(\'cf_server_keepalive_misses\').value);"
		"  p.set('ecm_log',cfgEl('cf_ecm_log').checked?'1':'0');"
	"  p.set('scheduled_restart',cfgEl('cf_restart_enabled').checked?'1':'0');"
	"  p.set('scheduled_restart_time',cfgEl('cf_restart_time').value);"
		"  p.set('logfile',cfgEl('cf_logfile').value);"
		"  p.set('webif_port',cfgEl('cf_webif_port').value);"
		"  p.set('webif_bindaddr',cfgEl('cf_webif_bindaddr').value);"
		"  p.set('webif_user',cfgEl('cf_webif_user').value);"
		"  p.set('webif_pass',cfgEl('cf_webif_pass').value);"
		"  p.set('webif_refresh',cfgEl('cf_webif_refresh').value);"
		"  p.set('seller_name',cfgEl('cf_seller_name').value.trim());"
		"  p.set('seller_type',cfgEl('cf_seller_type').value);"
		"  p.set('seller_host',cfgEl('cf_seller_host').value.trim());"
		"  p.set('dvbapi_enabled',cfgEl('cf_dvbapi_enabled').checked?'1':'0');"
		"  p.set('dvbapi_user',cfgEl('cf_dvbapi_user').value.trim());"
		"  p.set('dvbapi_boxtype',cfgEl('cf_dvbapi_boxtype').value);"
		"  p.set('dvbapi_socket',cfgEl('cf_dvbapi_socket').value.trim());"
		"  p.set('dvbapi_delay',cfgEl('cf_dvbapi_delay').value);"
		"  p.set('dvbapi_max_services',cfgEl('cf_dvbapi_max_services').value);"
		"  p.set(\'failban_enabled\',cfgEl(\'cf_failban_enabled\').checked?\'1\':\'0\');"
		"  p.set(\'failban_allowlist\',cfgEl(\'cf_failban_allowlist\').value);"
		"  p.set(\'failban_max_fails\',cfgEl(\'cf_failban_max_fails\').value);"
		"  var fbs=Math.max(10,Math.min(604800,parseInt(cfgEl('cf_failban_ban_secs').value,10)||300)); cfgEl('cf_failban_ban_secs').value=String(fbs); p.set('failban_ban_secs',String(fbs));"
		"  tcmg_api('/api/config/save',{method:'POST',body:p.toString(),headers:{'Content-Type':'application/x-www-form-urlencoded'}})"
		"  .then(function(d){"
		"    if(d&&d.ok){cfgSetMessage(true,'Configuration saved. Reload has been triggered.');}"
		"    else{cfgSetMessage(false,d&&d.msg?d.msg:'Request failed.');}"
		"  })"
		"  .catch(function(e){cfgSetMessage(false,'Request failed: '+e);})"
		"  .finally(function(){"
		"    window._cfgSaving=false;b.disabled=false;"
		"    b.innerHTML=b.dataset.cfgOriginal||'Save & Reload';"
		"  });"
		"}"
		"document.addEventListener('keydown',function(e){"
		"  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();saveCfg();}"
		"});"
		"</script>");

	pos = emit_footer(&buf, &bsz, pos);
	PAGE_SEND_AND_FREE(fd);
}
void send_page_files(int fd)
{
    PAGE_INIT(32768)
    pos = emit_header(&buf, &bsz, pos, "Files", "files");

    char cfgpath[CFGPATH_LEN];
    tcmg_build_path(cfgpath, sizeof(cfgpath), g_cfgdir, TCMG_CFG_FILE);
    int cfg_trunc = 0;
    size_t cfg_len = 0;
    struct stat cfg_st;
    if (stat(cfgpath, &cfg_st) == 0 && cfg_st.st_size > 0) cfg_len = (size_t)cfg_st.st_size;
    char *cfgesc = file_read_escaped(cfgpath, WEB_FILE_VIEW_MAX, &cfg_trunc);
    if (!cfgesc) {
        free(buf);
        send_json_error(fd, 503, "Service Unavailable", "out of memory");
        return;
    }

    pos = buf_printf(&buf, &bsz, pos,
        "<div class='file-page'>"
        "<div class='file-tabs' role='tablist' aria-label='Files'>"
        "  <button type='button' class='ctab act' id='fileTab-conf' role='tab' aria-selected='true' aria-controls='filePanel' tabindex='0' data-file='conf' onclick='switchFile(\"conf\")'>tcmg.conf</button>"
        "  <button type='button' class='ctab' id='fileTab-usr' role='tab' aria-selected='false' aria-controls='filePanel' tabindex='-1' data-file='usr' onclick='switchFile(\"usr\")'>tcmg.users</button>"
        "  <button type='button' class='ctab' id='fileTab-rdr' role='tab' aria-selected='false' aria-controls='filePanel' tabindex='-1' data-file='rdr' onclick='switchFile(\"rdr\")'>tcmg.readers</button>"
        "  <button type='button' class='ctab' id='fileTab-srv' role='tab' aria-selected='false' aria-controls='filePanel' tabindex='-1' data-file='srv' onclick='switchFile(\"srv\")'>tcmg.srvid2</button>"
        "</div>"
        "<div class='file-card' id='filePanel' role='tabpanel' tabindex='0' aria-labelledby='fileTab-conf'>"
        "%s"
        "<div class='et'><span id='fileName' class='ef'>tcmg.conf</span><span id='fileState' class='file-state'>Saved</span></div>"
        "<div id='fileWarn' class='ew' style='display:%s'></div>"
        "<textarea class='ea' id='fileArea' spellcheck='false' autocomplete='off'%s>%s</textarea>"
        "<div class='ef2 file-actions'>"
        "  <div class='file-info'><span id='fileSize'>%llu bytes</span><span class='file-dot'>·</span><span id='fileMode'>Validated on save</span></div>"
        "  <div class='file-buttons'>"
        "    <button type='button' class='tool sm' onclick='reloadFile()'>Reload</button>"
        "    <button type='button' class='tool sm' onclick='downloadCurrentFile()'>Download</button>"
        "    <button type='button' class='tool pri sm' id='fileSaveBtn' onclick='saveCurrentFile()' %s>" ICON("i-save") "Save</button>"
        "  </div>"
        "</div></div></div>",
        cfg_trunc ? FILE_TRUNC_BANNER : "",
        cfg_trunc ? "flex" : "none",
        cfg_trunc ? " readonly" : "", cfgesc,
        (unsigned long long)cfg_len, cfg_trunc ? "disabled" : "");
    free(cfgesc);

    pos = buf_printf(&buf, &bsz, pos,
        "<script>"
        "var currentFile='conf',dirty=false,busy=false;"
        "var fileNames={conf:'tcmg.conf',usr:'tcmg.users',rdr:'tcmg.readers',srv:'tcmg.srvid2'};"
        "function state(t,c){var e=document.getElementById('fileState');if(e){e.textContent=t;e.className='file-state '+(c||'')}}"
        "function setBusy(v){busy=v;var e=document.getElementById('fileBusy'),b=document.getElementById('fileSaveBtn');if(e)e.hidden=!v;if(b)b.disabled=v||document.getElementById('fileArea').readOnly}"
        "function clearWarn(){var e=document.getElementById('fileWarn');if(e){e.style.display='none';e.textContent=''}}"
        "function warn(msg){var e=document.getElementById('fileWarn');if(e){e.style.display='flex';e.textContent=msg}}"
        "function markDirty(){dirty=true;state('Unsaved','dirty');clearWarn()}"
        "function tabs(f){document.querySelectorAll('.file-tabs .ctab').forEach(function(b){var a=b.dataset.file===f;b.classList.toggle('act',a);b.setAttribute('aria-selected',a?'true':'false');b.tabIndex=a?0:-1});var p=document.getElementById('filePanel');if(p)p.setAttribute('aria-labelledby','fileTab-'+f)}"
        "function switchFile(f){if(busy||f===currentFile)return;if(dirty&&!confirm('Discard unsaved changes?'))return;loadFile(f)}"
        "function reloadFile(){if(dirty&&!confirm('Discard unsaved changes?'))return;loadFile(currentFile)}function downloadCurrentFile(){if(busy)return;var blob=new Blob([document.getElementById('fileArea').value],{type:'text/plain;charset=utf-8'}),u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download=fileNames[currentFile];document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(u)},0)}"
        "function loadFile(f){currentFile=f;dirty=false;tabs(f);clearWarn();setBusy(true);state('Loading','loading');document.getElementById('fileName').textContent=fileNames[f];tcmg_api('/api/config/file/get?file='+encodeURIComponent(f)).then(function(x){if(!x.ok)throw new Error(x.msg||'Load failed');var a=document.getElementById('fileArea');a.value=x.content||'';a.readOnly=!!x.truncated;document.getElementById('fileSize').textContent=x.size+' bytes'+(x.truncated?' · truncated':'');document.getElementById('fileMode').textContent=x.truncated?'Read only':'Validated on save';document.getElementById('fileSaveBtn').disabled=!!x.truncated;document.getElementById('fileWarn').style.display=x.truncated?'flex':'none';if(x.truncated)document.getElementById('fileWarn').textContent='File is larger than 512 KB and is shown read-only.';state('Saved');}).catch(function(e){warn(String(e));state('Load error','error')}).finally(function(){setBusy(false)})}"
        "function saveCurrentFile(){if(busy)return;var a=document.getElementById('fileArea');if(a.readOnly)return;var p=new URLSearchParams();p.set('file',currentFile);p.set('content',a.value);clearWarn();setBusy(true);state('Saving','loading');tcmg_api('/api/config/file/save',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:p.toString()}).then(function(x){if(!x.ok)throw new Error(x.msg||'Save failed');dirty=false;state('Saved','ok');document.getElementById('fileMode').textContent=currentFile==='srv'?'Reloaded':'Saved and reload queued';if(currentFile==='conf'||currentFile==='usr'||currentFile==='rdr'){warn('Saved. Configuration reload queued. Existing sessions remain active until the new state is applied.');} }).catch(function(e){warn(String(e));state('Save error','error')}).finally(function(){setBusy(false)})}"
        "document.getElementById('fileArea').addEventListener('input',markDirty);document.querySelectorAll('.file-tabs .ctab').forEach(function(b){b.addEventListener('keydown',function(e){var a=[].slice.call(document.querySelectorAll('.file-tabs .ctab')),i=a.indexOf(b),n=i;if(e.key==='ArrowRight'||e.key==='ArrowDown')n=(i+1)%%a.length;else if(e.key==='ArrowLeft'||e.key==='ArrowUp')n=(i+a.length-1)%%a.length;else if(e.key==='Home')n=0;else if(e.key==='End')n=a.length-1;else return;e.preventDefault();a[n].focus();a[n].click()})});"
        "document.addEventListener('keydown',function(e){if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();saveCurrentFile()}});"
        "</script>");

    pos = emit_footer(&buf, &bsz, pos);
    PAGE_SEND_AND_FREE(fd);
}
