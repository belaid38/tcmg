#define MODULE_LOG_PREFIX "webif"
#include "../service/service.h"
#include "../../src/core/constants.h"
#include "../../src/core/utils.h"
#include "../../src/log/log.h"
#include "../internal/proto.h"

static void fmt_ban_duration(long s, char *out, size_t sz)
{
	if (s < 0) s = 0;
	long d = s / 86400;
	s %= 86400;
	long h = s / 3600;
	s %= 3600;
	long m = s / 60;
	long sec = s % 60;
	if (d > 0) snprintf(out, sz, "%ldd %ldh %ldm %lds", d, h, m, sec);
	else if (h > 0) snprintf(out, sz, "%ldh %ldm %lds", h, m, sec);
	else if (m > 0) snprintf(out, sz, "%ldm %lds", m, sec);
	else snprintf(out, sz, "%lds", sec);
}

static int failban_clear(const char *clearip)
{
	if (clearip && clearip[0]) return webif_ban_clear(clearip);
	return webif_ban_clear_all();
}

void handle_api_failban_clear(int fd, const char *qs)
{
	char clearip[MAXIPLEN] = "";
	get_param(qs, "ip", clearip, sizeof(clearip));

	if (!clearip[0]) {
		send_json_error(fd, 400, "Bad Request", "missing ip");
		return;
	}

	int n = failban_clear(clearip);
	tcmg_log("ban cleared for ip=%s", clearip);

	char msg[128];
	snprintf(msg, sizeof(msg), n ? "Unbanned %s" : "%s was not banned", clearip);
	send_json_ok(fd, msg);
}

void handle_api_failban_clearall(int fd)
{
	int n = failban_clear(NULL);
	tcmg_log("%s", "all bans cleared");

	char msg[64];
	snprintf(msg, sizeof(msg), "Cleared %d ban(s)", n);
	send_json_ok(fd, msg);
}

void send_page_failban(int fd, const char *qs)
{
	char action[32], clearip[MAXIPLEN];
	get_param(qs, "action", action,  sizeof(action));
	get_param(qs, "ip",     clearip, sizeof(clearip));

	if (strcmp(action, "clear") == 0 && clearip[0]) {
		failban_clear(clearip);
		tcmg_log("ban cleared for ip=%s", clearip);
	} else if (strcmp(action, "clearall") == 0) {
		failban_clear(NULL);
		tcmg_log("%s", "all bans cleared");
	}

	PAGE_INIT(8192)

	pos = emit_header(&buf, &bsz, pos, "Fail-Ban", "failban");

	S_WEBIF_BAN_STATS bstats;
	webif_ban_snapshot(NULL, 0, &bstats);
	int ban_cap = bstats.active_bans > 0 ? bstats.active_bans : 1;
	S_WEBIF_BAN_VIEW *bans = calloc((size_t)ban_cap, sizeof(*bans));
	int nbans = bans ? webif_ban_snapshot(bans, (size_t)ban_cap, &bstats) : 0;
	int total_bans = bstats.active_bans;
	int max_fails = bstats.max_fails;
	int ban_secs = bstats.ban_secs;
	char ban_duration[64];
	fmt_ban_duration(ban_secs, ban_duration, sizeof(ban_duration));
	time_t now = time(NULL);

	pos = buf_printf(&buf, &bsz, pos,
		"<section class='fbhead' aria-label='Fail-Ban summary'>"
		"<div class='fbstats' id='fbStats'>"
		"<span>Active bans<b class='%s'>%d</b></span>"
		"<span>Max fails<b>%d</b></span>"
		"<span>Ban duration<b>%s</b></span>"
		"</div>"
		"<button type='button' class='tool danger' id='fbClearAll'%s>"
		ICON("i-trash") "Clear All</button>"
		"</section>",
		total_bans > 0 ? "tr" : "tg", total_bans, max_fails, ban_duration,
		total_bans > 0 ? "" : " hidden");

	pos = buf_printf(&buf, &bsz, pos,
		"<div class='tw cm auto'><table>"
		"<thead><tr>"
		"<th>IP Address</th><th>Country</th><th>Remaining</th><th>Action</th>"
		"</tr></thead><tbody id='fbBody'>");

	int shown = 0;
	for (int bi = 0; bi < nbans; bi++) {
		S_WEBIF_BAN_VIEW *b = &bans[bi];
		if (b->until <= now) continue;
		long secs_left = (long)(b->until - now);
		char esc_ip[128], left_txt[64];
		html_escape(b->ip, esc_ip, sizeof(esc_ip));
		fmt_ban_duration(secs_left, left_txt, sizeof(left_txt));
		pos = buf_printf(&buf, &bsz, pos,
			"<tr class='fbrow' data-ip='%s'>"
			"<td class='fbc-value fbc-ip'><span class='fbc-label'>IP</span><span class='mono bold'>%s</span></td>"
			"<td class='fbc-value fbc-country'><span class='fbc-label'>Country</span><span class='flg fbflag' data-ip='%s' title=''></span><span class='fbcountry-name' aria-live='polite'>&mdash;</span></td>"
			"<td class='fbc-value fbc-left'><span class='fbc-label'>Left</span><span class='mono to fbcd' data-left='%ld'>%s</span></td>"
			"<td class='fbc-action'><button type='button' class='tool sm' data-a='unban'>"
			ICON("i-unban") "Unban</button></td>"
			"</tr>",
			esc_ip, esc_ip, esc_ip, secs_left, left_txt);
		shown++;
	}
	free(bans);

	if (!shown)
		pos = buf_printf(&buf, &bsz, pos,
			"<tr class='erow'><td colspan='4'>"
			"<svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='var(--gr)' stroke-width='1.8'"
			" style='vertical-align:-3px;margin-right:6px'>"
			"<path d='M22 11.08V12a10 10 0 1 1-5.93-9.14'/>"
			"<polyline points='22 4 12 14.01 9 11.01'/>"
			"</svg><span class='tg'>All clear</span> &mdash; no active bans"
			"</td></tr>");

	pos = buf_printf(&buf, &bsz, pos,
		"</tbody></table></div>"
		"<script>(function(){"
		"  var body=document.getElementById('fbBody');"
		"  var busy=false;"

		"  var tbox=null;"
		"  function toast(msg,kind){"
		"    if(!tbox){"
		"      tbox=document.createElement('div');"
		"      tbox.className='toasts';"
		"      tbox.setAttribute('role','status');"
		"      tbox.setAttribute('aria-live','polite');"
		"      document.body.appendChild(tbox);"
		"    }"
		"    var t=document.createElement('div');"
		"    t.className='toast '+(kind||'');"
		"    var ic=document.createElement('span'); ic.className='toast-ico'; ic.setAttribute('aria-hidden','true');"
		"    ic.innerHTML=(kind==='err')?\"<svg viewBox='0 0 24 24'><circle cx='12' cy='12' r='9'></circle><path d='M12 7v6M12 17h.01'></path></svg>\":\"<svg viewBox='0 0 24 24'><path d='M5 12.5l4 4L19 7.5'></path></svg>\";" \
		"    var tx=document.createElement('span'); tx.textContent=msg; t.appendChild(ic); t.appendChild(tx);"
		"    tbox.appendChild(t);"
		"    setTimeout(function(){"
		"      t.style.transition='opacity .25s';t.style.opacity='0';"
		"      setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},260);"
		"    },kind==='err'?5000:2600);"
		"  }"

		"  function fmtDur(v){"
		"    v=Math.max(0,parseInt(v,10)||0);var d=Math.floor(v/86400);v%%=86400;var h=Math.floor(v/3600);v%%=3600;var m=Math.floor(v/60);var s=v%%60;"
		"    if(d) return d+'d '+h+'h '+m+'m '+s+'s';"
		"    if(h) return h+'h '+m+'m '+s+'s';"
		"    if(m) return m+'m '+s+'s';"
		"    return s+'s';"
		"  }"
		"  function applyFlags(){var els=body.querySelectorAll('.fbflag');for(var i=0;i<els.length;i++){var el=els[i],ip=el.getAttribute('data-ip'),name=el.parentNode?el.parentNode.querySelector('.fbcountry-name'):null;if(typeof _load_country==='function')_load_country(ip,el,name);}}"
		"  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',applyFlags,{once:true});else applyFlags();"
		"  function tickCountdown(){"
		"    var rows=body.querySelectorAll('.fbcd');"
		"    for(var i=0;i<rows.length;i++){"
		"      var el=rows[i], v=parseInt(el.getAttribute('data-left'),10);"
		"      if(isNaN(v)) v=0;"
		"      if(v>0) v--;"
		"      el.setAttribute('data-left',v);"
		"      el.textContent=fmtDur(v);"
		"      if(v===0&&el.parentNode) el.parentNode.classList.add('dim');"
		"    }"
		"    setTimeout(tickCountdown,1000);"
		"  }"
		"  applyFlags();"
		"  setTimeout(tickCountdown,1000);"

		"  function softRefresh(){"
		"    if(busy) return Promise.resolve();"
		"    busy=true;"
		"    return tcmg_html('/failban')"
		"      .then(function(r){"
		"        if(r.status===401){location.href='/login';return null;}"
		"        return r.text();"
		"      })"
		"      .then(function(html){"
		"        busy=false;"
		"        if(!html) return;"
		"        var doc=new DOMParser().parseFromString(html,'text/html');"
		"        var nb=doc.getElementById('fbBody');"
		"        if(nb){body.innerHTML=nb.innerHTML;applyFlags();}"
		"        var ns=doc.getElementById('fbStats'), cs=document.getElementById('fbStats');"
		"        if(ns&&cs) cs.innerHTML=ns.innerHTML;"
		"        var ca=document.getElementById('fbClearAll');"
		"        if(ca) ca.hidden=!body.querySelector('.fbrow');"
		"      })"
		"      .catch(function(){busy=false;});"
		"  }"
		"  window.tcmgSoftRefresh=softRefresh;"

		"  function post(url,okmsg){"
		"    return tcmg_api(url,{method:'POST'})"
		"      .then(function(d){"
		"        toast(d&&d.msg?d.msg:okmsg,(d&&d.ok===false)?'err':'ok');"
		"        return softRefresh();"
		"      })"
		"      .catch(function(){"
		"        toast('Request failed','err');"
		"      });"
		"  }"

		"  var ca=document.getElementById('fbClearAll');"
		"  if(ca) ca.addEventListener('click',function(){"
		"    if(!confirm('Clear all active bans?')) return;"
		"    post('/api/failban/clearall','Cleared');"
		"  });"

		"  body.addEventListener('click',function(e){"
		"    var btn=e.target.closest?e.target.closest('[data-a=\"unban\"]'):null;"
		"    if(!btn) return;"
		"    var tr=btn.closest('tr');"
		"    if(!tr) return;"
		"    var ip=tr.getAttribute('data-ip');"
		"    post('/api/failban/clear?ip='+encodeURIComponent(ip),'Unbanned '+ip);"
		"  });"
		"})();</script>");

	pos = emit_footer(&buf, &bsz, pos);
	PAGE_SEND_AND_FREE(fd);
}
