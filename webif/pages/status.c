#define MODULE_LOG_PREFIX "webif"
#include "../service/service.h"
#include "../../src/core/utils.h"
#include "../../src/log/log.h"
#include "../../src/pcsc/pcsc.h"
#include "../internal/proto.h"

static int emit_stat_card(char **buf, int *bsz, int pos,
                          const char *color, const char *label,
                          const char *sv_id, const char *value,
                          const char *sub, const char *extra)
{
	return buf_printf(buf, bsz, pos,
		"<div class='sc %s'>"
		"<div class='sl_'>%s</div>"
		"<div class='sv'%s%s%s>%s</div>"
		"%s"
		"%s%s%s"
		"</div>",
		color, label,
		sv_id ? " id='" : "", sv_id ? sv_id : "", sv_id ? "'" : "",
		value,
		extra ? extra : "",
		(sub && sub[0]) ? (strstr(sub, "<a ") ? "<div class='sd sd-lnk'>" : "<div class='sd sd-txt'>") : "", (sub && sub[0]) ? sub : "", (sub && sub[0]) ? "</div>" : "");
}

void send_page_status(int fd)
{
	PAGE_INIT(16384)

	pos = emit_header(&buf, &bsz, pos, "Dashboard", "status");

	S_SERVER_STATS st = collect_stats();
	char hrstr[16];
	snprintf(hrstr, sizeof(hrstr),
	         st.ecm_total > 0 ? "%.1f%%" : "0.0%%", st.hit_rate);

	char hbf_extra[192];
	snprintf(hbf_extra, sizeof(hbf_extra),
	         "  <div class='hbw'>"
	         "<div class='hbf' id='p_hbf' style='width:%.0f%%'></div></div>",
	         st.hit_rate);

	int dis_cnt = 0, exp_cnt = 0;
	webif_account_status_counts(&dis_cnt, &exp_cnt);

	pos = buf_printf(&buf, &bsz, pos, "<div class='cg'>");

	pos = emit_stat_card(&buf, &bsz, pos, "bl", "Uptime", "p_up",
	    st.uptime_str, "since start", NULL);

	{
		char conn_val[16], conn_sub[64];
		snprintf(conn_val, sizeof(conn_val), "%d", st.active_conns);
		snprintf(conn_sub, sizeof(conn_sub), "of <span id='p_acc'>%d</span> accounts", st.naccounts);
		pos = emit_stat_card(&buf, &bsz, pos, "gr", "Online", "p_conn",
		    conn_val, conn_sub, NULL);
	}

	pos = buf_printf(&buf, &bsz, pos,
		"<div class='sc am'><div class='sl_'><span class='l-full'>Disabled / Expired</span><span class='l-short'>Off / Exp</span></div>"
		"<div class='sv'><span id='p_dis'>%d</span> / <span id='p_exp'>%d</span></div>"
		"<div class='sd sd-txt'>accounts</div></div>", dis_cnt, exp_cnt);

	{
		char v[24];
		snprintf(v, sizeof(v), "%lld", (long long)st.ecm_total);
		pos = emit_stat_card(&buf, &bsz, pos, "vi", "ECM", "p_ecm", v, "requests", NULL);
		snprintf(v, sizeof(v), "%lld", (long long)st.cw_found);
		pos = emit_stat_card(&buf, &bsz, pos, "te", "CW Found", "p_hit", v, "successful", NULL);
		snprintf(v, sizeof(v), "%lld", (long long)st.cw_not);
		pos = emit_stat_card(&buf, &bsz, pos, "re", "CW Miss", "p_miss", v, "no CW", NULL);
	}

	{
		char hsub[320];
		snprintf(hsub, sizeof(hsub),
		    "<a href='#' class='sd-link' onclick=\"if(confirm('Reset all stats?')){tcmg_api('/api/resetstats',{method:'POST'}).then(function(){if(typeof _poll==='function')_poll();}).catch(function(){});}return false\">reset<span class='lw'> stats</span></a>");
		pos = emit_stat_card(&buf, &bsz, pos, "cy", "Hit Rate", "p_hr", hrstr, hsub, hbf_extra);
	}

	{
		char ban_val[8];
		snprintf(ban_val, sizeof(ban_val), "%d", st.nbans);
		pos = emit_stat_card(&buf, &bsz, pos, "or", "Banned IPs", "p_ban", ban_val,
		    "<a href='/failban' class='sd-link'>view<span class='lw'> list</span> &rarr;</a>", NULL);
	}

	pos = buf_printf(&buf, &bsz, pos, "</div>");

	pos = buf_printf(&buf, &bsz, pos,
		"<div class='tw cm auto'><table>"
		"<thead><tr>"
		"<th style='width:30px' title='Location'>" ICO_GLOBE "</th>"
		"<th>User</th><th>IP Address</th><th>CAID</th>"
		"<th>SID</th><th>Channel</th><th>Connected</th><th>Idle</th><th></th>"
		"</tr></thead>"
		"<tbody id='p_clients'>"
		"</tbody></table></div>");

	pos = emit_footer(&buf, &bsz, pos);
	PAGE_SEND_AND_FREE(fd);
}
