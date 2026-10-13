#define MODULE_LOG_PREFIX "webif"
#include "../../src/core/runtime_state.h"
#include "../../src/log/log.h"
#include "../internal/proto.h"

void send_page_power(int fd, const char *qs)
{
	char action[16], confirm[8];
	get_param(qs, "action",  action,  sizeof(action));
	get_param(qs, "confirm", confirm, sizeof(confirm));

	PAGE_INIT(8192)

	pos = emit_header(&buf, &bsz, pos, "Power", "power");

	int valid_action = (strcmp(action, "restart") == 0 || strcmp(action, "shutdown") == 0);
	int do_stop = 0, do_restart = 0;

	if (strcmp(confirm, "yes") == 0 && valid_action) {
		int is_restart = (strcmp(action, "restart") == 0);
		tcmg_log("%s requested", is_restart ? "restart" : "shutdown");
		do_stop = 1; do_restart = is_restart;

		pos = buf_printf(&buf, &bsz, pos,
			"<div class='pg-center'>"
			"<div class='done-card'>"
			"<div class='%s' style='margin:0 auto 16px'>"
			"  <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8'>"
			"    %s"
			"  </svg>"
			"</div>"
			"<h2>%s</h2>"
			"<p style='margin-top:8px'>%s</p>"
			"%s"
			"</div></div>",
			is_restart ? "dico info" : "dico danger",
			is_restart
				? "<polyline points='23 4 23 10 17 10'/><path d='M20.49 15a9 9 0 1 1-2.12-9.36L23 10'/>"
				: "<path d='M18.36 6.64a9 9 0 1 1-12.73 0'/><line x1='12' y1='2' x2='12' y2='12'/>",
			is_restart ? "Restarting&hellip;" : "Server Stopped",
			is_restart
				? "Config will be reloaded. Redirecting when back online&hellip;"
				: "TCMG has been shut down. All connections were dropped.",
			is_restart
				? "<div style='display:flex;justify-content:center;margin-top:14px'>"
				  "<div class='spill'><div class='pulse sm'></div>&nbsp;Waiting for server&hellip;</div>"
				  "</div>"
				  "<script>setTimeout(function(){"
				  "  function wait(){"
				  "    tcmg_api('/api/status')"
				  "      .then(function(){location.href='/status';},function(){setTimeout(wait,1500);});"
				  "  }"
				  "  wait();"
				  "},3500);</script>"
				: "");
	}

	else if (valid_action) {
		int is_restart = (strcmp(action, "restart") == 0);
		pos = buf_printf(&buf, &bsz, pos,
			"<div class='pg-center'>"
			"<div class='dlg'>"
			"<div class='%s' style='margin:0 auto 18px'>"
			"  <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8'>"
			"    %s"
			"  </svg>"
			"</div>"
			"<h2>%s Server?</h2>"
			"<p>%s</p>"
			"<div class='da'>"
			"  <a href='/power?action=%s&confirm=yes' class='%s'>Confirm %s</a>"
			"  <a href='/power' class='btn bg'>Cancel</a>"
			"</div>"
			"</div></div>",
			is_restart ? "dico info" : "dico danger",
			is_restart
				? "<polyline points='23 4 23 10 17 10'/><path d='M20.49 15a9 9 0 1 1-2.12-9.36L23 10'/>"
				: "<path d='M18.36 6.64a9 9 0 1 1-12.73 0'/><line x1='12' y1='2' x2='12' y2='12'/>",
			is_restart ? "Restart" : "Shutdown",
			is_restart
				? "Active connections will be dropped and configuration reloaded on restart."
				: "All active connections will be dropped immediately. The process will <strong>not</strong> restart.",
			is_restart ? "restart" : "shutdown",
			is_restart ? "btn bp" : "btn bd_",
			is_restart ? "Restart" : "Shutdown");
	}

	else {
		pos = buf_printf(&buf, &bsz, pos,
			"<div class='pw-row'>"
			"<a href='/power?action=restart' class='btn bp'>" ICON("i-refresh") "Restart</a>"
			"<a href='/power?action=shutdown' class='btn bd_'>" ICON("i-power") "Shut down</a>"
			"</div>");
	}

	pos = emit_footer(&buf, &bsz, pos);
	PAGE_SEND_AND_FREE(fd);

	if (do_stop) {
		if (do_restart) g_restart = 1;
		g_running = 0;
	}
}

void send_page_shutdown(int fd, const char *qs) { (void)qs; send_redirect(fd, "/power?action=shutdown"); }
void send_page_restart (int fd, const char *qs) { (void)qs; send_redirect(fd, "/power?action=restart"); }
