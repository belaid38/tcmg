#define MODULE_LOG_PREFIX "webif"
#include "../service/service.h"
#include "../../src/core/utils.h"
#include "../../src/core/runtime_state.h"
#include "../../src/platform/platform.h"
#include "../../src/log/log.h"
#include "../internal/proto.h"
#include "../internal/form.h"
#include <sys/stat.h>

void send_api_config_get(int fd)
{
    int bsz = 4096, pos = 0;
    char *buf = (char *)malloc((size_t)bsz);
    if (!buf) { send_json_error(fd, 503, "Service Unavailable", "out of memory"); return; }

    S_WEBIF_CONFIG_VIEW c;
    if (!webif_config_snapshot(&c)) { free(buf); send_json_error(fd, 500, "Internal Error", "config unavailable"); return; }
    char key_hex[29];
    for (int i = 0; i < 14; i++) snprintf(key_hex + i * 2, 3, "%02X", c.newcamd_key[i]);
    key_hex[28] = '\0';
    char esc_bindaddr[256], esc_cs_bind[256], esc_logfile[512], esc_user[256], esc_webif_bind[256];
    char esc_failban_allow[CFGVAL_LEN * 2];
    char esc_sname[CFGVAL_LEN * 2], esc_shost[CFGKEY_LEN * 2];
    json_escape(c.seller_name, esc_sname, sizeof(esc_sname));
    json_escape(c.seller_host, esc_shost, sizeof(esc_shost));
    json_escape(c.newcamd_bindaddr, esc_bindaddr, sizeof(esc_bindaddr));
    json_escape(c.cs378x_bindaddr, esc_cs_bind, sizeof(esc_cs_bind));
    json_escape(c.logfile, esc_logfile, sizeof(esc_logfile));
    json_escape(c.webif_user, esc_user, sizeof(esc_user));
    json_escape(c.webif_bindaddr, esc_webif_bind, sizeof(esc_webif_bind));
    json_escape(c.failban_allowlist, esc_failban_allow, sizeof(esc_failban_allow));
    pos = buf_printf(&buf, &bsz, pos,
        "{\"newcamd_port\":%d,\"newcamd_bindaddr\":\"%s\",\"newcamd_key\":\"%s\","
        "\"newcamd_keepalive\":%d,\"newcamd_mgclient\":%d,\"cccam_port\":%d,\"cs378x_port\":%d,"
        "\"cs378x_bindaddr\":\"%s\",\"sock_timeout\":%d,\"server_keepalive\":%d,\"server_keepalive_misses\":%d,"
        "\"ecm_log\":%d,\"scheduled_restart\":%d,\"scheduled_restart_time\":\"%s\",\"logfile\":\"%s\",\"webif_port\":%d,\"webif_refresh\":%d,\"webif_user\":\"%s\","
        "\"webif_bindaddr\":\"%s\",\"failban_enabled\":%d,\"failban_allowlist\":\"%s\","
        "\"failban_max_fails\":%d,\"failban_ban_secs\":%d,\"seller_name\":\"%s\",\"seller_type\":\"%s\",\"seller_host\":\"%s\",\"seller_port\":%d}",
        c.newcamd_port, esc_bindaddr, key_hex, (int)c.newcamd_keepalive, (int)c.newcamd_mgclient,
        c.cccam_port, c.cs378x_port, esc_cs_bind, c.sock_timeout, c.server_keepalive,
        c.server_keepalive_misses, (int)c.ecm_log, (int)c.scheduled_restart_enabled, c.scheduled_restart_time, esc_logfile, c.webif_port, c.webif_refresh,
        esc_user, esc_webif_bind, (int)c.failban_enabled, esc_failban_allow, c.failban_max_fails, (int)c.failban_ban_secs,
        esc_sname, c.seller_type, esc_shost, c.seller_port);
    send_response(fd, 200, "OK", "application/json", buf, pos);
    free(buf);
}

typedef struct { const char *body; char err[96]; } fparse;

static void fld(fparse *p, const char *key, char *out, size_t sz)
{
	out[0] = '\0';
	if (p->err[0]) return;
	if (webif_form_copy(p->body, key, out, sz) < 0)
		snprintf(p->err, sizeof(p->err), "%s is too long", key);
}

static void bad(fparse *p, const char *key, const char *why)
{
	if (!p->err[0]) snprintf(p->err, sizeof(p->err), "invalid %s: %s", key, why);
}

static int num(fparse *p, const char *key, const char *s, long lo, long hi, long *out)
{
	if (!s[0]) return 0;
	char *e = NULL;
	errno = 0;
	long  v = strtol(s, &e, 10);
	if (errno == ERANGE || e == s || *e || v < lo || v > hi) {
		char why[48];
		snprintf(why, sizeof(why), "expected %ld-%ld", lo, hi);
		bad(p, key, why);
		return 0;
	}
	*out = v;
	return 1;
}

static int hexkey(fparse *p, const char *key, const char *s, uint8_t out[14])
{
	if (!s[0]) return 0;
	if (strlen(s) != 28) { bad(p, key, "expected 28 hex digits"); return 0; }
	for (int i = 0; i < 28; i++)
		if (!isxdigit((unsigned char)s[i])) { bad(p, key, "expected 28 hex digits"); return 0; }
	for (int i = 0; i < 14; i++) {
		char b[3] = { s[i * 2], s[i * 2 + 1], '\0' };
		out[i] = (uint8_t)strtol(b, NULL, 16);
	}
	return 1;
}

static void text_ok(fparse *p, const char *key, const char *s)
{
	if (s[0] && !web_valid_text(s)) bad(p, key, "must not contain '#', control characters or edge spaces");
}

static void ip_ok(fparse *p, const char *key, const char *s)
{
	if (!web_valid_ipv4_or_empty(s)) bad(p, key, "expected an IPv4 address");
}

void handle_api_config_save(int fd, const char *post_body)
{
	fparse P = { post_body, "" };
	char newcamd_port_s[16], newcamd_bindaddr[MAXIPLEN + 8], newcamd_key_s[40], keepalive_s[8], mgclient_s[8];
	char cccam_port_s[16], cs378x_port_s[16], cs378x_bindaddr[MAXIPLEN+8], sock_timeout_s[16], server_keepalive_s[16], server_keepalive_misses_s[16], ecm_log_s[8], logfile[CFGPATH_LEN];
	char webif_port_s[16], webif_refresh_s[16], scheduled_restart_s[8], scheduled_restart_time_s[16], webif_user[CFGKEY_LEN], webif_pass[CFGKEY_LEN];
	char webif_bindaddr[MAXIPLEN + 8];
	char failban_enabled_s[8], failban_allowlist_s[CFGVAL_LEN], failban_maxfails_s[16], failban_bansecs_s[16];
	char seller_name[CFGVAL_LEN], seller_type[16], seller_host[CFGKEY_LEN], seller_port_s[16];

	fld(&P, "newcamd_port",      newcamd_port_s,   sizeof(newcamd_port_s));
	fld(&P, "newcamd_bindaddr",  newcamd_bindaddr, sizeof(newcamd_bindaddr));
	fld(&P, "newcamd_key",       newcamd_key_s,    sizeof(newcamd_key_s));
	fld(&P, "newcamd_keepalive", keepalive_s,      sizeof(keepalive_s));
	fld(&P, "newcamd_mgclient",  mgclient_s,       sizeof(mgclient_s));
	fld(&P, "cccam_port",        cccam_port_s,     sizeof(cccam_port_s));
	fld(&P, "cs378x_port",       cs378x_port_s,    sizeof(cs378x_port_s));
	fld(&P, "cs378x_bindaddr",   cs378x_bindaddr,   sizeof(cs378x_bindaddr));
	fld(&P, "sock_timeout",      sock_timeout_s,   sizeof(sock_timeout_s));
	fld(&P, "server_keepalive", server_keepalive_s, sizeof(server_keepalive_s));
	fld(&P, "server_keepalive_misses", server_keepalive_misses_s, sizeof(server_keepalive_misses_s));
	fld(&P, "ecm_log",           ecm_log_s,        sizeof(ecm_log_s));
	fld(&P, "scheduled_restart", scheduled_restart_s, sizeof(scheduled_restart_s));
	fld(&P, "scheduled_restart_time", scheduled_restart_time_s, sizeof(scheduled_restart_time_s));
	fld(&P, "logfile",           logfile,          sizeof(logfile));
	fld(&P, "webif_port",        webif_port_s,     sizeof(webif_port_s));
	fld(&P, "webif_refresh",     webif_refresh_s,  sizeof(webif_refresh_s));
	fld(&P, "webif_user",        webif_user,       sizeof(webif_user));
	fld(&P, "webif_pass",        webif_pass,       sizeof(webif_pass));
	fld(&P, "webif_bindaddr",    webif_bindaddr,   sizeof(webif_bindaddr));
	fld(&P, "failban_enabled", failban_enabled_s, sizeof(failban_enabled_s));
	fld(&P, "failban_allowlist", failban_allowlist_s, sizeof(failban_allowlist_s));
	fld(&P, "failban_max_fails", failban_maxfails_s, sizeof(failban_maxfails_s));
	fld(&P, "failban_ban_secs",  failban_bansecs_s,  sizeof(failban_bansecs_s));
	fld(&P, "seller_name", seller_name, sizeof(seller_name));
	fld(&P, "seller_type", seller_type, sizeof(seller_type));
	fld(&P, "seller_host", seller_host, sizeof(seller_host));
	fld(&P, "seller_port", seller_port_s, sizeof(seller_port_s));

	long v_newcamd_port = 0, v_ka = 0, v_mgc = 0, v_cccam = 0, v_cs378x = 0, v_sock = 0, v_ska = 0, v_skam = 0, v_ecmlog = 0, v_sched = 0, v_wport = 0, v_wref = 0;
		long v_fb_enabled = 0, v_fbmax = 0, v_fbsecs = 0, v_sport = 0;
	uint8_t k_new[14];

	int h_np  = num(&P, "newcamd_port",      newcamd_port_s,   0, 65535, &v_newcamd_port);
	int h_ka  = num(&P, "newcamd_keepalive", keepalive_s,      0, 1, &v_ka);
	int h_mgc = num(&P, "newcamd_mgclient",  mgclient_s,       0, 1, &v_mgc);
	int h_cc  = num(&P, "cccam_port",        cccam_port_s,     0, 65535, &v_cccam);
	int h_cs  = num(&P, "cs378x_port",       cs378x_port_s,    0, 65535, &v_cs378x);
	ip_ok(&P, "cs378x_bindaddr", cs378x_bindaddr);
	int h_st  = num(&P, "sock_timeout",      sock_timeout_s,   5, 600, &v_sock);
	int h_ska = num(&P, "server_keepalive", server_keepalive_s, 0, 3600, &v_ska);
	int h_skam = num(&P, "server_keepalive_misses", server_keepalive_misses_s, 1, 20, &v_skam);
	int h_el  = num(&P, "ecm_log",           ecm_log_s,        0, 1, &v_ecmlog);
	int h_sched = num(&P, "scheduled_restart", scheduled_restart_s, 0, 1, &v_sched);
	int h_wp  = num(&P, "webif_port",        webif_port_s,     1, 65535, &v_wport);
	int h_wr  = num(&P, "webif_refresh",     webif_refresh_s,  0, 3600, &v_wref);
	int h_fbe = num(&P, "failban_enabled", failban_enabled_s, 0, 1, &v_fb_enabled);
	int h_fbm = num(&P, "failban_max_fails", failban_maxfails_s, 1, 1000, &v_fbmax);
	int h_fbs = num(&P, "failban_ban_secs",  failban_bansecs_s,  10, 604800, &v_fbsecs);
	int h_sp  = num(&P, "seller_port", seller_port_s, 0, 65535, &v_sport);
	int h_k1  = hexkey(&P, "newcamd_key", newcamd_key_s, k_new);
	ip_ok(&P, "newcamd_bindaddr", newcamd_bindaddr);
	ip_ok(&P, "webif_bindaddr",   webif_bindaddr);
	text_ok(&P, "logfile", logfile);
	text_ok(&P, "webif_user", webif_user);
	text_ok(&P, "webif_pass", webif_pass);
	text_ok(&P, "failban_allowlist", failban_allowlist_s);
	text_ok(&P, "seller_name", seller_name);
	text_ok(&P, "seller_host", seller_host);
	if (seller_type[0] && strcmp(seller_type, "cccam") && strcmp(seller_type, "newcamd") && strcmp(seller_type, "cs378x"))
		bad(&P, "seller_type", "expected cccam, newcamd or cs378x");
	if (scheduled_restart_time_s[0]) {
		int hh = -1, mm = -1;
		if (sscanf(scheduled_restart_time_s, "%d:%d", &hh, &mm) != 2 || hh < 0 || hh > 23 || mm < 0 || mm > 59 || strlen(scheduled_restart_time_s) != 5 || scheduled_restart_time_s[2] != ':')
			bad(&P, "scheduled_restart_time", "expected HH:MM");
	}

	if (P.err[0]) {
		send_json_error(fd, 400, "Bad Request", P.err);
		return;
	}

	S_WEBIF_CONFIG_PATCH patch;
	memset(&patch, 0, sizeof(patch));
	patch.has_newcamd_port = h_np; patch.newcamd_port = (int)v_newcamd_port;
	patch.has_newcamd_bindaddr = newcamd_bindaddr[0] || form_has(post_body, "newcamd_bindaddr");
	tcmg_strlcpy(patch.newcamd_bindaddr, newcamd_bindaddr, sizeof(patch.newcamd_bindaddr));
	patch.has_newcamd_key = h_k1; if (h_k1) memcpy(patch.newcamd_key, k_new, sizeof(patch.newcamd_key));
	patch.has_newcamd_keepalive = h_ka; patch.newcamd_keepalive = (int8_t)v_ka;
	patch.has_newcamd_mgclient = h_mgc; patch.newcamd_mgclient = (int8_t)v_mgc;
	patch.has_cccam_port = h_cc; patch.cccam_port = (int)v_cccam;
	patch.has_cs378x_port = h_cs; patch.cs378x_port = (int)v_cs378x;
	patch.has_cs378x_bindaddr = cs378x_bindaddr[0] || form_has(post_body, "cs378x_bindaddr");
	tcmg_strlcpy(patch.cs378x_bindaddr, cs378x_bindaddr, sizeof(patch.cs378x_bindaddr));
	patch.has_sock_timeout = h_st; patch.sock_timeout = (int)v_sock;
	patch.has_server_keepalive = h_ska; patch.server_keepalive = (int)v_ska;
	patch.has_server_keepalive_misses = h_skam; patch.server_keepalive_misses = (int)v_skam;
	patch.has_ecm_log = h_el; patch.ecm_log = (int8_t)v_ecmlog;
	patch.has_scheduled_restart = h_sched; patch.scheduled_restart_enabled = (int8_t)v_sched;
	patch.has_scheduled_restart_time = scheduled_restart_time_s[0] || form_has(post_body, "scheduled_restart_time");
	tcmg_strlcpy(patch.scheduled_restart_time, scheduled_restart_time_s, sizeof(patch.scheduled_restart_time));
	patch.has_logfile = logfile[0] || form_has(post_body, "logfile");
	tcmg_strlcpy(patch.logfile, logfile, sizeof(patch.logfile));
	patch.has_webif_port = h_wp; patch.webif_port = (int)v_wport;
	patch.has_webif_refresh = h_wr; patch.webif_refresh = (int)v_wref;
	patch.has_webif_user = webif_user[0] || form_has(post_body, "webif_user");
	patch.has_webif_pass = webif_pass[0] || form_has(post_body, "webif_pass");
	patch.has_webif_bindaddr = webif_bindaddr[0] || form_has(post_body, "webif_bindaddr");
	tcmg_strlcpy(patch.webif_user, webif_user, sizeof(patch.webif_user));
	tcmg_strlcpy(patch.webif_pass, webif_pass, sizeof(patch.webif_pass));
	tcmg_strlcpy(patch.webif_bindaddr, webif_bindaddr, sizeof(patch.webif_bindaddr));
	patch.has_failban_enabled = h_fbe; patch.failban_enabled = (int8_t)v_fb_enabled;
	patch.has_failban_allowlist = failban_allowlist_s[0] || form_has(post_body, "failban_allowlist");
	tcmg_strlcpy(patch.failban_allowlist, failban_allowlist_s, sizeof(patch.failban_allowlist));
	patch.has_failban_max_fails = h_fbm; patch.failban_max_fails = (int)v_fbmax;
	patch.has_failban_ban_secs = h_fbs; patch.failban_ban_secs = (int)v_fbsecs;
	patch.has_seller_name = seller_name[0] || form_has(post_body, "seller_name");
	tcmg_strlcpy(patch.seller_name, seller_name, sizeof(patch.seller_name));
	patch.has_seller_type = seller_type[0] != '\0';
	tcmg_strlcpy(patch.seller_type, seller_type, sizeof(patch.seller_type));
	patch.has_seller_host = seller_host[0] || form_has(post_body, "seller_host");
	tcmg_strlcpy(patch.seller_host, seller_host, sizeof(patch.seller_host));
	patch.has_seller_port = h_sp || form_has(post_body, "seller_port");
	patch.seller_port = (int)v_sport;

	bool restart_required = false;
	if (!webif_config_apply(&patch, &restart_required)) {
		send_json_error(fd, 500, "Internal Error", "failed to write config file");
		return;
	}
	if (restart_required) {
		send_json_ok_raw(fd, "{\"ok\":true,\"restart_required\":true,\"msg\":\"Configuration saved. Restart TCMG to apply listener changes.\"}");
	} else {
		send_json_ok_raw(fd, "{\"ok\":true,\"restart_required\":false,\"msg\":\"Configuration saved and reload scheduled.\"}");
	}

}

static bool api_file_target(const char *kind, char *path, size_t psz, const char **label)
{
    if (!strcmp(kind, "conf")) { tcmg_build_path(path, psz, g_cfgdir, TCMG_CFG_FILE); if (label) *label = TCMG_CFG_FILE; return true; }
    if (!strcmp(kind, "usr"))  { tcmg_build_path(path, psz, g_cfgdir, TCMG_USER_FILE); if (label) *label = TCMG_USER_FILE; return true; }
    if (!strcmp(kind, "rdr"))  { tcmg_build_path(path, psz, g_cfgdir, TCMG_SERVER_FILE); if (label) *label = TCMG_SERVER_FILE; return true; }
    if (!strcmp(kind, "srv"))  { tcmg_build_path(path, psz, g_cfgdir, TCMG_SRVID_FILE); if (label) *label = TCMG_SRVID_FILE; return true; }
    return false;
}

static char *api_read_file(const char *path, size_t max, size_t *out_len, bool *truncated)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    struct stat st;
    if (fstat(fileno(fp), &st) != 0 || st.st_size < 0) { fclose(fp); return NULL; }
    size_t limit = (size_t)st.st_size;
    bool cut = false;
    if (limit > max) { limit = max; cut = true; }
    char *buf = malloc(limit + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t n = fread(buf, 1, limit, fp);
    int ferr = ferror(fp);
    fclose(fp);
    if (ferr) { free(buf); return NULL; }
    if (out_len) *out_len = n;
    if (truncated) *truncated = cut;
    buf[n] = '\0';
    return buf;
}

void send_api_file_get(int fd, const char *qs)
{
    char kind[8] = "";
    get_param(qs, "file", kind, sizeof(kind));
    char path[CFGPATH_LEN];
    const char *label = NULL;
    if (!api_file_target(kind, path, sizeof(path), &label)) {
        send_json_error(fd, 400, "Bad Request", "invalid file");
        return;
    }

    bool truncated = false;
    size_t len = 0;
    char *content = api_read_file(path, WEB_FILE_VIEW_MAX, &len, &truncated);
    if (!content) {
        send_json_error(fd, 404, "Not Found", "file not found");
        return;
    }
    size_t esc_cap = len * 6 + 256;
    char *esc = malloc(esc_cap);
    if (!esc) { free(content); send_json_error(fd, 503, "Service Unavailable", "out of memory"); return; }
    json_escape(content, esc, (int)esc_cap);
    size_t out_cap = esc_cap + 256;
    char *out = malloc(out_cap);
    if (!out) { free(esc); free(content); send_json_error(fd, 503, "Service Unavailable", "out of memory"); return; }
    int n = snprintf(out, out_cap,
        "{\"ok\":true,\"file\":\"%s\",\"label\":\"%s\",\"size\":%llu,\"truncated\":%s,\"content\":\"%s\"}",
        kind, label, (unsigned long long)len, truncated ? "true" : "false", esc);
    free(esc);
    free(content);
    send_response(fd, 200, "OK", "application/json", out, n);
    free(out);
}

void handle_api_file_save(int fd, const char *post_body)
{
    char file_s[8] = "";
    char *f = form_get_alloc(post_body, "file");
    if (f) { tcmg_strlcpy(file_s, f, sizeof(file_s)); free(f); }
    char *content = form_get_alloc(post_body, "content");
    if (!strcmp(file_s, "conf")) {
        if (!content || !content[0]) { free(content); send_json_error(fd, 400, "Bad Request", "empty content rejected"); return; }
        size_t len = strlen(content);
        bool ok = webif_save_config_file(content, len);
        free(content);
        if (!ok) { send_json_error(fd, 400, "Bad Request", "config parse or write failed"); return; }
        tcmg_log("%s", "tcmg.conf saved via api -- reload triggered");
        send_json_ok(fd, "ok");
        return;
    }
    if (!strcmp(file_s, "srv")) {
        if (!content || !content[0]) { free(content); send_json_error(fd, 400, "Bad Request", "empty content rejected"); return; }
        int loaded = 0;
        bool ok = webif_save_srvid_file(content, strlen(content), &loaded);
        free(content);
        if (!ok) { send_json_error(fd, 500, "Internal Error", "cannot write file"); return; }
        tcmg_log("srvid2 saved entries=%d reloaded", loaded);
        send_json_ok(fd, "ok");
        return;
    }
    if (!strcmp(file_s, "usr") || !strcmp(file_s, "rdr")) {
        if (!content) { free(content); send_json_error(fd, 400, "Bad Request", "missing content"); return; }
        char err[384] = "";
        bool users = !strcmp(file_s, "usr");
        bool ok = users ? webif_save_users_file(content, strlen(content), err, sizeof(err))
                        : webif_save_readers_file(content, strlen(content), err, sizeof(err));
        free(content);
        if (!ok) { send_json_error(fd, 400, "Bad Request", err[0] ? err : "validation or write failed"); return; }
        tcmg_log("%s saved via file editor -- reload triggered", users ? "tcmg.users" : "tcmg.readers");
        send_json_ok(fd, "ok");
        return;
    }
    free(content);
    send_json_error(fd, 400, "Bad Request", "invalid file");
}
