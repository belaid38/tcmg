#define MODULE_LOG_PREFIX "webif"
#include "../../src/log/log.h"
#include "../internal/proto.h"

typedef struct {
	char **buf;
	int *bsz;
	int pos;
	int failed;
	int json;
} s_log_emit_ctx;

static int emit_livelog_line(int32_t id, const char *line, const char *usr, void *ctx)
{
	(void)id; (void)usr;
	s_log_emit_ctx *c = (s_log_emit_ctx *)ctx;
	int p = buf_printf(c->buf, c->bsz, c->pos, "<span class='ll-line' data-r=\"");
	p = buf_html_string(c->buf, c->bsz, p, line);
	if (p < 0) { c->failed = 1; return -1; }
	p = buf_printf(c->buf, c->bsz, p, "\">");
	p = buf_html_string(c->buf, c->bsz, p, line);
	if (p < 0) { c->failed = 1; return -1; }
	c->pos = buf_printf(c->buf, c->bsz, p, "</span>");
	return 0;
}

static int emit_logpoll_line(int32_t id, const char *line, const char *usr, void *ctx)
{
	s_log_emit_ctx *c = (s_log_emit_ctx *)ctx;
	int p = buf_printf(c->buf, c->bsz, c->pos,
		"%s{\"id\":%d,\"usr\":\"",
		c->pos > 0 && (*c->buf)[c->pos - 1] != '[' ? "," : "", id);
	p = buf_json_string(c->buf, c->bsz, p, usr && usr[0] ? usr : "");
	if (p < 0) { c->failed = 1; return -1; }
	p = buf_printf(c->buf, c->bsz, p, "\",\"line\":\"");
	p = buf_json_string(c->buf, c->bsz, p, line);
	if (p < 0) { c->failed = 1; return -1; }
	c->pos = buf_printf(c->buf, c->bsz, p, "\"}");
	return 0;
}

void send_page_livelog(int fd)
{
	PAGE_INIT(16384)
	pos = emit_header(&buf, &bsz, pos, "Live Log", "livelog");

	int32_t total = log_ring_total();
	int32_t from_id = total > WEB_MAX_LINES_POLL ? total - WEB_MAX_LINES_POLL : 0;

	pos = buf_printf(&buf, &bsz, pos,
		"<div class='ll-bar'>"
		"<div class='ll-controls'>"
		"<input class='ls' id='filter' name='log_filter' type='search' autocomplete='off' autocorrect='off' autocapitalize='off' spellcheck='false' inputmode='search' placeholder='Filter&hellip;' oninput='applyFilter()' title='Regex, e.g.: hit|miss' aria-label='Log filter'>"
		"<button class='btn bg sm' onclick='clearLog()'>" ICO_TRASH " Clear</button>"
		"<button class='btn bg sm' onclick='prepSave()'><svg viewBox='0 0 24 24' aria-hidden='true'><path d='M12 3v11m0 0 4-4m-4 4-4-4M5 19h14'/></svg> Save</button>"
		"<label class='ll-chk'><input type='checkbox' id='asc' checked>Scroll</label>"
		"<label class='ll-chk'><input type='checkbox' id='paused'>Pause</label>"
		"<div class='ll-meta'><span class='ll-dot'></span><span id='llstate' class='ll-state'>Live</span>"
		"<span class='ll-meta-sep'>&middot;</span><span id='linecnt' class='ll-mask'>0</span><span class='ll-meta-word'>lines</span>"
		"<span class='ll-meta-sep'>&middot;</span><span id='dbmask' class='ll-mask'>0x%04X</span></div>"
		"</div>"
		"<div class='ll-dbrow'><span class='ll-label'>Debug</span>",
		(unsigned)g_dblevel);
	for (int i = 0; i < MAX_DEBUG_LEVELS; i++) {
		uint16_t m = g_dblevel_names[i].mask;
		pos = buf_printf(&buf, &bsz, pos,
			"<a id='db%u' href='#' class='dt%s' onclick='toggleDbg(%u);return false;' title='0x%04X'>%s</a>",
			m, (g_dblevel & m) ? " on" : "", m, m, g_dblevel_names[i].name);
	}
	pos = buf_printf(&buf, &bsz, pos,
		"<a id='dbALL' href='#' class='dt%s' onclick='toggleAll();return false;'>ALL</a>"
		"</div></div>"
		"<div id='lw' data-next='%d' data-mask='%u'><pre id='lp'>",
		(g_dblevel == D_ALL) ? " on" : "", total, (unsigned)g_dblevel);

	s_log_emit_ctx c = { &buf, &bsz, pos, 0, 0 };
	int32_t next_id = total;
	log_ring_foreach(from_id, WEB_MAX_LINES_POLL, emit_livelog_line, &c, &next_id);
	pos = c.pos;
	if (c.failed) { free(buf); send_json_error(fd, 503, "Service Unavailable", "out of memory"); return; }

	pos = buf_printf(&buf, &bsz, pos,
		"</pre></div><script src='/assets/livelog.js?v=%s' defer></script>",
		TCMG_ASSET_REV);

	pos = emit_footer(&buf, &bsz, pos);
	PAGE_SEND_AND_FREE(fd);
}

void send_logpoll(int fd, const char *qs)
{
	char dbg_s[16] = "", since_s[32] = "";
	get_param(qs, "debug", dbg_s, sizeof(dbg_s));
	get_param(qs, "since", since_s, sizeof(since_s));
	if (dbg_s[0]) {
		char *end = NULL;
		errno = 0;
		long v = strtol(dbg_s, &end, 0);
		if (errno == 0 && *end == '\0' && v >= 0 && v <= 0xFFFF) g_dblevel = (uint16_t)v;
	}
	int32_t from_id = 0;
	if (since_s[0]) {
		char *end = NULL;
		errno = 0;
		long v = strtol(since_s, &end, 10);
		if (errno == 0 && end && *end == '\0' && v > 0 && v <= INT32_MAX) from_id = (int32_t)v;
	}

	int32_t total = log_ring_total();
	if (from_id >= total) {
		char idle[96];
		int  in = snprintf(idle, sizeof(idle),
		                   "{\"debug\":%u,\"next\":%d,\"lines\":[]}",
		                   (unsigned)g_dblevel, (int)total);
		send_response(fd, 200, "OK", "application/json", idle, in);
		return;
	}
	int bsz = 4096, pos = 0;
	char *buf = (char *)malloc((size_t)bsz);
	if (!buf) { send_json_error(fd, 503, "Service Unavailable", "out of memory"); return; }
	pos = buf_printf(&buf, &bsz, pos, "{\"debug\":%u,\"next\":0,\"lines\":[", (unsigned)g_dblevel);
	s_log_emit_ctx c = { &buf, &bsz, pos, 0, 1 };
	int32_t next_id = from_id;
	log_ring_foreach(from_id, WEB_MAX_LINES_POLL, emit_logpoll_line, &c, &next_id);
	pos = c.pos;
	if (c.failed) { free(buf); send_json_error(fd, 503, "Service Unavailable", "out of memory"); return; }
	pos = buf_printf(&buf, &bsz, pos, "],\"next\":%d}", next_id);
	send_response(fd, 200, "OK", "application/json", buf, pos);
	free(buf);
}
