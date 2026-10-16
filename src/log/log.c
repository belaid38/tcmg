#define MODULE_LOG_PREFIX "log"
#include "log.h"
#include "../core/constants.h"
#include "../core/utils.h"
#include "../platform/platform.h"
#include "../srvid/srvid.h"
#include <stdatomic.h>

_Atomic uint16_t  g_dblevel = 0;

const S_DBLEVEL_NAME g_dblevel_names[MAX_DEBUG_LEVELS] = {
	{ D_WIRE,    "wire"    },
	{ D_ECM,     "ecm"     },
	{ D_EMU,     "emu"     },
	{ D_NEWCAMD, "newcamd" },
	{ D_CCCAM,   "cccam"   },
	{ D_HTTP,    "http"    },
	{ D_CONN,    "conn"    },
	{ D_READER,  "reader"  },
	{ D_PROTOCOL,"protocol" },
	{ D_DVBAPI,  "dvbapi"  },
};

#define LOG_FILE_MAX_BYTES  (10u * 1024u * 1024u)
#define USR_FILE_MAX_BYTES  (5u  * 1024u * 1024u)
#define LOG_LINE_MAX        1120
#define LOG_BODY_MAX        1024
#define LOG_HEX_INPUT_CAP   512
#define LOG_PREFIX_MAX      12
#define WQ_SIZE             2048

#define ANSI_RESET   "\x1b[0m"
#define ANSI_BOLD    "\x1b[1m"
#define ANSI_DIM     "\x1b[2m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_BGREEN  "\x1b[92m"
#define ANSI_RED     "\x1b[91m"
#define ANSI_YELLOW  "\x1b[93m"
#define ANSI_BLUE    "\x1b[94m"
#define ANSI_MAGENTA "\x1b[95m"
#define ANSI_CYAN    "\x1b[96m"
#define ANSI_WHITE   "\x1b[97m"
#define ANSI_GRAY    "\x1b[90m"
#define ANSI_ORANGE  "\x1b[33m"

static int s_color_enabled = -1;

static int color_enabled(void)
{
	if (s_color_enabled < 0) {
#ifdef TCMG_OS_WINDOWS
		s_color_enabled = 0;
#else
		const char *term = getenv("TERM");
		const char *no   = getenv("NO_COLOR");
		s_color_enabled = (!no || !no[0]) &&
		                  isatty(fileno(stdout)) &&
		                  term && strcmp(term, "dumb") != 0;
#endif
	}
	return s_color_enabled;
}

typedef struct {
	char *line;
	char *usr_line;
	char usr[CFGKEY_LEN];
} S_WQ_ENTRY;

static char *log_dup_n(const char *s, size_t max)
{
	size_t n = s ? strnlen(s, max) : 0;
	char *p = (char *)malloc(n + 1);
	if (!p) return NULL;
	if (n) memcpy(p, s, n);
	p[n] = '\0';
	return p;
}

static S_WQ_ENTRY       s_wq[WQ_SIZE];
static _Atomic int32_t  s_wq_head    = 0;
static _Atomic int32_t  s_wq_tail    = 0;
static pthread_mutex_t  s_wq_mtx     = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   s_wq_cond    = PTHREAD_COND_INITIALIZER;
static pthread_cond_t   s_wq_empty   = PTHREAD_COND_INITIALIZER;
static pthread_t        s_wq_tid;
static _Atomic int8_t   s_wq_running = 0;
static _Atomic int8_t   s_wq_started = 0;
static _Atomic int8_t   s_wq_queueing = 0;

typedef struct {
	char   *line;
	char    usr[CFGKEY_LEN];
	int32_t id;
} S_RING_ENTRY;

static S_RING_ENTRY    s_ring[LOG_RING_MAX];
static int32_t         s_ring_head  = 0;
static int32_t         s_ring_total = 0;
static pthread_mutex_t s_ring_mtx   = PTHREAD_MUTEX_INITIALIZER;

static FILE *s_log_fp  = NULL;
static char  s_log_path[CFGPATH_LEN] = "";
static FILE *s_usr_fp  = NULL;
static char  s_usr_path[CFGPATH_LEN] = "";

static pthread_mutex_t s_file_mtx       = PTHREAD_MUTEX_INITIALIZER;
static char  s_pending_log[CFGPATH_LEN] = "";
static char  s_pending_usr[CFGPATH_LEN] = "";
static int8_t s_pending_log_set         = 0;
static int8_t s_pending_usr_set         = 0;
static int8_t s_pending_reopen          = 0;

static int8_t s_ecm_log = 1;

static __thread char t_log_user[CFGKEY_LEN] = "";
static __thread char t_log_type = 's';
static pthread_mutex_t s_dedupe_mtx = PTHREAD_MUTEX_INITIALIZER;
static uint64_t s_last_hash = 0;
static int8_t s_have_last = 0;
static int32_t s_dup_count = 0;
static int64_t s_dup_started_ms = 0;
static char s_last_key[LOG_BODY_MAX + CFGKEY_LEN + LOG_PREFIX_MAX + 16] = "";

static uint64_t log_hash(const char *s)
{
	uint64_t h = 1469598103934665603ULL;
	while (*s) {
		h ^= (uint8_t)*s++;
		h *= 1099511628211ULL;
	}
	return h;
}

static void ts_now(char *buf, size_t sz)
{
	static __thread time_t s_last_t   = 0;
	static __thread char   s_last[24] = "";
	time_t t = time(NULL);
	if (t != s_last_t) {
		struct tm tm_buf;
		localtime_r(&t, &tm_buf);
		strftime(s_last, sizeof(s_last), "%Y/%m/%d %H:%M:%S", &tm_buf);
		s_last_t = t;
	}
	size_t n = sz < sizeof(s_last) ? sz : sizeof(s_last);
	memcpy(buf, s_last, n);
	if (n > 0) buf[n - 1] = '\0';
}

typedef enum {
	LC_NORMAL = 0,
	LC_CW_HIT,
	LC_CW_CACHE,
	LC_CW_SHARED,
	LC_CW_MISS,
	LC_ECM_REJECTED,
	LC_ERROR,
	LC_WARN,
	LC_WEBIF,
	LC_BAN,
	LC_NET,
	LC_EMU,
	LC_DEBUG,
	LC_STARTUP,
	LC_SHUTDOWN,
	LC_RELOAD,
} E_LOG_COLOR;

typedef struct {
	E_LOG_COLOR color;
	const char *needle;
} S_LOG_MARK;

static const char *find_log_mark(const char *body, E_LOG_COLOR *color, size_t *mark_len)
{
	static const S_LOG_MARK marks[] = {
		{ LC_ECM_REJECTED, "ecm rejected" },
		{ LC_CW_MISS,      "not found" },
		{ LC_CW_CACHE,     "cache" },
		{ LC_CW_SHARED,    "shared" },
		{ LC_CW_HIT,       "found" },
		{ LC_ERROR,        "reader error" },
		{ LC_ERROR,        "card error" },
		{ LC_ERROR,        "transport error" },
		{ LC_ERROR,        "failed" },
		{ LC_ERROR,        "FATAL" },
		{ LC_ERROR,        "FORCED" },
		{ LC_ERROR,        "ERROR" },
		{ LC_WARN,         "warn" },
		{ LC_WARN,         "rejected" },
		{ LC_WARN,         "repeated" },
		{ LC_SHUTDOWN,     "shutting down" },
		{ LC_SHUTDOWN,     "shutdown" },
		{ LC_RELOAD,       "reloaded" },
		{ LC_RELOAD,       "reload" },
		{ LC_RELOAD,       "re-opened" },
		{ LC_STARTUP,      "started" },
		{ LC_STARTUP,      "listening" },
		{ LC_STARTUP,      ">> tcmg <<" },
		{ LC_BAN,          "AUTH blocked" },
		{ LC_BAN,          "LOGIN failed" },
		{ LC_BAN,          "failban=triggered" },
		{ LC_BAN,          "banned" },
		{ LC_WEBIF,        "AUTH failed" },
		{ LC_WEBIF,        "AUTH success" },
		{ LC_WEBIF,        "webif" },
		{ LC_NET,          "disconnect" },
		{ LC_NET,          "connect" },
		{ LC_EMU,          "emu:" },
		{ LC_DEBUG,        "debug" },
	};
	if (!body || !color || !mark_len) return NULL;
	for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
		const char *p = strstr(body, marks[i].needle);
		if (p) {
			*color = marks[i].color;
			*mark_len = strlen(marks[i].needle);
			return p;
		}
	}
	{
		const char *p = strstr(body, "error");
		if (p) {
			*color = LC_ERROR;
			*mark_len = 5;
			return p;
		}
	}
	return NULL;
}

static const char *color_prefix(E_LOG_COLOR c)
{
	switch (c) {
	case LC_CW_HIT:   return ANSI_BOLD ANSI_BGREEN;
	case LC_CW_CACHE: return ANSI_BOLD ANSI_CYAN;
	case LC_CW_SHARED:return ANSI_BOLD ANSI_MAGENTA;
	case LC_CW_MISS:  return ANSI_BOLD ANSI_RED;
	case LC_ECM_REJECTED: return ANSI_BOLD ANSI_ORANGE;
	case LC_ERROR:    return ANSI_BOLD ANSI_RED;
	case LC_WARN:     return ANSI_YELLOW;
	case LC_SHUTDOWN: return ANSI_BOLD ANSI_MAGENTA;
	case LC_STARTUP:  return ANSI_BOLD ANSI_CYAN;
	case LC_RELOAD:   return ANSI_BOLD ANSI_BLUE;
	case LC_BAN:      return ANSI_ORANGE;
	case LC_WEBIF:    return ANSI_BLUE;
	case LC_NET:      return ANSI_MAGENTA;
	case LC_EMU:      return ANSI_CYAN;
	case LC_DEBUG:    return ANSI_GRAY;
	default:          return NULL;
	}
}

static void print_colored(FILE *fp, const char *line)
{
	if (!color_enabled()) {
		fputs(line, fp);
		fputc('\n', fp);
		return;
	}

	const char *body = line;
	for (int i = 0; i < 3; i++) {
		const char *sp = strchr(body, ' ');
		if (!sp) break;
		body = sp + 1;
	}

	E_LOG_COLOR c = LC_NORMAL;
	size_t mark_len = 0;
	const char *mark = find_log_mark(body, &c, &mark_len);
	const char *col = color_prefix(c);
	if (!mark || !col) {
		fputs(line, fp);
		fputc('\n', fp);
		return;
	}

	(void)fwrite(line, 1, (size_t)(mark - line), fp);
	fputs(col, fp);
	(void)fwrite(mark, 1, mark_len, fp);
	fputs(ANSI_RESET, fp);
	fputs(mark + mark_len, fp);
	fputc('\n', fp);
}

static void rotate_if_needed(FILE **fp, const char *path, unsigned long max_bytes)
{
	if (!*fp || !path[0]) return;
	long pos = ftell(*fp);
	if (pos < 0 || (unsigned long)pos < max_bytes) return;
	fputs("-- log file rotated --\n", *fp);
	fflush(*fp);
	fclose(*fp);
	char prev[CFGPATH_LEN + 8];
	snprintf(prev, sizeof(prev), "%s.prev", path);
	rename(path, prev);
	*fp = fopen(path, "a");
	if (*fp) {
		char ts[24];
		ts_now(ts, sizeof(ts));
		fprintf(*fp, "-- log continued at %s --\n", ts);
	}
}

static void ring_push(const char *line, const char *usr)
{
	char *copy = log_dup_n(line, LOG_LINE_MAX - 1);
	char *old;
	pthread_mutex_lock(&s_ring_mtx);
	S_RING_ENTRY *e = &s_ring[s_ring_head % LOG_RING_MAX];
	old = e->line;
	e->line = copy;
	tcmg_strlcpy(e->usr,  usr ? usr : "", sizeof(e->usr));
	e->id = s_ring_total;
	s_ring_head = (s_ring_head + 1) % LOG_RING_MAX;
	s_ring_total++;
	pthread_mutex_unlock(&s_ring_mtx);
	free(old);
}

static void apply_pending_files(void)
{
	pthread_mutex_lock(&s_file_mtx);

	if (s_pending_reopen) {
		if (s_log_fp) {
			fputs("-- log file re-opened --\n", s_log_fp);
			fflush(s_log_fp);
			fclose(s_log_fp);
			s_log_fp = NULL;
		}
		if (s_log_path[0]) {
			s_log_fp = fopen(s_log_path, "a");
			if (s_log_fp) {
				char ts[24];
				ts_now(ts, sizeof(ts));
				fprintf(s_log_fp, "-- log re-opened at %s --\n", ts);
			}
		}
		s_pending_reopen = 0;
	}

	if (s_pending_log_set) {
		if (s_log_fp) { fclose(s_log_fp); s_log_fp = NULL; }
		s_log_path[0] = '\0';
		if (s_pending_log[0]) {
			s_log_fp = fopen(s_pending_log, "a");
			if (s_log_fp) {
				tcmg_strlcpy(s_log_path, s_pending_log, sizeof(s_log_path));
				char ts[24];
				ts_now(ts, sizeof(ts));
				fprintf(s_log_fp, "\n>> tcmg << log started at %s\n", ts);
				fflush(s_log_fp);
			}
		}
		s_pending_log_set = 0;
	}

	if (s_pending_usr_set) {
		if (s_usr_fp) { fclose(s_usr_fp); s_usr_fp = NULL; }
		s_usr_path[0] = '\0';
		if (s_pending_usr[0]) {
			s_usr_fp = fopen(s_pending_usr, "a");
			if (s_usr_fp)
				tcmg_strlcpy(s_usr_path, s_pending_usr, sizeof(s_usr_path));
		}
		s_pending_usr_set = 0;
	}

	pthread_mutex_unlock(&s_file_mtx);
}

static void writer_drain(void)
{
	int32_t tail = atomic_load_explicit(&s_wq_tail, memory_order_acquire);
	int32_t head = atomic_load_explicit(&s_wq_head, memory_order_acquire);

	while (tail != head) {
		int32_t     slot = tail % WQ_SIZE;
		S_WQ_ENTRY *e    = &s_wq[slot];
		const char *line = e->line ? e->line : "";

		print_colored(stdout, line);

		if (s_log_fp) {
			rotate_if_needed(&s_log_fp, s_log_path, LOG_FILE_MAX_BYTES);
			if (s_log_fp) {
				fputs(line, s_log_fp);
				fputc('\n', s_log_fp);
			}
		}

		ring_push(line, e->usr);

		if (e->usr_line && s_usr_fp) {
			rotate_if_needed(&s_usr_fp, s_usr_path, USR_FILE_MAX_BYTES);
			if (s_usr_fp) {
				fputs(e->usr_line, s_usr_fp);
				fputc('\n', s_usr_fp);
			}
		}

		free(e->line);
		free(e->usr_line);
		e->line     = NULL;
		e->usr_line = NULL;
		e->usr[0]   = '\0';

		tail++;
		atomic_store_explicit(&s_wq_tail, tail, memory_order_release);
		head = atomic_load_explicit(&s_wq_head, memory_order_acquire);
	}

	fflush(stdout);
	if (s_log_fp) fflush(s_log_fp);
	if (s_usr_fp) fflush(s_usr_fp);

	pthread_mutex_lock(&s_wq_mtx);
	pthread_cond_broadcast(&s_wq_empty);
	pthread_mutex_unlock(&s_wq_mtx);
}

static void *writer_thread(void *arg)
{
	(void)arg;
	while (atomic_load_explicit(&s_wq_running, memory_order_acquire)) {
		pthread_mutex_lock(&s_wq_mtx);
		while (
			atomic_load_explicit(&s_wq_tail,    memory_order_relaxed) ==
			atomic_load_explicit(&s_wq_head,    memory_order_relaxed) &&
			atomic_load_explicit(&s_wq_running, memory_order_relaxed))
		{
			pthread_cond_wait(&s_wq_cond, &s_wq_mtx);
		}
		pthread_mutex_unlock(&s_wq_mtx);
		apply_pending_files();
		writer_drain();
	}
	apply_pending_files();
	writer_drain();
	return NULL;
}

void log_init(void)
{
	pthread_mutex_lock(&s_dedupe_mtx);
	s_last_hash = 0;
	s_last_key[0] = '\0';
	s_have_last = 0;
	s_dup_count = 0;
	s_dup_started_ms = 0;
	pthread_mutex_unlock(&s_dedupe_mtx);
	if (atomic_load_explicit(&s_wq_started, memory_order_acquire)) return;
	atomic_store_explicit(&s_wq_queueing, 0, memory_order_release);
	atomic_store_explicit(&s_wq_running, 1, memory_order_release);
	int rc = pthread_create(&s_wq_tid, NULL, writer_thread, NULL);
	if (rc != 0) {
		atomic_store_explicit(&s_wq_running, 0, memory_order_release);
		atomic_store_explicit(&s_wq_queueing, 0, memory_order_release);
		fprintf(stderr, "[TCMG] log writer thread creation failed rc=%d (%s); using synchronous logging\n",
		        rc, strerror(rc));
		return;
	}
	atomic_store_explicit(&s_wq_started, 1, memory_order_release);
	atomic_store_explicit(&s_wq_queueing, 1, memory_order_release);
}

void log_flush(void)
{
	/* With no writer, emit_line_ex() writes synchronously and the queue is empty. */
	if (!atomic_load_explicit(&s_wq_started, memory_order_acquire)) return;
	pthread_mutex_lock(&s_wq_mtx);
	while (atomic_load_explicit(&s_wq_head, memory_order_relaxed) !=
	       atomic_load_explicit(&s_wq_tail, memory_order_relaxed))
		pthread_cond_wait(&s_wq_empty, &s_wq_mtx);
	pthread_mutex_unlock(&s_wq_mtx);
}

void log_shutdown(void)
{
	tcmg_log("%s", ">> " TCMG_BANNER " << shutting down");
	log_flush();
	if (atomic_load_explicit(&s_wq_started, memory_order_acquire)) {
		/* Switch producers to synchronous mode before the writer begins exiting. */
		atomic_store_explicit(&s_wq_queueing, 0, memory_order_release);
		atomic_store_explicit(&s_wq_running, 0, memory_order_release);
		pthread_mutex_lock(&s_wq_mtx);
		pthread_cond_signal(&s_wq_cond);
		pthread_mutex_unlock(&s_wq_mtx);
		int rc = pthread_join(s_wq_tid, NULL);
		if (rc != 0)
			fprintf(stderr, "[TCMG] log writer thread join failed rc=%d (%s)\n", rc, strerror(rc));
		atomic_store_explicit(&s_wq_started, 0, memory_order_release);
	}
	if (s_log_fp) { fclose(s_log_fp); s_log_fp = NULL; }
	if (s_usr_fp) { fclose(s_usr_fp); s_usr_fp = NULL; }
	pthread_mutex_lock(&s_ring_mtx);
	for (int32_t i = 0; i < LOG_RING_MAX; i++) { free(s_ring[i].line); s_ring[i].line = NULL; }
	pthread_mutex_unlock(&s_ring_mtx);
}

void log_reopen(void)
{
	pthread_mutex_lock(&s_file_mtx);
	s_pending_reopen = 1;
	pthread_mutex_unlock(&s_file_mtx);
	pthread_mutex_lock(&s_wq_mtx);
	pthread_cond_signal(&s_wq_cond);
	pthread_mutex_unlock(&s_wq_mtx);
}

static void wq_push(const char *line, const char *usr, const char *usr_line)
{
	pthread_mutex_lock(&s_wq_mtx);
	int32_t head = atomic_load_explicit(&s_wq_head, memory_order_relaxed);
	int32_t tail = atomic_load_explicit(&s_wq_tail, memory_order_acquire);

	if (((head + 1) % WQ_SIZE) == (tail % WQ_SIZE)) {
		pthread_mutex_unlock(&s_wq_mtx);
		fputs("[TCMG] log queue full -- line dropped\n", stderr);
		return;
	}

	int32_t     slot = head % WQ_SIZE;
	S_WQ_ENTRY *e    = &s_wq[slot];

	e->line = log_dup_n(line, LOG_LINE_MAX - 1);
	if (!e->line) {
		pthread_mutex_unlock(&s_wq_mtx);
		return;
	}
	tcmg_strlcpy(e->usr,  usr ? usr : "", sizeof(e->usr));
	e->usr_line = (usr_line && usr_line[0]) ? log_dup_n(usr_line, 191) : NULL;

	atomic_store_explicit(&s_wq_head, head + 1, memory_order_release);
	pthread_cond_signal(&s_wq_cond);
	pthread_mutex_unlock(&s_wq_mtx);
}

static int dedupe_check(const char *mod, const char *body, const char *usr, int dedupe, int32_t *summary_count)
{
	char key[sizeof(s_last_key)];
	const char *m = mod ? mod : "";
	const char *u = usr ? usr : "";
	int64_t now = tcmg_mono_ms();
	int32_t summary = 0;
	snprintf(key, sizeof(key), "%c|%s|%s|%s", t_log_type, m, u, body ? body : "");
	uint64_t hash = log_hash(key);
	pthread_mutex_lock(&s_dedupe_mtx);
	if (dedupe && s_have_last && hash == s_last_hash && strcmp(key, s_last_key) == 0) {
		if (s_dup_count > 0 && now - s_dup_started_ms >= 60000) {
			summary = s_dup_count;
			s_dup_count = 1;
			s_dup_started_ms = now;
		} else {
			if (s_dup_count == 0) s_dup_started_ms = now;
			s_dup_count++;
		}
		pthread_mutex_unlock(&s_dedupe_mtx);
		if (summary_count) *summary_count = summary;
		return 1;
	}
	if (s_dup_count > 0) summary = s_dup_count;
	s_dup_count = 0;
	s_last_hash = hash;
	tcmg_strlcpy(s_last_key, key, sizeof(s_last_key));
	s_have_last = 1;
	pthread_mutex_unlock(&s_dedupe_mtx);
	if (summary_count) *summary_count = summary;
	return 0;
}

static void emit_line_ex(const char *mod, const char *body, int dedupe, const char *usr, const char *usr_line)
{
	char ts[24];
	char line[LOG_LINE_MAX];
	uint32_t tid = (uint32_t)(uintptr_t)pthread_self();
	int32_t summary_count = 0;
	const char *log_usr = usr ? usr : "";
	ts_now(ts, sizeof(ts));
	if (mod) {
		char modbuf[LOG_PREFIX_MAX + 2];
		snprintf(modbuf, sizeof(modbuf), "(%s)", mod);
		snprintf(line, sizeof(line), "%s %08X %c %10s %s", ts, tid, t_log_type, modbuf, body ? body : "");
	} else {
		snprintf(line, sizeof(line), "%s %08X %c            %s", ts, tid, t_log_type, body ? body : "");
	}
	if (dedupe_check(mod, body, log_usr, dedupe, &summary_count)) {
		if (summary_count > 0) {
			char dup[LOG_LINE_MAX];
			snprintf(dup, sizeof(dup), "%s %08X %c            -- last line repeated %d time(s) --", ts, tid, t_log_type, summary_count);
			if (atomic_load_explicit(&s_wq_queueing, memory_order_acquire))
				wq_push(dup, log_usr, NULL);
			else {
				print_colored(stdout, dup);
				fflush(stdout);
				ring_push(dup, log_usr);
			}
		}
		return;
	}
	if (summary_count > 0) {
		char dup[LOG_LINE_MAX];
		snprintf(dup, sizeof(dup), "%s %08X %c            -- last line repeated %d time(s) --", ts, tid, t_log_type, summary_count);
		if (atomic_load_explicit(&s_wq_queueing, memory_order_acquire))
			wq_push(dup, log_usr, NULL);
		else {
			print_colored(stdout, dup);
			fflush(stdout);
			ring_push(dup, log_usr);
		}
	}
	if (atomic_load_explicit(&s_wq_queueing, memory_order_acquire))
		wq_push(line, log_usr, usr_line);
	else {
		print_colored(stdout, line);
		fflush(stdout);
		ring_push(line, log_usr);
	}
}

static void emit_line(const char *mod, const char *body, int dedupe)
{
	emit_line_ex(mod, body, dedupe, t_log_user, NULL);
}

void log_set_file(const char *path)
{
	pthread_mutex_lock(&s_file_mtx);
	tcmg_strlcpy(s_pending_log, path ? path : "", sizeof(s_pending_log));
	s_pending_log_set = 1;
	pthread_mutex_unlock(&s_file_mtx);
	pthread_mutex_lock(&s_wq_mtx);
	pthread_cond_signal(&s_wq_cond);
	pthread_mutex_unlock(&s_wq_mtx);
}

void log_set_usrfile(const char *path)
{
	pthread_mutex_lock(&s_file_mtx);
	tcmg_strlcpy(s_pending_usr, path ? path : "", sizeof(s_pending_usr));
	s_pending_usr_set = 1;
	pthread_mutex_unlock(&s_file_mtx);
	pthread_mutex_lock(&s_wq_mtx);
	pthread_cond_signal(&s_wq_cond);
	pthread_mutex_unlock(&s_wq_mtx);
}

void log_set_user(const char *user)
{
	if (user && *user)
		tcmg_strlcpy(t_log_user, user, sizeof(t_log_user));
	else
		t_log_user[0] = '\0';
}

void log_set_type(E_LOG_TYPE type)
{
	t_log_type = (char)type;
}

void tcmg_log_txt(const char *mod, const char *fmt, ...)
{
	char    body[LOG_BODY_MAX];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(body, sizeof(body), fmt, ap);
	va_end(ap);
	emit_line(mod, body, 1);
}

void tcmg_log_force_txt(const char *mod, const char *fmt, ...)
{
	char    body[LOG_BODY_MAX];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(body, sizeof(body), fmt, ap);
	va_end(ap);
	emit_line(mod, body, 0);
}

static void hex_row(const uint8_t *buf, int32_t offset, int32_t count, char *row)
{
	int32_t rp = 0;
	int32_t j;

	for (j = 0; j < count; j++) {
	static const char hex_ch[] = "0123456789ABCDEF";
		uint8_t b = buf[offset + j];
		row[rp++] = hex_ch[b >> 4];
		row[rp++] = hex_ch[b & 0xF];
		row[rp++] = ' ';
	}
	while (j < 16) {
		row[rp++] = ' ';
		row[rp++] = ' ';
		row[rp++] = ' ';
		j++;
	}
	while (rp > 0 && row[rp - 1] == ' ') rp--;
	row[rp] = '\0';
}

void tcmg_log_hex(const char *mod, const uint8_t *buf, int32_t n,
                  const char *fmt, ...)
{
	char    prefix[256];
	va_list ap;
	char    firstline[320];
	int32_t i;

	va_start(ap, fmt);
	vsnprintf(prefix, sizeof(prefix), fmt, ap);
	va_end(ap);

	if (n > LOG_HEX_INPUT_CAP) n = LOG_HEX_INPUT_CAP;

	if (n == 0) {
		char body[300];
		int32_t rp = 0;
		const char *p = prefix;
		while (*p && rp < 295) body[rp++] = *p++;
		body[rp++] = ':'; body[rp++] = ' ';
		body[rp++] = '('; body[rp++] = 'e';
		body[rp++] = 'm'; body[rp++] = 'p';
		body[rp++] = 't'; body[rp++] = 'y';
		body[rp++] = ')'; body[rp] = '\0';
		emit_line(mod, body, 1);
		return;
	}

	{
		int32_t rp = 0;
		const char *p = prefix;
		char  tmp[16];
		int32_t nlen = 0;
		int32_t v = n;
		while (*p && rp < 295) firstline[rp++] = *p++;
		firstline[rp++] = ' ';
		firstline[rp++] = '(';
		do {
			tmp[nlen++] = (char)('0' + v % 10);
			v /= 10;
		} while (v && nlen < 15);
		while (nlen > 0) firstline[rp++] = tmp[--nlen];
		firstline[rp++] = ' ';
		firstline[rp++] = 'b';
		firstline[rp++] = 'y';
		firstline[rp++] = 't';
		firstline[rp++] = 'e';
		firstline[rp++] = 's';
		firstline[rp++] = ')';
		firstline[rp++] = ':';
		firstline[rp] = '\0';
	}
	emit_line(mod, firstline, 1);

	for (i = 0; i < n; i += 16) {
		int32_t count = (i + 16 < n) ? 16 : (n - i);
		char    row[56];
		hex_row(buf, i, count, row);
		emit_line(NULL, row, 1);
	}
}

void log_ecm_raw(uint16_t caid, uint16_t sid, const uint8_t *data, int32_t len)
{
	int32_t cap;
	int32_t i;

	if (!(D_ECM & g_dblevel)) return;

	{
		char header[64];
		snprintf(header, sizeof(header), "caid=%04X sid=%04X len=%d", caid, sid, len);
		emit_line("ecm", header, 1);
	}

	cap = (len > 256) ? 256 : len;
	for (i = 0; i < cap; i += 16) {
		int32_t count = (i + 16 < cap) ? 16 : (cap - i);
		char    row[64];
		hex_row(data, i, count, row);
		emit_line(NULL, row, 1);
	}

	if (len > 256) {
		char trunc[40];
		snprintf(trunc, sizeof(trunc), "  ... (%d bytes truncated)", len - 256);
		emit_line(NULL, trunc, 1);
	}
}

void log_cw_result(uint16_t caid, uint16_t sid, int32_t len,
                   const uint8_t *cw, E_LOG_ECM_RESULT result, E_TCMG_ECM_SOURCE source,
                   int32_t ms, const char *user)
{
	char body[512];
	char usr_line[LOG_LINE_MAX];
	char ts[24];

	if (!s_ecm_log) return;

	{
		char ch_buf[SRVID_NAME_MAX];
		srvid_lookup_copy(caid, sid, ch_buf, sizeof(ch_buf));
		const char *ch = ch_buf[0] ? ch_buf : NULL;
		const bool hit = result == LOG_ECM_FOUND;

		char cw_str[33] = "";
		if (hit && cw) {
			static const char hx[] = "0123456789ABCDEF";
			for (int32_t i = 0; i < 16; i++) {
				cw_str[i * 2]     = hx[cw[i] >> 4];
				cw_str[i * 2 + 1] = hx[cw[i] & 0xF];
			}
			cw_str[32] = '\0';
		}

		const char *result_text = result == LOG_ECM_FOUND ?
		                          (source == TCMG_ECM_SOURCE_CACHE ? "cache" :
		                           source == TCMG_ECM_SOURCE_SHARED ? "shared" : "found") :
		                          (result == LOG_ECM_REJECTED ? "ecm rejected" :
		                           result == LOG_ECM_TRANSPORT_ERROR ? "transport error" :
		                           result == LOG_ECM_CARD_ERROR ? "card error" :
		                           result == LOG_ECM_READER_ERROR ? "reader error" : "not found");

		const char *display_user = (user && *user) ? user : "?";
		if (result == LOG_ECM_FOUND) {
			if (ch)
				snprintf(body, sizeof(body),
				         "(%04X:%04X:%02X:%s): %s (%d ms) by %s  [%s]",
				         caid, sid, (int)len, cw_str, result_text, ms,
				         display_user, ch);
			else
				snprintf(body, sizeof(body),
				         "(%04X:%04X:%02X:%s): %s (%d ms) by %s",
				         caid, sid, (int)len, cw_str, result_text, ms,
				         display_user);
		} else if (result == LOG_ECM_REJECTED) {
			if (ch)
				snprintf(body, sizeof(body),
				         "(%04X:%04X:%02X): ecm rejected (%d ms) by %s  [%s]",
				         caid, sid, (int)len, ms, display_user, ch);
			else
				snprintf(body, sizeof(body),
				         "(%04X:%04X:%02X): ecm rejected (%d ms) by %s",
				         caid, sid, (int)len, ms, display_user);
		} else {
			if (ch)
				snprintf(body, sizeof(body),
				         "(%04X:%04X:%02X): %s (%d ms) by %s  [%s]",
				         caid, sid, (int)len, result_text, ms, display_user, ch);
			else
				snprintf(body, sizeof(body),
				         "(%04X:%04X:%02X): %s (%d ms) by %s",
				         caid, sid, (int)len, result_text, ms, display_user);
		}

		usr_line[0] = '\0';
		if (user && *user) {
			const char *usr_result = hit ?
			    (source == TCMG_ECM_SOURCE_CACHE ? "cache" :
			     source == TCMG_ECM_SOURCE_SHARED ? "shared" : "found") :
			                         (result == LOG_ECM_REJECTED ? "rejected" :
			                          result == LOG_ECM_TRANSPORT_ERROR ? "transport" :
			                          result == LOG_ECM_CARD_ERROR ? "card_error" :
			                          result == LOG_ECM_READER_ERROR ? "reader_error" : "miss");
			ts_now(ts, sizeof(ts));
			snprintf(usr_line, sizeof(usr_line),
			         "%s\t%s\t%04X\t%04X\t%s\t%d\t%02X\t%s",
			         ts, user, caid, sid,
			         usr_result,
			         ms, (int)len,
			         ch ? ch : "");
		}
	}

	emit_line_ex("ecm", body, 1, user, usr_line[0] ? usr_line : NULL);
}

void   log_ecm_set(int8_t on) { s_ecm_log = on ? 1 : 0; }
int8_t log_ecm_get(void)      { return s_ecm_log; }

int32_t log_ring_total(void)
{
	pthread_mutex_lock(&s_ring_mtx);
	int32_t t = s_ring_total;
	pthread_mutex_unlock(&s_ring_mtx);
	return t;
}

int32_t log_ring_foreach(int32_t from_id, int32_t max_lines, log_ring_iter_cb cb, void *ctx, int32_t *out_next)
{
	if (!cb || max_lines <= 0) {
		if (out_next) *out_next = log_ring_total();
		return 0;
	}
	pthread_mutex_lock(&s_ring_mtx);
	int32_t oldest = s_ring_total - LOG_RING_MAX;
	if (oldest < 0) oldest = 0;
	if (from_id < oldest) from_id = oldest;
	int32_t total = s_ring_total;
	int32_t count = 0;
	for (int32_t i = from_id; i < total && count < max_lines; i++) {
		int32_t slot = i % LOG_RING_MAX;
		S_RING_ENTRY *e = &s_ring[slot];
		if (cb(i, e->line ? e->line : "", e->usr, ctx) < 0) break;
		count++;
	}
	if (out_next) *out_next = s_ring_total;
	pthread_mutex_unlock(&s_ring_mtx);
	return count;
}
