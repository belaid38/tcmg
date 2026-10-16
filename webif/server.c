#define MODULE_LOG_PREFIX "webif"
#include "../src/core/utils.h"
#include "../src/core/runtime_state.h"
#include "../src/log/log.h"
#include "../src/client/client.h"
#include "../src/net/net.h"
#include "../src/security/failban.h"
#include "internal/proto.h"
#include "service/service.h"
#include <semaphore.h>
#include <stdatomic.h>

static _Atomic int8_t s_webif_running = 0;
static int             s_webif_sock    = -1;
static pthread_t       s_webif_tid;
static sem_t           s_webif_sem;
static pthread_mutex_t s_webif_lifecycle_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_webif_workers_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_webif_workers_cv = PTHREAD_COND_INITIALIZER;
static unsigned        s_webif_workers = 0;

#ifndef TCMG_OS_WINDOWS

static int s_webif_wake[2] = { -1, -1 };

static void webif_wake_close(void)
{
	for (int i = 0; i < 2; i++)
		if (s_webif_wake[i] >= 0) { close(s_webif_wake[i]); s_webif_wake[i] = -1; }
}
#endif

#define WEBIF_MAX_THREADS 16

typedef struct { int fd; char ip[MAXIPLEN]; } s_conn_arg;

static void *conn_thread(void *arg)
{
	s_conn_arg *c = (s_conn_arg *)arg;
	log_set_type(LOG_TYPE_WEBIF);
	handle_request(c->fd, c->ip);
	close(c->fd);
	free(c);
	sem_post(&s_webif_sem);
	pthread_mutex_lock(&s_webif_workers_mtx);
	if (s_webif_workers > 0) s_webif_workers--;
	if (s_webif_workers == 0) pthread_cond_broadcast(&s_webif_workers_cv);
	pthread_mutex_unlock(&s_webif_workers_mtx);
	return NULL;
}

static int request_is_authed(const char *raw, const char *client_ip, char *sess_tok_out)
{
	sess_tok_out[0] = '\0';

	if (!webif_auth_enabled()) return 1;

	char cookie_hdr[512] = "";
	if (web_header_get(raw, "Cookie", cookie_hdr, sizeof(cookie_hdr))) {
		char tok[WEB_SESSION_LEN + 1];
		const char *sess = cookie_get_session(cookie_hdr, tok, sizeof(tok));
		if (sess && session_check(sess)) {
			tcmg_strlcpy(sess_tok_out, sess, WEB_SESSION_LEN + 1);
			return 1;
		}
	}

	char auth_hdr[512] = "";
	if (web_header_get(raw, "Authorization", auth_hdr, sizeof(auth_hdr))) {

		if (ban_is_banned(client_ip)) {
			tcmg_log("%s AUTH blocked: failban", client_ip);
			return 0;
		}
		if (check_auth(auth_hdr)) return 1;
		int banned_now = ban_record_fail(client_ip);
		tcmg_log("%s AUTH failed: method=basic invalid_credentials%s",
		         client_ip, banned_now ? " failban=triggered" : "");
	}

	return 0;
}

static int is_state_changing(const char *method, const char *path, const char *qs)
{
	if (strcmp(method, "POST") == 0) return 1;
	if (strncmp(path, "/api/user/", 10) == 0 && strcmp(path, "/api/user/get") != 0) return 1;
	if (strncmp(path, "/api/failban/", 13) == 0) return 1;
	if (strcmp(path, "/api/reload")     == 0 || strcmp(path, "/api/restart") == 0 ||
	    strcmp(path, "/api/resetstats") == 0 || strcmp(path, "/restart")     == 0 ||
	    strcmp(path, "/shutdown")       == 0) return 1;
	if (strcmp(path, "/power")   == 0 && strstr(qs, "confirm="))  return 1;
	if (strcmp(path, "/failban") == 0 && strstr(qs, "action="))   return 1;
	if (strcmp(path, "/logpoll") == 0 && strstr(qs, "debug="))    return 1;
	return 0;
}

static int csrf_blocked(const char *raw)
{
	char v[128] = "";
	if (web_header_get(raw, "Sec-Fetch-Site", v, sizeof(v)) && strcmp(v, "cross-site") == 0)
		return 1;
	char origin[256] = "", host[256] = "";
	if (web_header_get(raw, "Origin", origin, sizeof(origin)) && strcmp(origin, "null") != 0 &&
	    web_header_get(raw, "Host", host, sizeof(host))) {
		const char *o = strstr(origin, "://");
		o = o ? o + 3 : origin;
		if (strcmp(o, host) != 0) return 1;
	}
	return 0;
}

static void discard_oversize_body(int fd, const char *raw, int rawlen)
{
	char clbuf[32] = "";
	if (!web_header_get(raw, "Content-Length", clbuf, sizeof(clbuf))) return;
	char *end = NULL;
	errno = 0;
	long long clen = strtoll(clbuf, &end, 10);
	if (errno == ERANGE || end == clbuf || *end || clen < 0 || clen > (long long)WEB_POST_MAX * 4LL) return;
	const char *body = strstr(raw, "\r\n\r\n");
	if (!body) return;
	body += 4;
	long long have = raw + rawlen > body ? (long long)(raw + rawlen - body) : 0;
	if (have < 0 || have >= clen) return;
	long long remain = clen - have;
	char buf[8192];
	while (remain > 0) {
		size_t want = remain > (long long)sizeof(buf) ? sizeof(buf) : (size_t)remain;
		int n = (int)recv(fd, RECV_CAST(buf), want, 0);
		if (n <= 0) break;
		remain -= n;
	}
}

static void send_json_401(int fd)
{
	static const char body[] = "{\"ok\":false,\"msg\":\"unauthorized\"}";
	send_response(fd, 401, "Unauthorized", "application/json",
	              body, (int)sizeof(body) - 1);
}

void handle_request(int fd, const char *client_ip)
{
	char raw_small[4096];
	char *raw = raw_small;
	int raw_cap = (int)sizeof(raw_small);
	int raw_heap = 0;
	int rlen = 0;
	net_set_timeout(fd, WEB_READ_TIMEOUT_S);

	for (;;) {
		if (rlen >= raw_cap - 1) {
			if (strstr(raw, "\r\n\r\n")) break;
			if (raw_cap >= WEB_BUF_SIZE) {
				send_json_error(fd, 431, "Request Header Fields Too Large", "headers too large");
				if (raw_heap) free(raw);
				return;
			}
			int next_cap = raw_cap * 2;
			if (next_cap > WEB_BUF_SIZE) next_cap = WEB_BUF_SIZE;
			char *nb = (char *)malloc((size_t)next_cap);
			if (!nb) {
				send_json_error(fd, 503, "Service Unavailable", "out of memory");
				if (raw_heap) free(raw);
				return;
			}
			memcpy(nb, raw, (size_t)rlen);
			if (raw_heap) free(raw);
			raw = nb;
			raw_cap = next_cap;
			raw_heap = 1;
		}

		int n = (int)recv(fd, RECV_CAST(raw + rlen),
		                  (size_t)(raw_cap - 1 - rlen), 0);
		if (n <= 0) {
			if (raw_heap) free(raw);
			return;
		}
		rlen += n;
		raw[rlen] = '\0';
		if (strstr(raw, "\r\n\r\n")) break;
	}

	if (rlen < 10) {
		if (raw_heap) free(raw);
		return;
	}
	raw[rlen] = '\0';

	s_http_req req;
	if (!req_parse(&req, fd, raw, rlen)) {
		if (raw_heap) free(raw);
		return;
	}
	if (req.status) {
		int st = req.status;
		if (st == 413) discard_oversize_body(fd, raw, rlen);
		req_free(&req);
		if (raw_heap) free(raw);
		send_json_error(fd, st,
			st == 413 ? "Payload Too Large" : st == 414 ? "URI Too Long" :
			st == 503 ? "Service Unavailable" : "Bad Request",
			st == 413 ? "request body too large" : st == 414 ? "uri too long" :
			st == 503 ? "out of memory" : "bad request");
		return;
	}

	if (strcmp(req.path, "/logpoll") != 0)
		tcmg_log_dbg(D_HTTP, "HTTP %s %s%s%s", req.method, req.path,
		             req.qs[0] ? "?" : "", req.qs);

	char sess_tok[WEB_SESSION_LEN + 1];
	int  authed = request_is_authed(raw, client_ip, sess_tok);
	int  csrf   = authed && is_state_changing(req.method, req.path, req.qs) && csrf_blocked(raw);

	const char *p  = req.path;
	const char *qs = req.qs;

	if (strcmp(p, "/login") == 0 && strcmp(req.method, "POST") == 0) {
		char u[CFGKEY_LEN] = {0}, pw[CFGKEY_LEN] = {0};
		form_get(req.body, "u",  u,  sizeof(u));
		form_get(req.body, "p", pw, sizeof(pw));
		if (ban_is_banned(client_ip)) {
			tcmg_log("%s AUTH blocked: method=form failban", client_ip);
			send_login_page(fd, 2);
			req_free(&req);
			if (raw_heap) free(raw);
			return;
		}
		if (check_credentials(u, pw)) {
			ban_record_ok(client_ip);
			char token[WEB_SESSION_LEN + 1];
			session_create(token);
			tcmg_log_dbg(D_HTTP, "LOGIN ok user='%s' from=%s", u, client_ip);
			send_redirect_with_cookie(fd, "/status", token);
		} else {
			int banned_now = ban_record_fail(client_ip);
			tcmg_log("%s AUTH failed: method=form invalid_credentials user='%s'%s",
			         client_ip, u, banned_now ? " failban=triggered" : "");
			send_login_page(fd, 1);
		}
		req_free(&req);
		if (raw_heap) free(raw);
		return;
	}

	if (strcmp(p, "/logout") == 0) {
		if (sess_tok[0]) {
			tcmg_log_dbg(D_HTTP, "logout from=%s", client_ip);
			session_invalidate(sess_tok);
		}
		send_redirect_clear_cookie(fd, "/login");
		req_free(&req);
		if (raw_heap) free(raw);
		return;
	}

	if (!authed) {
		if (strcmp(p, "/login") == 0) {
			send_login_page(fd, 0);
		} else if (strncmp(p, "/api/", 5) == 0 || strcmp(p, "/logpoll") == 0) {
			send_json_401(fd);
		} else {
			send_redirect(fd, "/login");
		}
		req_free(&req);
		if (raw_heap) free(raw);
		return;
	}

	if (strcmp(p, "/login") == 0)
		{ send_redirect(fd, "/status"); req_free(&req); if (raw_heap) free(raw); return; }

	if (csrf) {
		tcmg_log("cross-site request blocked: %s %s from=%s", req.method, p, client_ip);
		send_json_error(fd, 403, "Forbidden", "cross-site request blocked");
		req_free(&req);
		if (raw_heap) free(raw);
		return;
	}

	if (strcmp(p, "/") == 0)
		send_redirect(fd, "/status");

	else if (strcmp(p, "/status") == 0) send_page_status(fd);

	else if (strcmp(p, "/users")   == 0) send_page_users(fd);
	else if (strcmp(p, "/readers") == 0) send_page_readers(fd);
	else if (strcmp(p, "/failban") == 0) send_page_failban(fd, qs);
	else if (strcmp(p, "/config")  == 0) send_page_config(fd);
	else if (strcmp(p, "/files")   == 0) send_page_files(fd);
	else if (strcmp(p, "/livelog") == 0) send_page_livelog(fd);
	else if (strcmp(p, "/logpoll") == 0) send_logpoll(fd, qs);
	else if (strcmp(p, "/power")   == 0) send_page_power(fd, qs);
	else if (strcmp(p, "/restart") == 0) send_page_restart(fd, qs);
	else if (strcmp(p, "/shutdown")== 0) send_page_shutdown(fd, qs);
	else if (strcmp(p, "/tvcas")   == 0) send_page_tvcas(fd);

	else if (strcmp(p, "/assets/app.css")   == 0) send_webif_asset(fd, p);
	else if (strcmp(p, "/assets/app.js")     == 0) send_webif_asset(fd, p);
	else if (strcmp(p, "/assets/livelog.js")  == 0) send_webif_asset(fd, p);
	else if (strcmp(p, "/assets/users.js")   == 0) send_webif_asset(fd, p);
	else if (strcmp(p, "/assets/readers.js")  == 0) send_webif_asset(fd, p);

	else if (strcmp(p, "/api/status")               == 0) send_api_status(fd, qs);
	else if (strcmp(p, "/api/client/kill") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_client_kill(fd, qs);
	else if (strcmp(p, "/api/pcsc/readers")         == 0) send_api_pcsc_readers(fd);
	else if (strcmp(p, "/api/serial/ports")         == 0) send_api_serial_ports(fd);
	else if (strcmp(p, "/api/readers")             == 0) send_api_readers(fd);
	else if (strcmp(p, "/api/reader/get")           == 0) send_api_reader_get(fd, qs);
	else if (strcmp(p, "/api/reader/save") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_reader_save(fd, req.body ? req.body : "");
	else if (strcmp(p, "/api/reader/delete") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_reader_delete(fd, qs);
	else if (strcmp(p, "/api/reader/toggle") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_reader_toggle(fd, qs);
	else if (strcmp(p, "/api/userstats")              == 0) send_api_userstats(fd);
	else if (strcmp(p, "/api/user/toggle") == 0 && strcmp(req.method, "POST") == 0)
		handle_user_toggle(fd, qs);
	else if (strcmp(p, "/api/user/get")              == 0) send_api_user_get(fd, qs);
	else if (strcmp(p, "/api/user/resetstats") == 0 && strcmp(req.method, "POST") == 0)
		handle_user_resetstats(fd, qs);
	else if (strcmp(p, "/api/user/delete") == 0 && strcmp(req.method, "POST") == 0)
		handle_user_delete(fd, qs);
	else if (strcmp(p, "/api/user/save")  == 0 && strcmp(req.method, "POST") == 0)
		handle_user_save(fd, req.body ? req.body : "");
	else if (strcmp(p, "/api/user/add")   == 0 && strcmp(req.method, "POST") == 0)
		handle_user_add(fd, req.body ? req.body : "");

	else if (strcmp(p, "/api/config/get")  == 0) send_api_config_get(fd);
	else if (strcmp(p, "/api/config/save") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_config_save(fd, req.body ? req.body : "");
	else if (strcmp(p, "/api/config/file/get") == 0) send_api_file_get(fd, qs);
	else if (strcmp(p, "/api/config/file/save") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_file_save(fd, req.body ? req.body : "");

	else if (strcmp(p, "/api/failban/clear") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_failban_clear(fd, qs);
	else if (strcmp(p, "/api/failban/clearall") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_failban_clearall(fd);

	else if (strcmp(p, "/api/reload") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_reload(fd);
	else if (strcmp(p, "/api/restart") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_restart(fd);
	else if (strcmp(p, "/api/resetstats") == 0 && strcmp(req.method, "POST") == 0)
		handle_api_resetstats(fd);

	else {
		static const char not_found[] =
			"<html><body style='background:#090d14;color:#e8f0fe;"
			"font-family:monospace;display:flex;align-items:center;"
			"justify-content:center;height:100vh'>"
			"<div><h1 style='color:#1fb8a3'>404</h1><p>Not Found</p>"
			"<a href='/status' style='color:#1fb8a3'>&#8592; Back to Status</a>"
			"</div></body></html>";
		send_response(fd, 404, "Not Found", "text/html",
		              not_found, (int)strlen(not_found));
	}

	req_free(&req);
	if (raw_heap) free(raw);
}

static void *http_server_thread(void *arg)
{
	(void)arg;
	log_set_type(LOG_TYPE_WEBIF);
	char bindaddr[MAXIPLEN];
	webif_bindaddr(bindaddr, sizeof(bindaddr));
	tcmg_log("listening http %s:%d", bindaddr[0] ? bindaddr : "0.0.0.0", webif_port());

	while (atomic_load_explicit(&s_webif_running, memory_order_acquire)) {
#ifndef TCMG_OS_WINDOWS
		struct pollfd pfd[2];
		pfd[0].fd = s_webif_sock;    pfd[0].events = POLLIN; pfd[0].revents = 0;
		pfd[1].fd = s_webif_wake[0]; pfd[1].events = POLLIN; pfd[1].revents = 0;
		int have_wake = s_webif_wake[0] >= 0;

		int pr = poll(pfd, have_wake ? 2 : 1, have_wake ? -1 : 500);
		if (pr < 0) {
			if (errno != EINTR) { struct timespec ts = { 0, 100 * 1000 * 1000 }; nanosleep(&ts, NULL); }
			continue;
		}
		if (have_wake && pfd[1].revents) break;
		if (!(pfd[0].revents & POLLIN)) {
			if (pfd[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				struct timespec ts = { 0, 100 * 1000 * 1000 };
				nanosleep(&ts, NULL);
			}
			continue;
		}
#else
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(s_webif_sock, &rfds);
		struct timeval tv = { 0, 500000 };
		if (select(s_webif_sock + 1, &rfds, NULL, NULL, &tv) <= 0)
			continue;
#endif

		struct sockaddr_in ca;
		socklen_t clen = sizeof(ca);
		int cfd = accept(s_webif_sock, (struct sockaddr *)&ca, &clen);
		if (cfd < 0) {
			if (atomic_load_explicit(&s_webif_running, memory_order_acquire))
				tcmg_log_dbg(D_HTTP, "accept() failed errno=%d (%s)", errno, strerror(errno));
			continue;
		}

		char client_ip[MAXIPLEN];
		inet_ntop(AF_INET, &ca.sin_addr, client_ip, sizeof(client_ip));

		int nodelay = 1;
		setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, SO_CAST(&nodelay), sizeof(nodelay));

		tcmg_log_dbg(D_HTTP, "HTTP connection from=%s fd=%d", client_ip, cfd);

		if (sem_trywait(&s_webif_sem) == 0) {
			s_conn_arg *ca2 = (s_conn_arg *)malloc(sizeof(*ca2));
			if (!ca2) {
				sem_post(&s_webif_sem);
				static const char oom[] = "<html><body>WebIF unavailable</body></html>";
				send_response(cfd, 503, "Service Unavailable", "text/html", oom, (int)strlen(oom));
				close(cfd);
				continue;
			}
			pthread_t t;
			pthread_attr_t a;
			const pthread_attr_t *attrp = NULL;
			int attr_ready = 0;
			int detached_attr = 0;
			ca2->fd = cfd;
			tcmg_strlcpy(ca2->ip, client_ip, MAXIPLEN);
			pthread_mutex_lock(&s_webif_workers_mtx);
			s_webif_workers++;
			pthread_mutex_unlock(&s_webif_workers_mtx);
			int arc = pthread_attr_init(&a);
			if (arc == 0) {
				attr_ready = 1;
				arc = pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
				if (arc == 0) {
					attrp = &a;
					detached_attr = 1;
					int src = pthread_attr_setstacksize(&a, 128 * 1024);
					if (src != 0)
						tcmg_log_dbg(D_HTTP, "HTTP worker stack size request failed rc=%d (%s); using default stack", src, strerror(src));
				} else {
					tcmg_log("HTTP worker detach attribute failed rc=%d (%s); using per-thread detach", arc, strerror(arc));
					pthread_attr_destroy(&a);
					attr_ready = 0;
				}
			} else {
				tcmg_log("HTTP worker attribute initialization failed rc=%d (%s); using per-thread detach", arc, strerror(arc));
			}
			int prc = pthread_create(&t, attrp, conn_thread, ca2);
			if (prc == 0) {
				if (!detached_attr) {
					int drc = pthread_detach(t);
					if (drc != 0) {
						tcmg_log("HTTP worker detach failed rc=%d (%s); joining worker", drc, strerror(drc));
						int jrc = pthread_join(t, NULL);
						if (jrc != 0) tcmg_log("HTTP worker fallback join failed rc=%d (%s)", jrc, strerror(jrc));
					}
				}
				if (attr_ready) pthread_attr_destroy(&a);
				continue;
			}
			tcmg_log("HTTP worker pthread_create failed rc=%d (%s)", prc, strerror(prc));
			if (attr_ready) pthread_attr_destroy(&a);
			pthread_mutex_lock(&s_webif_workers_mtx);
			if (s_webif_workers > 0) s_webif_workers--;
			if (s_webif_workers == 0) pthread_cond_broadcast(&s_webif_workers_cv);
			pthread_mutex_unlock(&s_webif_workers_mtx);
			sem_post(&s_webif_sem);
			free(ca2);
			static const char busy[] = "<html><body>WebIF busy</body></html>";
			send_response(cfd, 503, "Service Unavailable", "text/html", busy, (int)strlen(busy));
		} else {
			static const char busy[] = "<html><body>WebIF busy</body></html>";
			send_response(cfd, 503, "Service Unavailable", "text/html", busy, (int)strlen(busy));
		}
		close(cfd);
	}

	tcmg_log("%s", "stopped");
	return NULL;
}

int32_t webif_start(void)
{
	pthread_mutex_lock(&s_webif_lifecycle_mtx);
	if (atomic_load_explicit(&s_webif_running, memory_order_acquire)) {
		pthread_mutex_unlock(&s_webif_lifecycle_mtx);
		return 0;
	}
	S_WEBIF_CONFIG_VIEW cfg;
	if (!webif_config_snapshot(&cfg) || !cfg.webif_enabled) {
		tcmg_log_dbg(D_HTTP, "%s", "disabled in config");
		pthread_mutex_unlock(&s_webif_lifecycle_mtx);
		return -1;
	}

	s_webif_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (s_webif_sock < 0) {
		tcmg_log("socket() failed: errno=%d (%s)", errno, strerror(errno));
		pthread_mutex_unlock(&s_webif_lifecycle_mtx);
		return -1;
	}

	int opt = 1;
	setsockopt(s_webif_sock, SOL_SOCKET, SO_REUSEADDR, SO_CAST(&opt), sizeof(opt));
#ifdef SO_REUSEPORT
	setsockopt(s_webif_sock, SOL_SOCKET, SO_REUSEPORT, SO_CAST(&opt), sizeof(opt));
#endif

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port   = htons((uint16_t)cfg.webif_port);
	if (cfg.webif_bindaddr[0]) {
		if (inet_pton(AF_INET, cfg.webif_bindaddr, &sa.sin_addr) != 1) {
			tcmg_log("invalid BINDADDR '%s' -- refusing to listen on all interfaces",
			         cfg.webif_bindaddr);
			close(s_webif_sock); s_webif_sock = -1;
			pthread_mutex_unlock(&s_webif_lifecycle_mtx);
			return -1;
		}
	} else
		sa.sin_addr.s_addr = INADDR_ANY;

	if (bind(s_webif_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		tcmg_log("bind() failed: port=%d errno=%d (%s)", cfg.webif_port, errno, strerror(errno));
		close(s_webif_sock); s_webif_sock = -1;
		pthread_mutex_unlock(&s_webif_lifecycle_mtx);
		return -1;
	}
	if (listen(s_webif_sock, 128) < 0) {
		tcmg_log("listen() failed: errno=%d (%s)", errno, strerror(errno));
		close(s_webif_sock); s_webif_sock = -1;
		pthread_mutex_unlock(&s_webif_lifecycle_mtx);
		return -1;
	}

	if (sem_init(&s_webif_sem, 0, WEBIF_MAX_THREADS) != 0) {
		tcmg_log("sem_init failed: errno=%d (%s)", errno, strerror(errno));
		close(s_webif_sock);
		s_webif_sock = -1;
		pthread_mutex_unlock(&s_webif_lifecycle_mtx);
		return -1;
	}
#ifndef TCMG_OS_WINDOWS
	if (pipe(s_webif_wake) != 0) {
		s_webif_wake[0] = s_webif_wake[1] = -1;
	} else {
		for (int i = 0; i < 2; i++) {
			int fl = fcntl(s_webif_wake[i], F_GETFD);
			if (fl >= 0) fcntl(s_webif_wake[i], F_SETFD, fl | FD_CLOEXEC);
		}
	}
#endif
	atomic_store_explicit(&s_webif_running, 1, memory_order_release);
	pthread_attr_t attr;
	const pthread_attr_t *attrp = NULL;
	int attr_ready = 0;
	int arc = pthread_attr_init(&attr);
	if (arc == 0) {
		attr_ready = 1;
		attrp = &attr; /* joinable is the pthread default; webif_stop joins it */
		int src = pthread_attr_setstacksize(&attr, 256 * 1024);
		if (src != 0)
			tcmg_log_dbg(D_HTTP, "HTTP server stack size request failed rc=%d (%s); using default stack", src, strerror(src));
	} else {
		tcmg_log("HTTP server attribute initialization failed rc=%d (%s); using default attributes", arc, strerror(arc));
	}
	int trc = pthread_create(&s_webif_tid, attrp, http_server_thread, NULL);
	if (trc != 0) {
		tcmg_log("HTTP server pthread_create failed rc=%d (%s)", trc, strerror(trc));
		atomic_store_explicit(&s_webif_running, 0, memory_order_release);
		sem_destroy(&s_webif_sem);
#ifndef TCMG_OS_WINDOWS
		webif_wake_close();
#endif
		close(s_webif_sock); s_webif_sock = -1;
		if (attr_ready) pthread_attr_destroy(&attr);
		pthread_mutex_unlock(&s_webif_lifecycle_mtx);
		return -1;
	}
	if (attr_ready) pthread_attr_destroy(&attr);
	pthread_mutex_unlock(&s_webif_lifecycle_mtx);
	return 0;
}

void webif_stop(void)
{
	pthread_mutex_lock(&s_webif_lifecycle_mtx);
	if (!atomic_load_explicit(&s_webif_running, memory_order_acquire)) {
		pthread_mutex_unlock(&s_webif_lifecycle_mtx);
		return;
	}
	atomic_store_explicit(&s_webif_running, 0, memory_order_release);
#ifndef TCMG_OS_WINDOWS
	if (s_webif_wake[1] >= 0) { ssize_t wr = write(s_webif_wake[1], "x", 1); (void)wr; }
#endif
	pthread_join(s_webif_tid, NULL);
	pthread_mutex_lock(&s_webif_workers_mtx);
	while (s_webif_workers != 0) pthread_cond_wait(&s_webif_workers_cv, &s_webif_workers_mtx);
	pthread_mutex_unlock(&s_webif_workers_mtx);
#ifndef TCMG_OS_WINDOWS
	webif_wake_close();
#endif
	if (s_webif_sock >= 0) { close(s_webif_sock); s_webif_sock = -1; }
	sem_destroy(&s_webif_sem);
	pthread_mutex_unlock(&s_webif_lifecycle_mtx);
}
