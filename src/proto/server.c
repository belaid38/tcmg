#define MODULE_LOG_PREFIX "proto"
#include "server.h"
#include "core/runtime_state.h"
#include "core/utils.h"
#include "platform/platform.h"
#include "log/log.h"

static void *proto_server_accept_thread(void *arg)
{
    S_PROTO_SERVER *server = (S_PROTO_SERVER *)arg;
    pthread_attr_t attr;
    const pthread_attr_t *attrp = NULL;
    int attr_ready = 0;
    int detached_attr = 0;

    if (!server) return NULL;

    int arc = pthread_attr_init(&attr);
    if (arc == 0) {
        attr_ready = 1;
        arc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (arc == 0) {
            attrp = &attr;
            detached_attr = 1;
            int src = pthread_attr_setstacksize(&attr, 256 * 1024);
            if (src != 0)
                tcmg_log_dbg(D_CONN, "[%s] stack size request failed rc=%d (%s); using default stack",
                             server->name, src, strerror(src));
        } else {
            tcmg_log("[%s] detached thread attribute failed rc=%d (%s); using per-thread detach",
                     server->name, arc, strerror(arc));
            pthread_attr_destroy(&attr);
            attr_ready = 0;
        }
    } else {
        tcmg_log("[%s] thread attribute initialization failed rc=%d (%s); using per-thread detach",
                 server->name, arc, strerror(arc));
    }
    log_set_type(LOG_TYPE_CLIENT);

    while (atomic_load(&server->running) && g_running)
    {
        const int listen_fd = server->fd;
        if (listen_fd < 0) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        struct timeval tv = {0, 200000};
        int rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (!atomic_load(&server->running) || !g_running) break;
        if (rc <= 0) continue;

        struct sockaddr_in ca;
        socklen_t clen = sizeof(ca);
        int cfd = (int)accept(listen_fd, (struct sockaddr *)&ca, &clen);
        if (cfd < 0)
        {
            if (atomic_load(&server->running))
                tcmg_log_dbg(D_CONN, "[%s] accept() failed errno=%d (%s)",
                             server->name, errno, strerror(errno));
            continue;
        }

        int active = atomic_fetch_add(&g_active_conns, 1);
        if (active >= MAX_CONNS)
        {
            atomic_fetch_sub(&g_active_conns, 1);
            close(cfd);
            tcmg_log("[%s] MAX_CONNS=%d reached -- connection rejected active=%d",
                     server->name, MAX_CONNS, active);
            continue;
        }

        S_CONN_ARGS *args = (S_CONN_ARGS *)malloc(sizeof(*args));
        if (!args)
        {
            atomic_fetch_sub(&g_active_conns, 1);
            close(cfd);
            tcmg_log("[%s] out of memory -- connection rejected active=%d",
                     server->name, active);
            continue;
        }

        args->fd = cfd;
        if (!inet_ntop(AF_INET, &ca.sin_addr, args->ip, sizeof(args->ip)))
            args->ip[0] = '\0';
        args->ip[MAXIPLEN - 1] = '\0';

        tcmg_log_dbg(D_CONN, "%s [%s] accepted connection fd=%d active=%d",
                     args->ip, server->name, cfd, active + 1);

        pthread_t tid;
        int prc = pthread_create(&tid, attrp, server->client_handler, args);
        if (prc != 0)
        {
            tcmg_log("[%s] pthread_create failed rc=%d (%s)",
                     server->name, prc, strerror(prc));
            atomic_fetch_sub(&g_active_conns, 1);
            close(cfd);
            free(args);
        } else if (!detached_attr) {
            /* pthread_attr_init/setdetachstate can fail; still detach the worker. */
            int drc = pthread_detach(tid);
            if (drc != 0) {
                tcmg_log("[%s] pthread_detach failed rc=%d (%s); joining worker to avoid leaking a joinable thread",
                         server->name, drc, strerror(drc));
                int jrc = pthread_join(tid, NULL);
                if (jrc != 0)
                    tcmg_log("[%s] fallback pthread_join failed rc=%d (%s)",
                             server->name, jrc, strerror(jrc));
            }
        }
    }

    if (attr_ready) pthread_attr_destroy(&attr);
    tcmg_log_dbg(D_CONN, "[%s] accept thread exiting", server->name);
    return NULL;
}

int32_t proto_server_start(S_PROTO_SERVER *server,
                           const char *name,
                           int32_t port,
                           const char *bindaddr,
                           T_PROTO_CLIENT_HANDLER client_handler)
{
    if (!server || !name || !client_handler) return -1;
    memset(server, 0, sizeof(*server));
    server->fd = -1;
    server->name = name;
    server->client_handler = client_handler;

    if (!port)
    {
        tcmg_log_dbg(D_CONN, "[%s] disabled (port=0)", name);
        return -1;
    }

    server->fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    int fd = server->fd;
    if (fd < 0)
    {
        tcmg_log("[%s] socket() failed errno=%d (%s)", name, errno, strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, SO_CAST(&one), sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;

    if (bindaddr && bindaddr[0])
    {
        if (inet_pton(AF_INET, bindaddr, &sa.sin_addr) != 1)
        {
            tcmg_log("[%s] invalid bind address '%s'", name, bindaddr);
            close(fd);
            server->fd = -1;
            return -1;
        }
    }
    else
    {
        sa.sin_addr.s_addr = INADDR_ANY;
    }

    sa.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        tcmg_log("[%s] bind() failed port=%d errno=%d (%s)",
                 name, port, errno, strerror(errno));
        close(fd);
        server->fd = -1;
        return -1;
    }

    if (listen(fd, 128) < 0)
    {
        tcmg_log("[%s] listen() failed errno=%d (%s)", name, errno, strerror(errno));
        close(fd);
        server->fd = -1;
        return -1;
    }

    atomic_store(&server->running, 1);
    int trc = pthread_create(&server->thread, NULL, proto_server_accept_thread, server);
    if (trc != 0)
    {
        atomic_store(&server->running, 0);
        close(fd);
        server->fd = -1;
        tcmg_log("[%s] failed to start listener rc=%d (%s)", name, trc, strerror(trc));
        return -1;
    }

    tcmg_log("[%s] listening on %s:%d", name,
             (bindaddr && bindaddr[0]) ? bindaddr : "*", port);
    return 0;
}
void proto_server_stop(S_PROTO_SERVER *server)
{
    if (!server || !atomic_load(&server->running)) return;

    /* Do not close/rewrite fd while the accept thread may still read it.
     * select() has a bounded timeout, so it will observe running=0 quickly. */
    atomic_store(&server->running, 0);
    pthread_join(server->thread, NULL);
    if (server->fd >= 0)
    {
        close(server->fd);
        server->fd = -1;
    }
    tcmg_log("[%s] stopped", server->name ? server->name : "server");
}
