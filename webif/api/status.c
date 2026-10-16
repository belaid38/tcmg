#define MODULE_LOG_PREFIX "webif"
#include "../../src/core/utils.h"
#include "../../src/pcsc/pcsc.h"
#include "../../src/log/log.h"
#include "../internal/proto.h"
#include "../service/service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool status_is_lite(const char *qs)
{
    return qs && strstr(qs, "lite=1") != NULL;
}

void send_api_status(int fd, const char *qs)
{
    if (status_is_lite(qs)) {
        char buf[96];
        int n = snprintf(buf, sizeof(buf), "{\"active_connections\":%d}",
                         webif_active_connection_count());
        send_response(fd, 200, "OK", "application/json", buf, n);
        return;
    }

    int bsz = 16384, pos = 0;
    char *buf = (char *)malloc((size_t)bsz);
    if (!buf) { send_json_error(fd, 503, "Service Unavailable", "out of memory"); return; }

    S_WEBIF_CONFIG_VIEW cfg;
    S_SERVER_STATS st = collect_stats();
    webif_config_snapshot(&cfg);
    time_t now = time(NULL);

    S_WEBIF_CLIENT_VIEW clients[MAX_ACTIVE_CLIENTS];
    int nclients = webif_client_snapshot_all(clients, MAX_ACTIVE_CLIENTS);

    pos = buf_printf(&buf, &bsz, pos,
        "{"
        "\"version\":\"%s\","
        "\"build\":\"%s\","
        "\"uptime_s\":%ld,"
        "\"uptime_str\":\"%s\","
        "\"newcamd_port\":%d,"
        "\"cccam_port\":%d,"
        "\"cs378x_port\":%d,"
        "\"camd35_port\":%d,"
        "\"active_connections\":%d,"
        "\"accounts\":%d,"
        "\"banned_ips\":%d,"
        "\"cw_found\":%lld,"
        "\"cw_not\":%lld,"
        "\"ecm_total\":%llu,"
        "\"hit_rate_pct\":%.1f,"
        "\"debug_mask\":%u,"
        "\"pcsc_enabled\":%d,"
        "\"pcsc_available\":%d,"
        "\"pcsc_readers\":%d,"
        "\"clients\":[",
        TCMG_VERSION, TCMG_BUILD_TIME,
        (long)st.uptime_s, st.uptime_str,
        cfg.newcamd_port, cfg.cccam_port, cfg.cs378x_port, cfg.camd35_port, st.active_conns,
        st.naccounts, st.nbans,
        (long long)st.cw_found, (long long)st.cw_not, (unsigned long long)st.ecm_total,
        st.hit_rate, g_dblevel,
        webif_pcsc_enabled(), pcsc_available(), pcsc_reader_count());

    bool first = true;
    for (int i = 0; i < nclients; i++) {
        const S_WEBIF_CLIENT_VIEW *cl = &clients[i];
        char conn_str[32], idle_str[32];
        char esc_user[256], esc_ip[128], esc_proto[64], esc_chan[256];
        format_uptime(now > cl->connect_time ? now - cl->connect_time : 0, conn_str, sizeof(conn_str));
        time_t last_act = cl->last_activity ? cl->last_activity : cl->connect_time;
        format_uptime(now > last_act ? now - last_act : 0, idle_str, sizeof(idle_str));
        json_escape(cl->user, esc_user, sizeof(esc_user));
        json_escape(cl->ip, esc_ip, sizeof(esc_ip));
        json_escape(cl->proto, esc_proto, sizeof(esc_proto));
        json_escape(cl->channel, esc_chan, sizeof(esc_chan));
        pos = buf_printf(&buf, &bsz, pos,
            "%s{\"user\":\"%s\",\"ip\":\"%s\",\"proto\":\"%s\","
            "\"caid\":\"%04X\",\"sid\":\"%04X\",\"channel\":\"%s\","
            "\"connected\":\"%s\",\"idle\":\"%s\",\"last_60s\":%lld,\"thread_id\":%u}",
            first ? "" : ",", esc_user, esc_ip, esc_proto,
            cl->caid, cl->sid, esc_chan, conn_str, idle_str, (long long)cl->cw_last_60s, cl->thread_id);
        first = false;
    }

    pos = buf_printf(&buf, &bsz, pos, "]}");
    send_response(fd, 200, "OK", "application/json", buf, pos);
    free(buf);
}

void handle_api_client_kill(int fd, const char *qs)
{
    char tid_s[8] = "", user[CFGKEY_LEN] = "";
    get_param(qs, "tid", tid_s, sizeof(tid_s));
    get_param(qs, "user", user, sizeof(user));
    if (!tid_s[0]) { send_json_error(fd, 400, "Bad Request", "tid is required"); return; }

    char *end = NULL;
    errno = 0;
    unsigned long tid_u = strtoul(tid_s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || tid_u > UINT32_MAX) {
        send_json_error(fd, 400, "Bad Request", "invalid tid");
        return;
    }

    uint32_t tid = (uint32_t)tid_u;
    webif_client_kill_by_tid(tid);
    tcmg_log("disconnect user='%s' tid=%u (requested via api)",
              user[0] ? user : "—", tid);
    send_json_ok(fd, "ok");
}
