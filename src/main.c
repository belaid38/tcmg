#define MODULE_LOG_PREFIX "main"
#include "core/state.h"
#include "core/utils.h"
#include "crypto/crypto.h"
#include "log/log.h"
#include "config/config.h"
#include "account/account.h"
#include "platform/platform.h"
#include "srvid/srvid.h"
#include "emu/emu.h"
#include "pcsc/pcsc.h"
#include "internal/internal.h"
#include "serial/serial.h"
#include "reader/reader.h"
#include "proto/registry.h"
#include "webif/server.h"
#include "client/client.h"
#include "dvbapi/dvbapi.h"
#include "security/failban.h"

static char **g_argv_saved = NULL;

static void scheduled_restart_key(const struct tm *tm, char *out, size_t out_len)
{
    if (!tm || !out || out_len == 0)
        return;
    snprintf(out, out_len, "%04d:%03d:%04d",
             tm->tm_year + 1900, tm->tm_yday, tm->tm_hour * 60 + tm->tm_min);
}

static int scheduled_restart_was_already_done(const struct tm *tm)
{
    const char *env = getenv("TCMG_SCHEDULED_RESTART_KEY");
    char key[32] = "";
    if (!env || !*env)
        return 0;
    scheduled_restart_key(tm, key, sizeof(key));
    return strcmp(env, key) == 0;
}

static void mark_scheduled_restart_done(const struct tm *tm)
{
    char key[32] = "";
    scheduled_restart_key(tm, key, sizeof(key));
#ifdef TCMG_OS_WINDOWS
    _putenv_s("TCMG_SCHEDULED_RESTART_KEY", key);
#else
    (void)setenv("TCMG_SCHEDULED_RESTART_KEY", key, 1);
#endif
}

static void print_usage(const char *prog)
{
	printf("\nUsage: %s [options]\n\n"
	       "Options:\n"
	       "  -c <dir>    Config directory (default: %s)\n"
	       "              Loads <dir>/" TCMG_CFG_FILE "\n"
	       "  -b          Run in background (daemonize)\n"
	       "  -d <level>  Debug bitmask (hex or decimal)\n"
	       "                0x0001=wire    0x0002=ecm     0x0004=emu\n"
	       "                0x0008=newcamd 0x0010=cccam   0x0020=http\n"
	       "                0x0040=conn    0x0080=reader  0x0100=protocol\n"
	       "                0x0200=dvbapi\n"
	       "                0xFFFF=all\n"
	       "  -v          Show version and exit\n"
	       "  -h          Show this help\n\n",
	       prog, CS_CONFDIR);
}

int main(int argc, char *argv[])
{
	char           srvidpath[CFGPATH_LEN];
	char           cfgpath[CFGPATH_LEN];

	g_start_time = time(NULL);
	g_argv_saved = argv;
	tcmg_winsock_init();
	tcmg_setup_signals(&g_running);

	int do_daemon = 0;
	(void)do_daemon;

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
		{
			tcmg_strlcpy(g_cfgdir, argv[++i], CFGPATH_LEN);
		}
		else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
		{
			char *end = NULL;
			errno = 0;
			long v = strtol(argv[++i], &end, 0);
			if (errno == 0 && end && *end == '\0' && v >= 0 && v <= 0xFFFF)
				g_dblevel = (uint16_t)v;
		}
		else if (strcmp(argv[i], "-b") == 0)
		{
			do_daemon = 1;
		}
		else if (strcmp(argv[i], "-v") == 0)
		{
			printf("%s\n", TCMG_BANNER);
			return 0;
		}
		else if (strcmp(argv[i], "-h") == 0)
		{
			print_usage(argv[0]);
			return 0;
		}
	}

	if (do_daemon && tcmg_daemonise() < 0)
		return 1;

	printf(
		"\n"
		"  _____  ____  __  __  ____\n"
		" |_   _|/ ___||  \\/  |/ ___|\n"
		"   | |  | |    | |\\/| | |  _\n"
		"   | |  | |___ | |  | | |_| |\n"
		"   |_|   \\____||_|  |_|\\____|\n"
		"\n"
		"  v" TCMG_VERSION "  --  built " TCMG_BUILD_TIME "\n"
		"\n");

	secure_zero(&g_cfg, sizeof(g_cfg));
	pthread_rwlock_init(&g_cfg.acc_lock, NULL);
	pthread_mutex_init(&g_cfg.ban_lock, NULL);

	tcmg_build_path(cfgpath, sizeof(cfgpath), g_cfgdir, TCMG_CFG_FILE);
	tcmg_mkdir(g_cfgdir);

	if (!cfg_load(cfgpath, &g_cfg))
	{
		if (access(cfgpath, F_OK) == 0)
		{
			tcmg_log("FATAL invalid configuration: %s (existing file was not overwritten)", cfgpath);
			return 1;
		}
		tcmg_log("config not found at %s -- writing split defaults", cfgpath);
		if (!cfg_write_default(cfgpath) || !cfg_load(cfgpath, &g_cfg))
		{
			tcmg_log("FATAL cannot create/load default configuration dir=%s", g_cfgdir);
			return 1;
		}
	}

	tcmg_log("config loaded file=%s", g_cfg.config_file);
	cfg_print(&g_cfg);
	log_ecm_set(g_cfg.ecm_log);

	tcmg_build_path(srvidpath, sizeof(srvidpath), g_cfgdir, TCMG_SRVID_FILE);
	{
		FILE *chk = fopen(srvidpath, "r");
		if (!chk)
		{
			tcmg_log("srvid file not found at %s -- writing defaults", srvidpath);
			if (!srvid_write_default(srvidpath))
				tcmg_log("srvid FAILED to create default file=%s", srvidpath);
		}
		else fclose(chk);
	}
	{
		int n = srvid_load(srvidpath);
		if (n >= 0)
			tcmg_log("srvid loaded channels=%d file=%s", n, srvidpath);
	}

	if (g_cfg.logfile[0])
	{
		log_set_file(g_cfg.logfile);
		tcmg_log("log file=%s", g_cfg.logfile);
	}
	if (g_cfg.usrfile[0])
	{
		log_set_usrfile(g_cfg.usrfile);
		tcmg_log("user stats file=%s", g_cfg.usrfile);
	}

	if (g_cfg.nreaders == 0)
		tcmg_log("%s", "no readers configured: clients will receive no CW until a reader is added");

	log_init();
	emu_init();
	pcsc_start();
	internal_start();
	serial_start();
	webif_start();
	proto_start_all();
	dvbapi_start();

	int scheduled_restart_day = -1;
	while (g_running)
	{
		time_t now = time(NULL);
		struct tm local_tm;
		int scheduled_restart_enabled = 0;
		int scheduled_restart_minutes = 240;
		pthread_rwlock_rdlock(&g_cfg.acc_lock);
		scheduled_restart_enabled = g_cfg.scheduled_restart_enabled;
		scheduled_restart_minutes = g_cfg.scheduled_restart_minutes;
		pthread_rwlock_unlock(&g_cfg.acc_lock);
		if (localtime_r(&now, &local_tm) &&
			scheduled_restart_enabled &&
			local_tm.tm_hour * 60 + local_tm.tm_min == scheduled_restart_minutes)
		{
			int day = local_tm.tm_year * 366 + local_tm.tm_yday;
			if (day != scheduled_restart_day && !scheduled_restart_was_already_done(&local_tm))
			{
				scheduled_restart_day = day;
				mark_scheduled_restart_done(&local_tm);
				tcmg_log("scheduled restart: 04:00 immediate");
				atomic_store(&g_restart_immediate, 1);
				atomic_store(&g_restart, 1);
				atomic_store(&g_running, 0);
				break;
			}
		}

		if (g_reload_cfg)
		{
			g_reload_cfg = 0;
			char errbuf[256] = "";
			if (cfg_reload(g_cfg.config_file, errbuf, sizeof(errbuf)))
			{
				srvid_load(srvidpath);
			}
			else
				tcmg_log("config reload failed: %s", errbuf);
		}
		tcmg_sleep_ms(100);
	}

	{
		int nc = g_active_conns;
		if (nc > 0)
			tcmg_log("shutdown: waiting for %d active client(s) to disconnect", nc);
		else
			tcmg_log("%s", "shutdown: no active clients -- proceeding");
	}

	webif_stop();
	pcsc_stop();
	internal_stop();
	serial_stop();
	dvbapi_stop();
	proto_stop_all();

	if (atomic_load(&g_restart_immediate))
	{
		tcmg_log("scheduled restart: dropping active connections and restarting now");
		reader_shutdown();
		tcmg_winsock_cleanup();
		log_flush();
		tcmg_exec_restart(g_argv_saved);
		tcmg_log("scheduled restart: exec failed");
		return 1;
	}

	for (int w = 0; w < 50 && g_active_conns > 0; w++)
	{
		if (w == 0)
			tcmg_log("shutdown: waiting for %d connection(s) to close", g_active_conns);
		sleep(1);
	}
	if (g_active_conns > 0)
		tcmg_log("shutdown: FORCED EXIT %d connection(s) still open --",
		         g_active_conns);

	if (g_active_conns == 0)
	{
		reader_shutdown();
		pthread_rwlock_wrlock(&g_cfg.acc_lock);
		cfg_accounts_free(&g_cfg);
		pthread_rwlock_unlock(&g_cfg.acc_lock);
		account_retired_free();
	}
	else
	{
		tcmg_log("shutdown: active connections remain; skipping account reclamation before process exit");
	}
	ban_free_all();
	srvid_free();
	pthread_rwlock_destroy(&g_cfg.acc_lock);
	pthread_mutex_destroy(&g_cfg.ban_lock);

	tcmg_winsock_cleanup();

	log_flush();
	log_shutdown();

	if (g_restart)
	{
		tcmg_exec_restart(g_argv_saved);
	}

	return 0;
}
