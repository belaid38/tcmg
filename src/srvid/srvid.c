#include "srvid.h"
#include "../core/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#define SRVID_MIN_BUCKETS  64
#define MAX_CAIDS_PER_LINE 16

typedef struct {
	uint32_t key;
	uint32_t name_off;
} S_SRVID_ENTRY;

typedef struct {
	S_SRVID_ENTRY *tbl;
	uint32_t       mask;
	char          *pool;
	size_t         pool_len;
	size_t         pool_cap;
	int            count;
} S_SRVID_TABLE;

static S_SRVID_TABLE  *g_srvid     = NULL;
static pthread_mutex_t g_srvid_mtx = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t hash_key(uint32_t k)
{
	k ^= k >> 16;
	k *= 0x45d9f3bU;
	k ^= k >> 16;
	return k;
}

static void tbl_free(S_SRVID_TABLE *t)
{
	if (!t) return;
	free(t->tbl);
	free(t->pool);
	free(t);
}

static void tbl_insert(S_SRVID_TABLE *t, uint32_t key, uint32_t name_off)
{
	uint32_t h = hash_key(key) & t->mask;
	for (uint32_t i = 0; i <= t->mask; i++)
	{
		uint32_t idx = (h + i) & t->mask;
		if (!t->tbl[idx].key)
		{
			t->tbl[idx].key = key;
			t->tbl[idx].name_off = name_off;
			return;
		}
		if (t->tbl[idx].key == key)
			return;
	}
}

static uint32_t pool_add(S_SRVID_TABLE *t, const char *name)
{
    size_t n;
    size_t required;
    size_t ncap;
    char *np;

    if (!t || !name) return UINT32_MAX;
    n = strnlen(name, SRVID_NAME_MAX - 1);
    if (t->pool_len > UINT32_MAX || n + 1 > (size_t)UINT32_MAX - t->pool_len)
        return UINT32_MAX;
    required = t->pool_len + n + 1;

    if (required > t->pool_cap) {
        ncap = t->pool_cap ? t->pool_cap : 4096;
        while (ncap < required) {
            if (ncap > (size_t)UINT32_MAX / 2) {
                ncap = required;
                break;
            }
            ncap *= 2;
        }
        np = (char *)realloc(t->pool, ncap);
        if (!np) return UINT32_MAX;
        t->pool = np;
        t->pool_cap = ncap;
    }

    uint32_t off = (uint32_t)t->pool_len;
    memcpy(t->pool + off, name, n);
    t->pool[off + n] = '\0';
    t->pool_len += n + 1;
    return off;
}

static void trim(char *s)
{
    char *p;
    char *q;
    if (!s) return;
    p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    if (!*s) return;

    q = s + strlen(s) - 1;
    while (q > s && isspace((unsigned char)*q)) *q-- = '\0';
    if (q == s && isspace((unsigned char)*q)) *q = '\0';
}

/* A truncated fgets() buffer must not be treated as a separate physical line:
 * the remaining bytes may begin with something that looks like a valid entry. */
static bool skip_overlong_line(FILE *f, const char *line)
{
    int ch;
    if (strchr(line, '\n')) return false;
    ch = fgetc(f);
    if (ch == EOF) return false;
    while (ch != EOF && ch != '\n') ch = fgetc(f);
    return true;
}

static bool parse_hex_u16_strict(const char *s, uint16_t *out)
{
    size_t n;
    char *end = NULL;
    unsigned long v;
    if (!s || !out) return false;
    n = strlen(s);
    if (n == 0 || n > 4) return false;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i])) return false;
    errno = 0;
    v = strtoul(s, &end, 16);
    if (errno != 0 || end == s || !end || *end || v == 0 || v > UINT16_MAX)
        return false;
    *out = (uint16_t)v;
    return true;
}

int srvid_load(const char *path)
{
    FILE *f;
    char line[512];
    size_t pairs = 0;
    uint32_t nb = SRVID_MIN_BUCKETS;
    S_SRVID_TABLE *newtbl;

    if (!path || !path[0]) return -1;
    f = fopen(path, "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        if (skip_overlong_line(f, line)) continue;
        char *colon = strchr(line, ':');
        char *pipe = strchr(line, '|');
        if (!colon || !pipe || colon > pipe) continue;
        if (pairs < SIZE_MAX) pairs++;
        for (char *c = colon; c < pipe; c++)
            if (*c == ',' && pairs < SIZE_MAX) pairs++;
    }
    if (ferror(f)) { fclose(f); return -1; }
    rewind(f);

    size_t target = pairs > SIZE_MAX / 2 ? SIZE_MAX : pairs * 2;
    while ((size_t)nb < target && nb < (1u << 24)) nb <<= 1;

    newtbl = (S_SRVID_TABLE *)calloc(1, sizeof(S_SRVID_TABLE));
    if (!newtbl) { fclose(f); return -1; }
    newtbl->tbl = (S_SRVID_ENTRY *)calloc(nb, sizeof(S_SRVID_ENTRY));
    if (!newtbl->tbl) { tbl_free(newtbl); fclose(f); return -1; }
    newtbl->mask = nb - 1;

    while (fgets(line, sizeof(line), f)) {
        if (skip_overlong_line(f, line)) continue;
        trim(line);
        if (!line[0] || line[0] == '#') continue;

        char *pipe = strchr(line, '|');
        if (!pipe) continue;
        *pipe++ = '\0';
        char *name_end = strchr(pipe, '|');
        if (name_end) *name_end = '\0';
        trim(pipe);
        if (!*pipe) continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon++ = '\0';
        trim(line);

        uint16_t sid;
        if (!parse_hex_u16_strict(line, &sid)) continue;

        uint16_t caids[MAX_CAIDS_PER_LINE];
        int ncaid = 0;
        char *saveptr = NULL;
        char *tok = strtok_r(colon, ",", &saveptr);
        bool valid = true;
        while (tok) {
            uint16_t caid;
            trim(tok);
            if (ncaid >= MAX_CAIDS_PER_LINE || !parse_hex_u16_strict(tok, &caid)) {
                valid = false;
                break;
            }
            bool duplicate = false;
            for (int i = 0; i < ncaid; i++)
                if (caids[i] == caid) { duplicate = true; break; }
            if (!duplicate) caids[ncaid++] = caid;
            tok = strtok_r(NULL, ",", &saveptr);
        }
        if (!valid || ncaid == 0) continue;

        uint32_t name_off = pool_add(newtbl, pipe);
        if (name_off == UINT32_MAX) {
            tbl_free(newtbl);
            fclose(f);
            return -1;
        }
        for (int i = 0; i < ncaid; i++) {
            uint32_t key = ((uint32_t)caids[i] << 16) | sid;
            tbl_insert(newtbl, key, name_off);
        }
        newtbl->count++;
    }
    if (ferror(f)) {
        tbl_free(newtbl);
        fclose(f);
        return -1;
    }
    fclose(f);

    if (newtbl->pool && newtbl->pool_len < newtbl->pool_cap) {
        char *tp = (char *)realloc(newtbl->pool, newtbl->pool_len);
        if (tp) { newtbl->pool = tp; newtbl->pool_cap = newtbl->pool_len; }
    }

    const int count = newtbl->count;
    pthread_mutex_lock(&g_srvid_mtx);
    S_SRVID_TABLE *old = g_srvid;
    g_srvid = newtbl;
    pthread_mutex_unlock(&g_srvid_mtx);
    tbl_free(old);
    return count;
}

void srvid_lookup_copy(uint16_t caid, uint16_t sid, char *buf, size_t bufsz)
{
	if (!buf || !bufsz) return;
	buf[0] = '\0';
	pthread_mutex_lock(&g_srvid_mtx);
	S_SRVID_TABLE *t = g_srvid;
	if (!t || !sid || !caid) { pthread_mutex_unlock(&g_srvid_mtx); return; }

	uint32_t key = ((uint32_t)caid << 16) | sid;
	uint32_t h   = hash_key(key) & t->mask;

	for (uint32_t i = 0; i <= t->mask; i++)
	{
		uint32_t idx = (h + i) & t->mask;
		if (!t->tbl[idx].key) break;
		if (t->tbl[idx].key == key)
		{
			const char *name = t->pool + t->tbl[idx].name_off;
			size_t n = strlen(name);
			if (n >= bufsz) n = bufsz - 1;
			memcpy(buf, name, n);
			buf[n] = '\0';
			break;
		}
	}
	pthread_mutex_unlock(&g_srvid_mtx);
}

const char *srvid_lookup(uint16_t caid, uint16_t sid)
{
	static __thread char t_name[SRVID_NAME_MAX];
	srvid_lookup_copy(caid, sid, t_name, sizeof(t_name));
	return t_name[0] ? t_name : NULL;
}

int srvid_write_default(const char *path)
{
	FILE *f = fopen(path, "w");
	if (!f) return 0;

	fprintf(f,
	"# tcmg.srvid2 — channel name database\n"
	"# Format: SID:CAID[,CAID2,...]|Channel Name|type||provider\n"
	"# Generated automatically. Add or edit entries as needed.\n"
	"# SID and CAID values are hexadecimal.\n"
	"\n"
	"# ── beIN SPORTS ─────────────────────────────────────────────────────────────\n"
	"0101:0B00,0B01,0B02|beIN SPORTS HD 1|TV||beIN SPORTS\n"
	"0102:0B00,0B01,0B02|beIN SPORTS HD 2|TV||beIN SPORTS\n"
	"0103:0B00,0B01,0B02|beIN SPORTS HD 3|TV||beIN SPORTS\n"
	);

	fclose(f);
	return 1;
}

void srvid_free(void)
{
	pthread_mutex_lock(&g_srvid_mtx);
	if (g_srvid) { tbl_free(g_srvid); g_srvid = NULL; }
	pthread_mutex_unlock(&g_srvid_mtx);
}
