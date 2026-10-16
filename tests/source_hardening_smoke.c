#include "config/config_internal.h"
#include "srvid/srvid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int callbacks;

static E_CFG_CB_RESULT count_callback(const char *section, const S_KV *kv,
                                      void *ctx, char *err, size_t errsz)
{
    (void)ctx;
    (void)err;
    (void)errsz;
    if (section && kv && !strcmp(section, "webif") &&
        !strcmp(kv->key, "should_not_be_seen")) callbacks++;
    return CFG_CB_OK;
}

static int write_bytes(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    int ok = fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0) ok = 0;
    return ok;
}

static int file_equals(const char *path, const char *expected)
{
    char buf[256];
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    int read_ok = !ferror(f);
    int close_ok = fclose(f) == 0;
    buf[n] = '\0';
    return read_ok && close_ok && strcmp(buf, expected) == 0;
}

static int test_paths(void)
{
    char out[128];
    cfg_path_sibling(out, sizeof(out), "/etc/tcmg.conf", "tcmg.users");
    if (strcmp(out, "/etc/tcmg.users") != 0) return 0;
    cfg_path_sibling(out, sizeof(out), "tcmg.conf", "tcmg.users");
    if (strcmp(out, "./tcmg.users") != 0) return 0;
    cfg_path_sibling(out, 8, "/a/very/long/config.ini", "tcmg.users");
    return out[0] == '\0';
}

static int test_long_config_line(const char *dir)
{
    char path[512];
    char err[256] = "";
    FILE *f;
    snprintf(path, sizeof(path), "%s/long.conf", dir);
    f = fopen(path, "wb");
    if (!f) return 0;
    if (fwrite("[global]\n", 1, 9, f) != 9) { fclose(f); return 0; }
    for (int i = 0; i < 4095; i++) {
        if (fputc('X', f) == EOF) { fclose(f); return 0; }
    }
    /* This token starts in the continuation of an oversized physical line.
     * It must not be reinterpreted as a fresh section. */
    const char *continuation = "[webif]\nshould_not_be_seen=yes\n";
    if (fwrite(continuation, 1, strlen(continuation), f) != strlen(continuation) || fclose(f) != 0)
        return 0;
    callbacks = 0;
    if (!cfg_parse_file(path, count_callback, NULL, err, sizeof(err))) return 0;
    return callbacks == 0;
}

static int test_srvid(const char *dir)
{
    char path[512], injected[600];
    char name[SRVID_NAME_MAX];
    FILE *f;
    const char *valid_and_invalid =
        "\n   \n# empty and whitespace lines\n"
        "0101:0B00,0B01|Valid Channel|TV||provider\n"
        "10001:0B00|Wrapped SID must be rejected\n"
        "0102:10B00|Wrapped CAID must be rejected\n"
        "0001xyz:0B00|Trailing SID junk must be rejected\n"
        "0103:0B00junk|Trailing CAID junk must be rejected\n";
    const char *forged = "0105:0B00|Forged long-line continuation|TV\n";
    snprintf(path, sizeof(path), "%s/tcmg.srvid2", dir);
    f = fopen(path, "wb");
    if (!f) return 0;
    if (fwrite(valid_and_invalid, 1, strlen(valid_and_invalid), f) != strlen(valid_and_invalid)) {
        fclose(f); return 0;
    }
    memset(injected, 'X', 511);
    memcpy(injected + 511, forged, strlen(forged));
    if (fwrite(injected, 1, 511 + strlen(forged), f) != 511 + strlen(forged) || fclose(f) != 0)
        return 0;

    int count = srvid_load(path);
    if (count != 1) { srvid_free(); return 0; }
    srvid_lookup_copy(0x0B00, 0x0101, name, sizeof(name));
    if (strcmp(name, "Valid Channel") != 0) { srvid_free(); return 0; }
    srvid_lookup_copy(0x0B01, 0x0101, name, sizeof(name));
    if (strcmp(name, "Valid Channel") != 0) { srvid_free(); return 0; }
    srvid_lookup_copy(0x0B00, 0x0001, name, sizeof(name));
    if (name[0]) { srvid_free(); return 0; }
    srvid_lookup_copy(0x0B00, 0x0102, name, sizeof(name));
    if (name[0]) { srvid_free(); return 0; }
    srvid_lookup_copy(0x0B00, 0x0103, name, sizeof(name));
    if (name[0]) { srvid_free(); return 0; }
    srvid_lookup_copy(0x0B00, 0x0105, name, sizeof(name));
    if (name[0]) { srvid_free(); return 0; }
    srvid_free();
    return 1;
}

static int test_atomic_config_write(const char *dir)
{
    char path[512], target[512], symlink_path[540];
    struct stat st;
    snprintf(path, sizeof(path), "%s/tcmg.conf", dir);
    snprintf(target, sizeof(target), "%s/victim.txt", dir);
    snprintf(symlink_path, sizeof(symlink_path), "%s.new", path);
    if (!write_bytes(target, "untouched", 9)) return 0;
    if (symlink(target, symlink_path) != 0) return 0;

    if (!cfg_write_atomic(path, "secret=config\n")) return 0;
    if (!file_equals(target, "untouched")) return 0;
    if (!file_equals(path, "secret=config\n")) return 0;
    if (stat(path, &st) != 0 || (st.st_mode & 0777) != 0600) return 0;
    unlink(symlink_path);
    return 1;
}

int main(void)
{
    char dir[] = "/tmp/tcmg-source-hardening-XXXXXX";
    char path[512];
    if (!mkdtemp(dir)) return 2;
    if (!test_paths()) { fprintf(stderr, "path sibling test failed\n"); return 3; }
    if (!test_long_config_line(dir)) { fprintf(stderr, "long config line test failed\n"); return 4; }
    if (!test_srvid(dir)) { fprintf(stderr, "srvid parser test failed\n"); return 5; }
    if (!test_atomic_config_write(dir)) { fprintf(stderr, "atomic config write test failed\n"); return 6; }
    srvid_free();
    snprintf(path, sizeof(path), "%s/long.conf", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/tcmg.srvid2", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/tcmg.conf", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/victim.txt", dir); unlink(path);
    rmdir(dir);
    printf("source hardening smoke: PASS\n");
    return 0;
}
