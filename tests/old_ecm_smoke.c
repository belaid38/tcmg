#include "reader/old_ecm.h"
#include <stdio.h>
#include <string.h>

static const char *MANUAL_ECM =
    "817034703264216EB6EFA65A38468DA2AC005F1CC011508CA82E3E4E0F74462096EE21A7F0DD1E57DD46FF3C5133886CB0861005D9E89C";

static int expect(int condition, const char *name)
{
    if (!condition) fprintf(stderr, "FAIL %s\n", name);
    return condition ? 0 : 1;
}

static void setup(S_READER *r)
{
    memset(r, 0, sizeof(*r));
    r->in_use = 1;
    r->enabled = 1;
    r->maintenance_mode = TCMG_READER_MAINT_OLD_ECM;
    r->old_ecm_source = TCMG_OLD_ECM_SOURCE_AUTO;
    r->old_ecm_successes = 3;
    r->ecm_whitelist = 0x37;
}

int main(void)
{
    int failures = 0;
    const uint8_t ecm_a[55] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55};
    const uint8_t ecm_b[55] = {55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
    const uint8_t *got = NULL;
    size_t got_len = 0;
    S_READER cfg;
    S_READER_OLD_ECM_STATE state;
    memset(&state, 0, sizeof(state));
    setup(&cfg);

    reader_old_ecm_sync(&state, &cfg);
    failures += expect(!reader_old_ecm_enabled(&(S_READER){0}), "disabled mode");
    failures += expect(reader_old_ecm_enabled(&cfg), "old ecm enabled");
    failures += expect(reader_old_ecm_get(&state, &got, &got_len) != 0, "auto starts without stored ecm");

    reader_old_ecm_bind(&state, &cfg, "/dev/sci0", (const uint8_t *)"ATR-A", 5);
    failures += expect(reader_old_ecm_get(&state, &got, &got_len) != 0, "auto bind has no stored ecm");
    reader_old_ecm_note_success(&state, &cfg, ecm_a, sizeof(ecm_a));
    failures += expect(reader_old_ecm_get(&state, &got, &got_len) == 0 && got_len == sizeof(ecm_a) && memcmp(got, ecm_a, sizeof(ecm_a)) == 0,
                       "auto captures first successful ecm");
    reader_old_ecm_note_success(&state, &cfg, ecm_b, sizeof(ecm_b));
    failures += expect(reader_old_ecm_get(&state, &got, &got_len) == 0 && memcmp(got, ecm_a, sizeof(ecm_a)) == 0,
                       "auto keeps first successful ecm");
    failures += expect(!reader_old_ecm_due(&cfg, &state, 0), "auto two successes not due yet");
    reader_old_ecm_note_success(&state, &cfg, ecm_b, sizeof(ecm_b));
    failures += expect(reader_old_ecm_due(&cfg, &state, 0), "auto three successes due");
    failures += expect(!reader_old_ecm_due(&cfg, &state, 1), "busy blocks old ecm");
    reader_old_ecm_note_attempt(&state);
    failures += expect(!reader_old_ecm_due(&cfg, &state, 0), "success counter resets after attempt");
    reader_old_ecm_note_success(&state, &cfg, ecm_a, sizeof(ecm_a));
    failures += expect(!reader_old_ecm_due(&cfg, &state, 0), "auto count restarts after attempt");

    cfg.old_ecm_source = TCMG_OLD_ECM_SOURCE_MANUAL;
    cfg.old_ecm_successes = 2;
    cfg.ecm_whitelist = 0x37;
    snprintf(cfg.old_ecm, sizeof(cfg.old_ecm), "%s", MANUAL_ECM);
    reader_old_ecm_sync(&state, &cfg);
    reader_old_ecm_bind(&state, &cfg, "/dev/sci0", (const uint8_t *)"ATR-A", 5);
    failures += expect(reader_old_ecm_get(&state, &got, &got_len) == 0 && got_len == 55,
                       "manual ecm loads");
    if (got_len == 55) {
        uint8_t parsed[TCMG_OLD_ECM_MAX_LEN];
        size_t parsed_len = 0;
        failures += expect(reader_old_ecm_parse_hex(MANUAL_ECM, parsed, sizeof(parsed), &parsed_len) == 0 && parsed_len == 55,
                           "manual ecm parses");
        failures += expect(memcmp(parsed, got, 55) == 0, "manual ecm exact bytes");
    }
    failures += expect(!reader_old_ecm_due(&cfg, &state, 0), "manual not due before any success");
    reader_old_ecm_note_success(&state, &cfg, ecm_a, sizeof(ecm_a));
    failures += expect(!reader_old_ecm_due(&cfg, &state, 0), "manual one success not due");
    reader_old_ecm_note_success(&state, &cfg, ecm_b, sizeof(ecm_b));
    failures += expect(reader_old_ecm_due(&cfg, &state, 0), "manual two successes due");
    reader_old_ecm_note_attempt(&state);
    failures += expect(!reader_old_ecm_due(&cfg, &state, 0), "manual counter resets after attempt");

    reader_old_ecm_bind(&state, &cfg, "/dev/sci0", (const uint8_t *)"ATR-B", 5);
    failures += expect(reader_old_ecm_get(&state, &got, &got_len) == 0 && got_len == 55,
                       "manual reloads on card change");
    cfg.maintenance_mode = TCMG_READER_MAINT_FAST_RESET;
    reader_old_ecm_sync(&state, &cfg);
    failures += expect(!reader_old_ecm_enabled(&cfg) && reader_old_ecm_get(&state, &got, &got_len) != 0,
                       "switching to fast reset clears old ecm runtime");

    uint8_t parsed[TCMG_OLD_ECM_MAX_LEN];
    size_t parsed_len = 0;
    failures += expect(reader_old_ecm_parse_hex("ABC", parsed, sizeof(parsed), &parsed_len) != 0, "odd hex rejected");
    failures += expect(reader_old_ecm_parse_hex("GG", parsed, sizeof(parsed), &parsed_len) != 0, "non hex rejected");
    failures += expect(reader_old_ecm_parse_hex("", parsed, sizeof(parsed), &parsed_len) != 0, "empty hex rejected");

    if (!failures) printf("old_ecm_smoke: PASS\n");
    return failures ? 1 : 0;
}
