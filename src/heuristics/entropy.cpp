/* entropy.cpp -- Entropy heuristic analyzer.
 *
 * Implements checks from section 5.6 Entropy row:
 *   - .text > 7.0  -> packed           (+20)
 *   - .text < 1.0  -> XOR-encoded      (+15)
 *   - Overall > 7.5 -> suspicious      (+10)
 *
 * Weights are JSON-configurable; defaults match REQUIREMENTS.md.
 */

#include "heuristics/entropy.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <ctype.h>

/* ── Defaults ────────────────────────────────────────────────────── */

void akav_entropy_weights_default(akav_entropy_weights_t* w)
{
    if (!w) return;
    w->text_high_entropy    = 20;
    w->text_low_entropy     = 15;
    w->overall_high_entropy = 10;
}

/* ── JSON weight loader (minimal parser, same pattern as static_analyzer) ── */

static const char* skip_ws(const char* p, const char* end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

static bool match_key(const char** pp, const char* end, const char* key)
{
    const char* p = skip_ws(*pp, end);
    if (p >= end || *p != '"') return false;
    p++;
    size_t klen = strlen(key);
    if (p + klen > end) return false;
    if (memcmp(p, key, klen) != 0) return false;
    p += klen;
    if (p >= end || *p != '"') return false;
    p++;
    p = skip_ws(p, end);
    if (p >= end || *p != ':') return false;
    p++;
    *pp = p;
    return true;
}

static bool parse_int(const char** pp, const char* end, int* out)
{
    const char* p = skip_ws(*pp, end);
    if (p >= end) return false;
    int sign = 1;
    if (*p == '-') { sign = -1; p++; }
    if (p >= end || !isdigit((unsigned char)*p)) return false;
    int val = 0;
    while (p < end && isdigit((unsigned char)*p)) {
        val = val * 10 + (*p - '0');
        p++;
    }
    *out = val * sign;
    *pp = p;
    return true;
}

bool akav_entropy_weights_load_json(akav_entropy_weights_t* w,
                                     const char* json_path)
{
    if (!w || !json_path) return false;

    akav_entropy_weights_default(w);

    FILE* f = NULL;
    fopen_s(&f, json_path, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 65536) { fclose(f); return false; }

    char* buf = (char*)malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return false; }
    size_t nread = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    buf[nread] = '\0';

    const char* end = buf + nread;

    struct { const char* name; int* target; } fields[] = {
        { "text_high_entropy",    &w->text_high_entropy },
        { "text_low_entropy",     &w->text_low_entropy },
        { "overall_high_entropy", &w->overall_high_entropy },
    };
    int num_fields = sizeof(fields) / sizeof(fields[0]);

    for (int i = 0; i < num_fields; i++) {
        const char* p = buf;
        while (p < end) {
            if (match_key(&p, end, fields[i].name)) {
                parse_int(&p, end, fields[i].target);
                break;
            }
            p++;
        }
    }

    free(buf);
    return true;
}

/* ── Shannon entropy ─────────────────────────────────────────────── */

double akav_shannon_entropy(const uint8_t* data, size_t len)
{
    if (!data || len == 0) return 0.0;

    uint32_t freq[256] = {0};
    for (size_t i = 0; i < len; i++)
        freq[data[i]]++;

    double entropy = 0.0;
    double dlen = (double)len;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / dlen;
        entropy -= p * log2(p);
    }
    return entropy;
}

/* ── Hit recording helper ────────────────────────────────────────── */

static void record_hit(akav_entropy_result_t* r, const char* name,
                        int weight, const char* fmt, ...)
{
    if (r->num_hits >= AKAV_HEUR_MAX_HITS || weight == 0) return;
    akav_heur_hit_t* h = &r->hits[r->num_hits];
    h->check_name = name;
    h->weight = weight;
    va_list args;
    va_start(args, fmt);
    vsnprintf(h->detail, sizeof(h->detail), fmt, args);
    va_end(args);
    r->total_score += weight;
    r->num_hits++;
}

/* ── Main analysis ───────────────────────────────────────────────── */

void akav_entropy_analyze(const akav_pe_t* pe,
                           const uint8_t* data, size_t data_len,
                           const akav_entropy_weights_t* weights,
                           akav_entropy_result_t* result)
{
    if (!pe || !pe->valid || !result) return;
    memset(result, 0, sizeof(*result));
    result->whole_file_entropy = -1.0;

    /* Use defaults if no weights provided */
    akav_entropy_weights_t def;
    if (!weights) {
        akav_entropy_weights_default(&def);
        weights = &def;
    }

    /* 1. Per-section checks: find .text section entropy */
    for (uint16_t i = 0; i < pe->num_sections; i++) {
        const akav_pe_section_t* sec = &pe->sections[i];

        /* Only check .text (or first code section if no .text) */
        bool is_text = (strcmp(sec->name, ".text") == 0);
        bool is_code = (sec->characteristics & 0x00000020) != 0; /* CNT_CODE */

        if (!is_text && !is_code) continue;

        if (sec->entropy < 0.0) continue; /* not computed */

        if (sec->entropy > 7.0) {
            record_hit(result, "text_high_entropy", weights->text_high_entropy,
                       "Section '%s' entropy %.2f > 7.0 (packed)",
                       sec->name, sec->entropy);
        } else if (sec->entropy < 1.0 && sec->raw_data_size > 0) {
            record_hit(result, "text_low_entropy", weights->text_low_entropy,
                       "Section '%s' entropy %.2f < 1.0 (XOR-encoded)",
                       sec->name, sec->entropy);
        }

        /* Only check the first code section we find */
        break;
    }

    /* 2. Whole-file entropy */
    if (data && data_len > 0) {
        result->whole_file_entropy = akav_shannon_entropy(data, data_len);

        if (result->whole_file_entropy > 7.5) {
            record_hit(result, "overall_high_entropy", weights->overall_high_entropy,
                       "Whole-file entropy %.2f > 7.5 (suspicious)",
                       result->whole_file_entropy);
        }
    }
}
