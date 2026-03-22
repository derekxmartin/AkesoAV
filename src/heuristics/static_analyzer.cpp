/* static_analyzer.cpp -- PE header heuristic analyzer.
 *
 * Implements all checks from section 5.6 "PE Header" row:
 *   - Entry point outside .text
 *   - W+X sections
 *   - Packer section names
 *   - <3 import DLLs / zero imports
 *   - Suspicious timestamp
 *   - Checksum mismatch
 *   - Overlay with high entropy
 *
 * Weights are JSON-configurable; defaults match REQUIREMENTS.md.
 */

#include "heuristics/static_analyzer.h"
#include "parsers/safe_reader.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <time.h>
#include <ctype.h>

/* ── Defaults ────────────────────────────────────────────────────── */

void akav_pe_header_weights_default(akav_pe_header_weights_t* w)
{
    if (!w) return;
    w->entry_outside_text   = 15;
    w->wx_section           = 20;
    w->packer_section_name  = 25;
    w->few_import_dlls      = 10;
    w->zero_imports         = 20;
    w->suspicious_timestamp = 10;
    w->checksum_mismatch    = 5;
    w->overlay_high_entropy = 15;
}

/* ── JSON weight loader (minimal parser) ─────────────────────────── */

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

bool akav_pe_header_weights_load_json(akav_pe_header_weights_t* w,
                                       const char* json_path)
{
    if (!w || !json_path) return false;

    akav_pe_header_weights_default(w);

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

    /* Simple scan for known keys */
    struct { const char* name; int* target; } fields[] = {
        { "entry_outside_text",   &w->entry_outside_text },
        { "wx_section",           &w->wx_section },
        { "packer_section_name",  &w->packer_section_name },
        { "few_import_dlls",      &w->few_import_dlls },
        { "zero_imports",         &w->zero_imports },
        { "suspicious_timestamp", &w->suspicious_timestamp },
        { "checksum_mismatch",    &w->checksum_mismatch },
        { "overlay_high_entropy", &w->overlay_high_entropy },
    };
    int num_fields = sizeof(fields) / sizeof(fields[0]);

    /* Scan through JSON looking for each key */
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

/* ── Shannon entropy helper ──────────────────────────────────────── */

static double shannon_entropy(const uint8_t* data, size_t len)
{
    if (len == 0) return 0.0;
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

/* ── PE checksum computation (matches Windows PE spec) ───────────── */

static uint32_t compute_pe_checksum(const uint8_t* data, size_t data_len,
                                     uint32_t checksum_offset)
{
    /* PE checksum algorithm: 16-bit fold-add over the file,
       skipping the 4-byte checksum field in the optional header. */
    uint64_t sum = 0;
    size_t words = data_len / 2;

    for (size_t i = 0; i < words; i++) {
        /* Skip the two 16-bit words that make up the checksum field */
        size_t byte_offset = i * 2;
        if (byte_offset == checksum_offset || byte_offset == checksum_offset + 2)
            continue;
        uint16_t word = (uint16_t)(data[byte_offset] | (data[byte_offset + 1] << 8));
        sum += word;
        /* Fold carry */
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    /* Handle odd trailing byte */
    if (data_len & 1) {
        sum += data[data_len - 1];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    /* Final fold */
    sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint32_t)(sum + data_len);
}

/* ── Case-insensitive string match helper ────────────────────────── */

static bool streqi(const char* a, const char* b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return false;
        a++; b++;
    }
    return *a == *b;
}

/* ── Packer section name list ────────────────────────────────────── */

static const char* PACKER_SECTION_NAMES[] = {
    ".UPX0", ".UPX1", ".UPX2",
    ".aspack",
    ".adata",
    ".themida",
    ".vmp0", ".vmp1",
    ".nsp0", ".nsp1",       /* NSPack */
    ".packed",
    ".petite",
    ".pec1", ".pec2",       /* PECompact */
    ".spack",
    ".perplex",
    ".yP",                  /* Y0da Protector */
    ".MaskPE",
    NULL
};

static bool is_packer_section(const char* name)
{
    for (int i = 0; PACKER_SECTION_NAMES[i]; i++) {
        if (streqi(name, PACKER_SECTION_NAMES[i]))
            return true;
    }
    return false;
}

/* ── Hit recording helper ────────────────────────────────────────── */

static void record_hit(akav_pe_header_result_t* r, const char* name,
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

void akav_pe_header_analyze(const akav_pe_t* pe,
                             const uint8_t* data, size_t data_len,
                             const akav_pe_header_weights_t* weights,
                             akav_pe_header_result_t* result)
{
    if (!pe || !pe->valid || !result) return;
    memset(result, 0, sizeof(*result));

    /* Use defaults if no weights provided */
    akav_pe_header_weights_t def;
    if (!weights) {
        akav_pe_header_weights_default(&def);
        weights = &def;
    }

    /* 1. Entry point outside .text section */
    {
        const akav_pe_section_t* text = akav_pe_find_section(pe, ".text");
        if (text) {
            uint32_t ep_rva = pe->entry_point;
            uint32_t sec_start = text->virtual_address;
            uint32_t sec_end = sec_start + text->virtual_size;
            if (ep_rva < sec_start || ep_rva >= sec_end) {
                record_hit(result, "entry_outside_text", weights->entry_outside_text,
                           "EP RVA 0x%X outside .text [0x%X-0x%X)",
                           ep_rva, sec_start, sec_end);
            }
        } else if (pe->num_sections > 0) {
            /* No .text section at all -- check if EP is in the first code section */
            bool ep_in_code = false;
            for (uint16_t i = 0; i < pe->num_sections; i++) {
                if (pe->sections[i].characteristics & AKAV_PE_SCN_CNT_CODE) {
                    uint32_t s = pe->sections[i].virtual_address;
                    uint32_t e = s + pe->sections[i].virtual_size;
                    if (pe->entry_point >= s && pe->entry_point < e) {
                        ep_in_code = true;
                        break;
                    }
                }
            }
            if (!ep_in_code && pe->entry_point != 0) {
                record_hit(result, "entry_outside_text", weights->entry_outside_text,
                           "EP RVA 0x%X not in any code section", pe->entry_point);
            }
        }
    }

    /* 2. W+X sections (writable + executable) */
    {
        const uint32_t wx_mask = AKAV_PE_SCN_MEM_WRITE | AKAV_PE_SCN_MEM_EXECUTE;
        for (uint16_t i = 0; i < pe->num_sections; i++) {
            if ((pe->sections[i].characteristics & wx_mask) == wx_mask) {
                record_hit(result, "wx_section", weights->wx_section,
                           "Section '%s' is W+X (0x%08X)",
                           pe->sections[i].name, pe->sections[i].characteristics);
            }
        }
    }

    /* 3. Packer section names */
    {
        for (uint16_t i = 0; i < pe->num_sections; i++) {
            if (is_packer_section(pe->sections[i].name)) {
                record_hit(result, "packer_section_name", weights->packer_section_name,
                           "Packer section: '%s'", pe->sections[i].name);
            }
        }
    }

    /* 4. Import DLL count checks */
    {
        if (pe->num_import_dlls == 0) {
            record_hit(result, "zero_imports", weights->zero_imports,
                       "PE has zero imported DLLs");
        } else if (pe->num_import_dlls < 3) {
            record_hit(result, "few_import_dlls", weights->few_import_dlls,
                       "PE imports only %u DLL(s)", pe->num_import_dlls);
        }
    }

    /* 5. Suspicious timestamp */
    {
        uint32_t ts = pe->timestamp;
        if (ts == 0) {
            record_hit(result, "suspicious_timestamp", weights->suspicious_timestamp,
                       "Timestamp is zero");
        } else {
            /* Check for <1990 or >future (current year + 2) */
            /* 1990-01-01 00:00:00 UTC = 631152000 */
            const uint32_t ts_1990 = 631152000u;
            /* Use a generous future cutoff: 2035-01-01 = 2051222400 */
            const uint32_t ts_future = 2051222400u;
            if (ts < ts_1990) {
                record_hit(result, "suspicious_timestamp", weights->suspicious_timestamp,
                           "Timestamp 0x%X is before 1990", ts);
            } else if (ts > ts_future) {
                record_hit(result, "suspicious_timestamp", weights->suspicious_timestamp,
                           "Timestamp 0x%X is in the far future", ts);
            }
        }
    }

    /* 6. Checksum mismatch */
    if (data && data_len > 0 && pe->checksum != 0) {
        /* The checksum field is at e_lfanew + 4 (PE sig) + 20 (COFF) + 64 (opt header offset) */
        /* For PE32: checksum is at optional_header_start + 64 */
        /* For PE32+: checksum is at optional_header_start + 64 */
        uint32_t opt_hdr_start = pe->e_lfanew + 4 + 20; /* PE sig + COFF header */
        uint32_t checksum_offset = opt_hdr_start + 64;

        if (checksum_offset + 4 <= data_len) {
            uint32_t computed = compute_pe_checksum(data, data_len, checksum_offset);
            if (computed != pe->checksum) {
                record_hit(result, "checksum_mismatch", weights->checksum_mismatch,
                           "PE checksum 0x%X != computed 0x%X",
                           pe->checksum, computed);
            }
        }
    }

    /* 7. Overlay with high entropy */
    if (pe->has_overlay && pe->overlay_size > 0 && data && data_len > 0) {
        if ((size_t)pe->overlay_offset + pe->overlay_size <= data_len) {
            double ent = shannon_entropy(data + pe->overlay_offset, pe->overlay_size);
            if (ent > 7.0) {
                record_hit(result, "overlay_high_entropy", weights->overlay_high_entropy,
                           "Overlay (%u bytes) entropy %.2f > 7.0",
                           pe->overlay_size, ent);
            }
        }
    }
}
