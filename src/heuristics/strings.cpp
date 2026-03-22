/* strings.cpp -- String heuristic analyzer.
 *
 * Implements checks from section 5.6 Strings row:
 *   - cmd.exe                          (+5)
 *   - powershell.exe                   (+10)
 *   - WScript.Shell                    (+10)
 *   - CurrentVersion\Run               (+15)
 *   - http:// or https:// per match    (+5/ea)
 *   - IP address pattern per match     (+5/ea)
 *   - base64 blob >100 chars           (+10)
 *
 * Weights are JSON-configurable; defaults match REQUIREMENTS.md.
 */

#include "heuristics/strings.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

/* ── Defaults ────────────────────────────────────────────────────── */

void akav_string_weights_default(akav_string_weights_t* w)
{
    if (!w) return;
    w->cmd_exe            = 5;
    w->powershell_exe     = 10;
    w->wscript_shell      = 10;
    w->currentversion_run = 15;
    w->url_http           = 5;
    w->ip_address         = 5;
    w->base64_blob        = 10;
}

/* ── JSON weight loader (minimal parser, same pattern as other analyzers) ── */

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

bool akav_string_weights_load_json(akav_string_weights_t* w,
                                    const char* json_path)
{
    if (!w || !json_path) return false;

    akav_string_weights_default(w);

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
        { "cmd_exe",            &w->cmd_exe },
        { "powershell_exe",     &w->powershell_exe },
        { "wscript_shell",      &w->wscript_shell },
        { "currentversion_run", &w->currentversion_run },
        { "url_http",           &w->url_http },
        { "ip_address",         &w->ip_address },
        { "base64_blob",        &w->base64_blob },
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

/* ── Hit recording helper ────────────────────────────────────────── */

static void record_hit(akav_string_result_t* r, const char* name,
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

/* ── Case-insensitive substring search ───────────────────────────── */

/* Find needle in haystack (case-insensitive), return pointer or NULL.
 * Works on binary data — stops at haystack_len, not null terminator. */
static const uint8_t* ci_memmem(const uint8_t* haystack, size_t haystack_len,
                                  const char* needle, size_t needle_len)
{
    if (needle_len == 0 || needle_len > haystack_len) return NULL;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        bool match = true;
        for (size_t j = 0; j < needle_len; j++) {
            if (tolower(haystack[i + j]) != tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return &haystack[i];
    }
    return NULL;
}

/* Count all case-insensitive occurrences of needle in haystack. */
static int ci_count_occurrences(const uint8_t* data, size_t data_len,
                                 const char* needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > data_len) return 0;

    int count = 0;
    size_t offset = 0;
    while (offset <= data_len - nlen) {
        const uint8_t* found = ci_memmem(data + offset, data_len - offset,
                                          needle, nlen);
        if (!found) break;
        count++;
        offset = (size_t)(found - data) + nlen;
    }
    return count;
}

/* ── IP address pattern detector ─────────────────────────────────── */

/* Check if position starts a decimal number 0-255. Returns length consumed. */
static int parse_octet(const uint8_t* p, size_t remaining)
{
    if (remaining == 0 || !isdigit(p[0])) return 0;

    int val = 0;
    int len = 0;
    while (len < 3 && (size_t)len < remaining && isdigit(p[len])) {
        val = val * 10 + (p[len] - '0');
        len++;
    }
    if (val > 255) return 0;

    /* Reject leading zeros (e.g., "01" or "001") to avoid false positives */
    if (len > 1 && p[0] == '0') return 0;

    return len;
}

/* Count IP address patterns (a.b.c.d where each octet is 0-255).
 * Rejects trivial patterns: 0.0.0.0, 127.0.0.1, and common version strings. */
static int count_ip_addresses(const uint8_t* data, size_t data_len)
{
    int count = 0;
    size_t i = 0;

    while (i < data_len) {
        /* Skip if preceded by alphanumeric (part of a longer token) */
        if (i > 0 && (isalnum(data[i - 1]) || data[i - 1] == '.'))
        {
            i++;
            continue;
        }

        const uint8_t* start = &data[i];
        size_t remaining = data_len - i;

        /* Parse 4 octets separated by dots */
        int octets[4] = {0};
        size_t pos = 0;
        bool valid = true;

        for (int oct = 0; oct < 4; oct++) {
            int olen = parse_octet(start + pos, remaining - pos);
            if (olen == 0) { valid = false; break; }

            /* Read the octet value */
            int oval = 0;
            for (int d = 0; d < olen; d++)
                oval = oval * 10 + (start[pos + d] - '0');
            octets[oct] = oval;

            pos += (size_t)olen;

            if (oct < 3) {
                if (pos >= remaining || start[pos] != '.') { valid = false; break; }
                pos++;
            }
        }

        if (!valid) { i++; continue; }

        /* Reject if followed by alphanumeric or dot (part of longer token) */
        if (i + pos < data_len && (isalnum(data[i + pos]) || data[i + pos] == '.'))
        {
            i++;
            continue;
        }

        /* Reject common benign IPs */
        bool benign =
            (octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0) ||
            (octets[0] == 127 && octets[1] == 0 && octets[2] == 0 && octets[3] == 1);

        if (!benign) {
            count++;
        }

        i += pos;
    }

    return count;
}

/* ── Base64 blob detector ────────────────────────────────────────── */

static bool is_base64_char(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=';
}

/* Count base64 blobs longer than min_len characters. */
static int count_base64_blobs(const uint8_t* data, size_t data_len,
                               size_t min_len)
{
    int count = 0;
    size_t i = 0;

    while (i < data_len) {
        /* Find start of potential base64 run */
        if (!is_base64_char(data[i])) { i++; continue; }

        /* Count consecutive base64 characters */
        size_t run_start = i;
        while (i < data_len && is_base64_char(data[i]))
            i++;
        size_t run_len = i - run_start;

        if (run_len > min_len) {
            /* Validate: base64 should be a multiple of 4 (with padding),
             * must contain mixed case and/or digits to avoid plain text.
             * Simple heuristic: require at least some uppercase, lowercase,
             * and digits/special to distinguish from plain English. */
            int upper = 0, lower = 0, digit = 0, special = 0;
            for (size_t j = run_start; j < run_start + run_len && j < data_len; j++) {
                uint8_t c = data[j];
                if (c >= 'A' && c <= 'Z') upper++;
                else if (c >= 'a' && c <= 'z') lower++;
                else if (c >= '0' && c <= '9') digit++;
                else special++; /* +, /, = */
            }

            /* Require mixed character classes to reduce false positives.
             * Real base64 typically has all three classes plus padding. */
            int classes = (upper > 0 ? 1 : 0) + (lower > 0 ? 1 : 0) +
                          (digit > 0 ? 1 : 0) + (special > 0 ? 1 : 0);
            if (classes >= 3) {
                count++;
            }
        }
    }

    return count;
}

/* ── Main analysis ───────────────────────────────────────────────── */

void akav_string_analyze(const uint8_t* data, size_t data_len,
                          const akav_string_weights_t* weights,
                          akav_string_result_t* result)
{
    if (!data || data_len == 0 || !result) return;
    memset(result, 0, sizeof(*result));

    /* Use defaults if no weights provided */
    akav_string_weights_t def;
    if (!weights) {
        akav_string_weights_default(&def);
        weights = &def;
    }

    /* ── Check 1: cmd.exe ────────────────────────────────────────── */
    if (ci_memmem(data, data_len, "cmd.exe", 7)) {
        record_hit(result, "cmd_exe", weights->cmd_exe,
                   "Contains 'cmd.exe'");
    }

    /* ── Check 2: powershell.exe ─────────────────────────────────── */
    if (ci_memmem(data, data_len, "powershell.exe", 14)) {
        record_hit(result, "powershell_exe", weights->powershell_exe,
                   "Contains 'powershell.exe'");
    }

    /* ── Check 3: WScript.Shell ──────────────────────────────────── */
    if (ci_memmem(data, data_len, "WScript.Shell", 13)) {
        record_hit(result, "wscript_shell", weights->wscript_shell,
                   "Contains 'WScript.Shell'");
    }

    /* ── Check 4: CurrentVersion\Run ─────────────────────────────── */
    if (ci_memmem(data, data_len, "CurrentVersion\\Run", 18)) {
        record_hit(result, "currentversion_run", weights->currentversion_run,
                   "Contains 'CurrentVersion\\Run' (registry persistence)");
    }

    /* ── Check 5: HTTP/HTTPS URLs ────────────────────────────────── */
    {
        int http_count = ci_count_occurrences(data, data_len, "http://");
        int https_count = ci_count_occurrences(data, data_len, "https://");
        int total_urls = http_count + https_count;

        if (total_urls > 0) {
            /* Cap at a reasonable number to prevent score explosion */
            int capped = total_urls > 10 ? 10 : total_urls;
            int score = capped * weights->url_http;
            record_hit(result, "url_http", score,
                       "Contains %d URL(s) (%d http + %d https)",
                       total_urls, http_count, https_count);
        }
    }

    /* ── Check 6: IP address patterns ────────────────────────────── */
    {
        int ip_count = count_ip_addresses(data, data_len);

        if (ip_count > 0) {
            int capped = ip_count > 10 ? 10 : ip_count;
            int score = capped * weights->ip_address;
            record_hit(result, "ip_address", score,
                       "Contains %d IP address pattern(s)", ip_count);
        }
    }

    /* ── Check 7: Base64 blobs ───────────────────────────────────── */
    {
        int b64_count = count_base64_blobs(data, data_len, 100);

        if (b64_count > 0) {
            record_hit(result, "base64_blob", weights->base64_blob,
                       "Contains %d base64 blob(s) >100 chars", b64_count);
        }
    }
}
