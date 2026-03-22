/* imports.cpp -- Import heuristic analyzer.
 *
 * Implements checks from section 5.6 Imports row:
 *   - VirtualAlloc+WriteProcessMemory+CreateRemoteThread  (+35)  injection combo
 *   - VirtualAlloc+VirtualProtect(RX)+CreateThread        (+25)  shellcode loader
 *   - CreateService+StartService                          (+20)  service installer
 *   - RegSetValueEx (Run key indicator)                   (+15)  persistence
 *   - All imports by ordinal                              (+15)  ordinal-only
 *   - Only GetProcAddress+LoadLibrary                     (+25)  API hashing
 *
 * Weights are JSON-configurable; defaults match REQUIREMENTS.md.
 */

#include "heuristics/imports.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

/* ── Case-insensitive comparison helpers ────────────────────────── */

static int ci_strcmp(const char* a, const char* b)
{
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/* ── Defaults ────────────────────────────────────────────────────── */

void akav_import_weights_default(akav_import_weights_t* w)
{
    if (!w) return;
    w->injection_combo      = 35;
    w->shellcode_loader     = 25;
    w->service_installer    = 20;
    w->persistence_registry = 15;
    w->ordinal_only         = 15;
    w->api_hashing          = 25;
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

bool akav_import_weights_load_json(akav_import_weights_t* w,
                                    const char* json_path)
{
    if (!w || !json_path) return false;

    akav_import_weights_default(w);

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
        { "injection_combo",      &w->injection_combo },
        { "shellcode_loader",     &w->shellcode_loader },
        { "service_installer",    &w->service_installer },
        { "persistence_registry", &w->persistence_registry },
        { "ordinal_only",         &w->ordinal_only },
        { "api_hashing",          &w->api_hashing },
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

static void record_hit(akav_import_result_t* r, const char* name,
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

/* ── Import scanning helpers ─────────────────────────────────────── */

/* Check if PE imports a specific function name (case-insensitive).
 * Checks both A and W variants automatically. */
static bool has_import(const akav_pe_t* pe, const char* func_name)
{
    for (uint32_t i = 0; i < pe->num_import_funcs; i++) {
        const akav_pe_import_func_t* fn = &pe->import_funcs[i];
        if (fn->is_ordinal) continue;

        /* Exact match */
        if (ci_strcmp(fn->name, func_name) == 0)
            return true;

        /* Check with A/W suffix: build "FuncNameA" and "FuncNameW" */
        size_t flen = strlen(func_name);
        size_t nlen = strlen(fn->name);
        if (nlen == flen + 1 && (fn->name[flen] == 'A' || fn->name[flen] == 'W')) {
            /* Compare the prefix */
            bool prefix_match = true;
            for (size_t c = 0; c < flen; c++) {
                if (tolower((unsigned char)fn->name[c]) != tolower((unsigned char)func_name[c])) {
                    prefix_match = false;
                    break;
                }
            }
            if (prefix_match) return true;
        }
    }
    return false;
}

/* ── Main analysis ───────────────────────────────────────────────── */

void akav_import_analyze(const akav_pe_t* pe,
                          const akav_import_weights_t* weights,
                          akav_import_result_t* result)
{
    if (!pe || !pe->valid || !result) return;
    memset(result, 0, sizeof(*result));

    /* Use defaults if no weights provided */
    akav_import_weights_t def;
    if (!weights) {
        akav_import_weights_default(&def);
        weights = &def;
    }

    /* No imports at all → skip all checks (zero_imports handled by PE header analyzer) */
    if (pe->num_import_dlls == 0 && pe->num_import_funcs == 0)
        return;

    /* ── Check 1: Injection combo ────────────────────────────────── */
    /* VirtualAlloc + WriteProcessMemory + CreateRemoteThread       */
    {
        bool va   = has_import(pe, "VirtualAlloc") || has_import(pe, "VirtualAllocEx");
        bool wpm  = has_import(pe, "WriteProcessMemory");
        bool crt  = has_import(pe, "CreateRemoteThread") ||
                    has_import(pe, "CreateRemoteThreadEx");

        if (va && wpm && crt) {
            record_hit(result, "injection_combo", weights->injection_combo,
                       "Imports VirtualAlloc+WriteProcessMemory+CreateRemoteThread");
        }
    }

    /* ── Check 2: Shellcode loader ───────────────────────────────── */
    /* VirtualAlloc + VirtualProtect(RX) + CreateThread             */
    {
        bool va  = has_import(pe, "VirtualAlloc") || has_import(pe, "VirtualAllocEx");
        bool vp  = has_import(pe, "VirtualProtect") || has_import(pe, "VirtualProtectEx");
        bool ct  = has_import(pe, "CreateThread");

        if (va && vp && ct) {
            record_hit(result, "shellcode_loader", weights->shellcode_loader,
                       "Imports VirtualAlloc+VirtualProtect+CreateThread");
        }
    }

    /* ── Check 3: Service installer ──────────────────────────────── */
    /* CreateService + StartService                                  */
    {
        bool cs = has_import(pe, "CreateService");
        bool ss = has_import(pe, "StartService");

        if (cs && ss) {
            record_hit(result, "service_installer", weights->service_installer,
                       "Imports CreateService+StartService");
        }
    }

    /* ── Check 4: Persistence via registry ───────────────────────── */
    /* RegSetValueEx (Run key indicator)                              */
    {
        bool rsv = has_import(pe, "RegSetValueEx");

        if (rsv) {
            record_hit(result, "persistence_registry", weights->persistence_registry,
                       "Imports RegSetValueEx (registry persistence indicator)");
        }
    }

    /* ── Check 5: Ordinal-only imports ───────────────────────────── */
    /* All imports resolved by ordinal (no function names)           */
    {
        if (pe->num_import_funcs > 0 &&
            pe->ordinal_only_count == pe->num_import_funcs) {
            record_hit(result, "ordinal_only", weights->ordinal_only,
                       "All %u imports are by ordinal (no named imports)",
                       pe->num_import_funcs);
        }
    }

    /* ── Check 6: API hashing indicator ──────────────────────────── */
    /* Only GetProcAddress + LoadLibrary (and variants)              */
    {
        bool gpa = has_import(pe, "GetProcAddress");
        bool ll  = has_import(pe, "LoadLibrary") || has_import(pe, "LoadLibraryEx");

        if (gpa && ll) {
            /* Count total unique named imports (non-ordinal) */
            uint32_t named_count = 0;
            for (uint32_t i = 0; i < pe->num_import_funcs; i++) {
                if (!pe->import_funcs[i].is_ordinal)
                    named_count++;
            }

            /* "Only" means these are the only named functions imported.
             * Allow GetProcAddress + LoadLibraryA/W + LoadLibraryExA/W variants.
             * If total named imports <= 4 (GPA + LL + LLEx + possibly GetModuleHandle),
             * that's suspicious. */
            bool only_resolver = true;
            for (uint32_t i = 0; i < pe->num_import_funcs; i++) {
                const akav_pe_import_func_t* fn = &pe->import_funcs[i];
                if (fn->is_ordinal) continue;

                const char* n = fn->name;
                if (ci_strcmp(n, "GetProcAddress") == 0) continue;
                if (ci_strcmp(n, "LoadLibraryA") == 0) continue;
                if (ci_strcmp(n, "LoadLibraryW") == 0) continue;
                if (ci_strcmp(n, "LoadLibraryExA") == 0) continue;
                if (ci_strcmp(n, "LoadLibraryExW") == 0) continue;
                if (ci_strcmp(n, "GetModuleHandleA") == 0) continue;
                if (ci_strcmp(n, "GetModuleHandleW") == 0) continue;
                if (ci_strcmp(n, "FreeLibrary") == 0) continue;

                /* Found a non-resolver import */
                only_resolver = false;
                break;
            }

            if (only_resolver && named_count > 0) {
                record_hit(result, "api_hashing", weights->api_hashing,
                           "Only resolver imports (GetProcAddress+LoadLibrary) - "
                           "API hashing indicator (%u named imports)", named_count);
            }
        }
    }
}
