/* dynamic_scorer.cpp -- Dynamic heuristic scorer from emulator API call log (P9-T5).
 *
 * Scores API call sequences per §5.7 behavior scoring table.
 */

#include "heuristics/dynamic_scorer.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── Suspicious DLL names for LoadLibrary checks ─────────────────── */

static const char* SUSPICIOUS_DLLS[] = {
    "ws2_32", "wininet", "urlmon", "shell32", "advapi32",
    "ntdll", "amsi", "wldp", "dbghelp", "psapi",
    NULL
};

/* ── Helpers ──────────────────────────────────────────────────────── */

static bool name_match(const char* func_name, const char* target)
{
    /* Case-insensitive prefix match (handles A/W suffix variants) */
    size_t tlen = strlen(target);
    if (_strnicmp(func_name, target, tlen) != 0) return false;
    char suffix = func_name[tlen];
    return suffix == '\0' || suffix == 'A' || suffix == 'W';
}

static void add_hit(akav_dynamic_result_t* result, const char* name,
                      int weight, const char* detail)
{
    if (result->num_hits >= AKAV_HEUR_MAX_HITS) return;
    akav_heur_hit_t* hit = &result->hits[result->num_hits++];
    hit->check_name = name;
    hit->weight = weight;
    strncpy_s(hit->detail, sizeof(hit->detail), detail, _TRUNCATE);
    result->total_score += weight;
}

/* PAGE_EXECUTE_READWRITE = 0x40 */
#define PAGE_EXECUTE_READWRITE 0x40u

/* ── Default weights ─────────────────────────────────────────────── */

void akav_dynamic_weights_default(akav_dynamic_weights_t* w)
{
    if (!w) return;
    w->get_module_handle_self   = -5;
    w->get_system_info          = -3;
    w->virtual_alloc_any        = 5;
    w->virtual_alloc_rwx        = 15;
    w->virtual_protect_rw_rx    = 15;
    w->alloc_write_protect_chain = 30;
    w->alloc_rwx_write_jump     = 35;
    w->load_library_suspicious  = 10;
    w->get_proc_address_loop    = 20;
    w->write_then_execute       = 25;
    w->int3_or_invalid          = 5;
    w->long_computation         = -10;
}

/* ── JSON weight loading ─────────────────────────────────────────── */

static bool read_file(const char* path, char* buf, size_t buf_size)
{
    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || (size_t)sz >= buf_size) { fclose(f); return false; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);
    return true;
}

static bool json_find_int(const char* json, const char* key, int* out)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* p = strstr(json, search);
    if (!p) return false;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (!*p) return false;
    *out = atoi(p);
    return true;
}

bool akav_dynamic_weights_load_json(akav_dynamic_weights_t* w,
                                      const char* json_path)
{
    if (!w || !json_path) return false;

    akav_dynamic_weights_default(w);

    char buf[4096];
    if (!read_file(json_path, buf, sizeof(buf))) return false;

    json_find_int(buf, "get_module_handle_self", &w->get_module_handle_self);
    json_find_int(buf, "get_system_info", &w->get_system_info);
    json_find_int(buf, "virtual_alloc_any", &w->virtual_alloc_any);
    json_find_int(buf, "virtual_alloc_rwx", &w->virtual_alloc_rwx);
    json_find_int(buf, "virtual_protect_rw_rx", &w->virtual_protect_rw_rx);
    json_find_int(buf, "alloc_write_protect_chain", &w->alloc_write_protect_chain);
    json_find_int(buf, "alloc_rwx_write_jump", &w->alloc_rwx_write_jump);
    json_find_int(buf, "load_library_suspicious", &w->load_library_suspicious);
    json_find_int(buf, "get_proc_address_loop", &w->get_proc_address_loop);
    json_find_int(buf, "write_then_execute", &w->write_then_execute);
    json_find_int(buf, "int3_or_invalid", &w->int3_or_invalid);
    json_find_int(buf, "long_computation", &w->long_computation);

    return true;
}

/* ── Core scoring ────────────────────────────────────────────────── */

void akav_dynamic_score(const akav_dynamic_context_t* ctx,
                          const akav_dynamic_weights_t* weights,
                          akav_dynamic_result_t* result)
{
    if (!ctx || !result) return;
    memset(result, 0, sizeof(*result));

    if (!ctx->log || ctx->log_count == 0) return;

    akav_dynamic_weights_t w;
    if (weights) {
        w = *weights;
    } else {
        akav_dynamic_weights_default(&w);
    }

    result->api_calls_analyzed = ctx->log_count;

    /* ── Track state for multi-call pattern detection ──────────── */

    bool seen_virtual_alloc = false;
    bool seen_virtual_alloc_rwx = false;
    uint32_t alloc_return_addr = 0;      /* address returned by VirtualAlloc */
    bool seen_write_to_alloc = false;    /* write to allocated region (heuristic) */
    bool seen_virtual_protect_rx = false;
    bool seen_jump_to_alloc = false;

    uint32_t get_proc_count = 0;
    bool gpa_loop_scored = false;

    /* ── Pass 1: Score individual calls ───────────────────────── */

    for (uint32_t i = 0; i < ctx->log_count; i++) {
        const akav_api_call_t* call = &ctx->log[i];

        /* GetModuleHandle (self) */
        if (name_match(call->func_name, "GetModuleHandle")) {
            add_hit(result, "get_module_handle_self",
                    w.get_module_handle_self, "GetModuleHandle (self)");
            continue;
        }

        /* GetSystemInfo */
        if (name_match(call->func_name, "GetSystemInfo")) {
            add_hit(result, "get_system_info",
                    w.get_system_info, "GetSystemInfo");
            continue;
        }

        /* VirtualAlloc */
        if (name_match(call->func_name, "VirtualAlloc")) {
            seen_virtual_alloc = true;
            alloc_return_addr = call->return_value;

            /* Check flProtect (param[3]) for PAGE_EXECUTE_READWRITE */
            if (call->params[3] == PAGE_EXECUTE_READWRITE) {
                seen_virtual_alloc_rwx = true;
                add_hit(result, "virtual_alloc_rwx",
                        w.virtual_alloc_rwx,
                        "VirtualAlloc with PAGE_EXECUTE_READWRITE");
            } else {
                add_hit(result, "virtual_alloc_any",
                        w.virtual_alloc_any, "VirtualAlloc");
            }
            continue;
        }

        /* VirtualProtect */
        if (name_match(call->func_name, "VirtualProtect")) {
            /* Check if flNewProtect (param[2]) indicates RX transition */
            uint32_t new_prot = call->params[2];
            if (new_prot == 0x20 || new_prot == 0x40) {
                /* PAGE_EXECUTE_READ (0x20) or PAGE_EXECUTE_READWRITE (0x40) */
                seen_virtual_protect_rx = true;
                add_hit(result, "virtual_protect_rw_rx",
                        w.virtual_protect_rw_rx,
                        "VirtualProtect RW->RX transition");
            }
            continue;
        }

        /* LoadLibrary — check for suspicious DLLs */
        if (name_match(call->func_name, "LoadLibrary") ||
            name_match(call->func_name, "LoadLibraryEx")) {
            /* params[0] is the DLL name pointer — we check the DLL name
             * stored in the log entry's dll_name or use heuristic */
            for (int s = 0; SUSPICIOUS_DLLS[s]; s++) {
                if (_strnicmp(call->dll_name, SUSPICIOUS_DLLS[s],
                              strlen(SUSPICIOUS_DLLS[s])) == 0) {
                    add_hit(result, "load_library_suspicious",
                            w.load_library_suspicious,
                            "LoadLibrary on suspicious DLL");
                    break;
                }
            }
            continue;
        }

        /* GetProcAddress — count for tight loop detection */
        if (name_match(call->func_name, "GetProcAddress")) {
            get_proc_count++;
            if (get_proc_count > 10 && !gpa_loop_scored) {
                gpa_loop_scored = true;
                add_hit(result, "get_proc_address_loop",
                        w.get_proc_address_loop,
                        "GetProcAddress tight loop (>10 calls)");
            }
            continue;
        }

        /* WriteProcessMemory — indicates writing to allocated region */
        if (name_match(call->func_name, "WriteProcessMemory")) {
            seen_write_to_alloc = true;
            continue;
        }

        /* CreateRemoteThread / CreateThread — may indicate jump to allocated */
        if (name_match(call->func_name, "CreateRemoteThread") ||
            name_match(call->func_name, "CreateThread")) {
            seen_jump_to_alloc = true;
            continue;
        }
    }

    /* ── Pass 2: Score multi-call patterns (chains) ───────────── */

    /* VirtualAlloc + memcpy-like write + VirtualProtect(RX) = injection chain */
    if (seen_virtual_alloc && seen_write_to_alloc && seen_virtual_protect_rx) {
        add_hit(result, "alloc_write_protect_chain",
                w.alloc_write_protect_chain,
                "VirtualAlloc + write + VirtualProtect(RX) chain");
    }

    /* VirtualAlloc(RWX) + write + jump-to-allocated = classic shellcode */
    if (seen_virtual_alloc_rwx && seen_write_to_alloc && seen_jump_to_alloc) {
        add_hit(result, "alloc_rwx_write_jump",
                w.alloc_rwx_write_jump,
                "VirtualAlloc(RWX) + write + jump to allocated");
    }

    /* Write then execute: final EIP in allocated region */
    if (seen_virtual_alloc && alloc_return_addr != 0 && ctx->eip_final != 0) {
        /* Check if EIP ended up in a region that was allocated */
        uint32_t alloc_base = alloc_return_addr;
        /* Heuristic: if final EIP is near allocated address */
        if (ctx->eip_final >= alloc_base &&
            ctx->eip_final < alloc_base + 0x100000) {
            add_hit(result, "write_then_execute",
                    w.write_then_execute,
                    "EIP transferred to allocated region");
        }
    }

    /* >1M instructions without API call = likely legitimate computation */
    if (ctx->insn_count > 1000000 && ctx->log_count == 0) {
        add_hit(result, "long_computation",
                w.long_computation,
                ">1M instructions without API call");
    }
}
