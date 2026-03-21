/* api.c — C API wrapper for the C++ Engine
 * This file compiles as C17. It delegates to the C++ Engine via the
 * opaque akav_engine_t handle defined in engine_internal.h.
 *
 * Because we compile as C, we cannot call C++ methods directly.
 * Instead, we forward-declare thin C-linkage shims implemented in engine_shims.cpp.
 */

#include "akesoav.h"
#include <stdlib.h>
#include <string.h>

/* ── Forward declarations of C-linkage shims (implemented in engine_shims.cpp) ── */
extern akav_error_t akav_shim_create(akav_engine_t** engine);
extern akav_error_t akav_shim_init(akav_engine_t* engine, const char* config_path);
extern akav_error_t akav_shim_load_signatures(akav_engine_t* engine, const char* db_path);
extern akav_error_t akav_shim_destroy(akav_engine_t* engine);
extern akav_error_t akav_shim_scan_file(akav_engine_t* engine, const char* path,
                                       const akav_scan_options_t* opts, akav_scan_result_t* result);
extern akav_error_t akav_shim_scan_buffer(akav_engine_t* engine, const uint8_t* buf, size_t len,
                                         const char* name, const akav_scan_options_t* opts,
                                         akav_scan_result_t* result);
extern akav_error_t akav_shim_scan_directory(akav_engine_t* engine, const char* path,
                                            const akav_scan_options_t* opts,
                                            akav_scan_callback_t callback, void* user_data);
extern akav_error_t akav_shim_cache_clear(akav_engine_t* engine);
extern akav_error_t akav_shim_cache_stats(akav_engine_t* engine, uint64_t* hits,
                                         uint64_t* misses, uint64_t* entries);
extern akav_error_t akav_shim_whitelist_add_hash(akav_engine_t* engine, const uint8_t sha256[32]);
extern akav_error_t akav_shim_whitelist_add_path(akav_engine_t* engine, const char* path_prefix);
extern akav_error_t akav_shim_whitelist_add_signer(akav_engine_t* engine, const char* signer_name);
extern akav_error_t akav_shim_whitelist_clear(akav_engine_t* engine);
extern const char* akav_shim_db_version(akav_engine_t* engine);
extern akav_error_t akav_shim_set_siem_callback(akav_engine_t* engine,
                                                akav_siem_callback_t callback, void* user_data);
extern akav_error_t akav_shim_siem_start_http_shipper(akav_engine_t* engine,
                                                      const char* siem_url, const char* api_key);
extern akav_error_t akav_shim_siem_stop_http_shipper(akav_engine_t* engine);
extern akav_error_t akav_shim_update_signatures(akav_engine_t* engine, const char* update_url);

/* ── Engine lifecycle ── */

AKAV_API akav_error_t akav_engine_create(_Out_ akav_engine_t** engine)
{
    if (!engine)
        return AKAV_ERROR_INVALID;
    return akav_shim_create(engine);
}

AKAV_API akav_error_t akav_engine_init(_In_ akav_engine_t* engine, _In_opt_z_ const char* config_path)
{
    if (!engine)
        return AKAV_ERROR_INVALID;
    return akav_shim_init(engine, config_path);
}

AKAV_API akav_error_t akav_engine_load_signatures(_In_ akav_engine_t* engine, _In_z_ const char* db_path)
{
    if (!engine || !db_path)
        return AKAV_ERROR_INVALID;
    return akav_shim_load_signatures(engine, db_path);
}

AKAV_API akav_error_t akav_engine_destroy(_In_ akav_engine_t* engine)
{
    if (!engine)
        return AKAV_ERROR_INVALID;
    return akav_shim_destroy(engine);
}

/* ── Scanning ── */

AKAV_API akav_error_t akav_scan_file(_In_ akav_engine_t* engine, _In_z_ const char* path,
                                   _In_opt_ const akav_scan_options_t* opts, _Out_ akav_scan_result_t* result)
{
    if (!engine || !path || !result)
        return AKAV_ERROR_INVALID;
    return akav_shim_scan_file(engine, path, opts, result);
}

AKAV_API akav_error_t akav_scan_buffer(_In_ akav_engine_t* engine,
                                     _In_reads_bytes_(len) const uint8_t* buf, size_t len,
                                     _In_opt_z_ const char* name, _In_opt_ const akav_scan_options_t* opts,
                                     _Out_ akav_scan_result_t* result)
{
    if (!engine || !result)
        return AKAV_ERROR_INVALID;
    if (!buf && len > 0)
        return AKAV_ERROR_INVALID;
    return akav_shim_scan_buffer(engine, buf, len, name, opts, result);
}

AKAV_API akav_error_t akav_scan_directory(_In_ akav_engine_t* engine, _In_z_ const char* path,
                                        _In_opt_ const akav_scan_options_t* opts,
                                        _In_ akav_scan_callback_t callback, _In_opt_ void* user_data)
{
    if (!engine || !path || !callback)
        return AKAV_ERROR_INVALID;
    return akav_shim_scan_directory(engine, path, opts, callback, user_data);
}

/* ── Cache management ── */

AKAV_API akav_error_t akav_cache_clear(_In_ akav_engine_t* engine)
{
    if (!engine)
        return AKAV_ERROR_INVALID;
    return akav_shim_cache_clear(engine);
}

AKAV_API akav_error_t akav_cache_stats(_In_ akav_engine_t* engine,
                                     _Out_ uint64_t* hits, _Out_ uint64_t* misses,
                                     _Out_ uint64_t* entries)
{
    if (!engine || !hits || !misses || !entries)
        return AKAV_ERROR_INVALID;
    return akav_shim_cache_stats(engine, hits, misses, entries);
}

/* ── Whitelist management ── */

AKAV_API akav_error_t akav_whitelist_add_hash(_In_ akav_engine_t* engine,
                                            _In_reads_bytes_(32) const uint8_t sha256[32])
{
    if (!engine || !sha256)
        return AKAV_ERROR_INVALID;
    return akav_shim_whitelist_add_hash(engine, sha256);
}

AKAV_API akav_error_t akav_whitelist_add_path(_In_ akav_engine_t* engine,
                                            _In_z_ const char* path_prefix)
{
    if (!engine || !path_prefix)
        return AKAV_ERROR_INVALID;
    return akav_shim_whitelist_add_path(engine, path_prefix);
}

AKAV_API akav_error_t akav_whitelist_add_signer(_In_ akav_engine_t* engine,
                                              _In_z_ const char* signer_name)
{
    if (!engine || !signer_name)
        return AKAV_ERROR_INVALID;
    return akav_shim_whitelist_add_signer(engine, signer_name);
}

AKAV_API akav_error_t akav_whitelist_clear(_In_ akav_engine_t* engine)
{
    if (!engine)
        return AKAV_ERROR_INVALID;
    return akav_shim_whitelist_clear(engine);
}

/* ── Info ── */

static const char AKAV_VERSION[] = "0.1.0";

AKAV_API const char* akav_engine_version(void)
{
    return AKAV_VERSION;
}

AKAV_API const char* akav_db_version(_In_ akav_engine_t* engine)
{
    if (!engine)
        return "unknown";
    return akav_shim_db_version(engine);
}

AKAV_API const char* akav_strerror(akav_error_t err)
{
    switch (err)
    {
    case AKAV_OK:              return "Success";
    case AKAV_ERROR:           return "Generic error";
    case AKAV_ERROR_INVALID:   return "Invalid parameter";
    case AKAV_ERROR_NOMEM:     return "Memory allocation failed";
    case AKAV_ERROR_IO:        return "I/O error";
    case AKAV_ERROR_DB:        return "Signature database error";
    case AKAV_ERROR_TIMEOUT:   return "Scan timeout exceeded";
    case AKAV_ERROR_SIGNATURE: return "RSA signature verification failed";
    case AKAV_ERROR_NOT_INIT:  return "Engine not initialized";
    case AKAV_ERROR_BOMB:      return "Decompression bomb detected";
    case AKAV_ERROR_SCAN:      return "Scan stage error";
    default:                   return "Unknown error";
    }
}

/* ── Update ── */

AKAV_API akav_error_t akav_update_signatures(_In_ akav_engine_t* engine,
                                           _In_z_ const char* update_url)
{
    if (!engine || !update_url)
        return AKAV_ERROR_INVALID;
    return akav_shim_update_signatures(engine, update_url);
}

/* ── SIEM ── */

AKAV_API akav_error_t akav_set_siem_callback(_In_ akav_engine_t* engine,
                                           _In_opt_ akav_siem_callback_t callback, _In_opt_ void* user_data)
{
    if (!engine)
        return AKAV_ERROR_INVALID;
    return akav_shim_set_siem_callback(engine, callback, user_data);
}

AKAV_API akav_error_t akav_siem_start_http_shipper(_In_ akav_engine_t* engine,
                                                  _In_z_ const char* siem_url, _In_z_ const char* api_key)
{
    if (!engine || !siem_url || !api_key)
        return AKAV_ERROR_INVALID;
    return akav_shim_siem_start_http_shipper(engine, siem_url, api_key);
}

AKAV_API akav_error_t akav_siem_stop_http_shipper(_In_ akav_engine_t* engine)
{
    if (!engine)
        return AKAV_ERROR_INVALID;
    return akav_shim_siem_stop_http_shipper(engine);
}

/* ── Defaults ── */

AKAV_API void akav_scan_options_default(_Out_ akav_scan_options_t* opts)
{
    if (!opts)
        return;
    memset(opts, 0, sizeof(*opts));
    opts->scan_archives = 1;
    opts->scan_packed = 1;
    opts->use_heuristics = 1;
    opts->heuristic_level = AKAV_HEUR_MEDIUM;
    opts->max_filesize = 0;         /* No limit */
    opts->max_scan_depth = 10;
    opts->timeout_ms = 30000;       /* 30 seconds */
    opts->scan_memory = 0;
    opts->use_cache = 1;
    opts->use_whitelist = 1;
}
