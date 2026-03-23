/* engine_shims.cpp — C-linkage shim functions that api.c calls.
 * These are compiled as C++ and can directly invoke Engine methods. */

#include "engine_internal.h"
#include "update/update_client.h"
#include <new>

extern "C"
{

akav_error_t akav_shim_create(akav_engine_t** engine)
{
    /* Allocate the opaque handle which contains the C++ Engine */
    akav_engine_t* e = new (std::nothrow) akav_engine_t;
    if (!e)
        return AKAV_ERROR_NOMEM;
    *engine = e;
    return AKAV_OK;
}

akav_error_t akav_shim_init(akav_engine_t* engine, const char* config_path)
{
    return engine->impl.init(config_path);
}

akav_error_t akav_shim_load_signatures(akav_engine_t* engine, const char* db_path)
{
    return engine->impl.load_signatures(db_path);
}

akav_error_t akav_shim_destroy(akav_engine_t* engine)
{
    delete engine;
    return AKAV_OK;
}

akav_error_t akav_shim_scan_file(akav_engine_t* engine, const char* path,
                                const akav_scan_options_t* opts, akav_scan_result_t* result)
{
    return engine->impl.scan_file(path, opts, result);
}

akav_error_t akav_shim_scan_buffer(akav_engine_t* engine, const uint8_t* buf, size_t len,
                                  const char* name, const akav_scan_options_t* opts,
                                  akav_scan_result_t* result)
{
    return engine->impl.scan_buffer(buf, len, name, opts, result);
}

akav_error_t akav_shim_scan_directory(akav_engine_t* engine, const char* path,
                                     const akav_scan_options_t* opts,
                                     akav_scan_callback_t callback, void* user_data)
{
    return engine->impl.scan_directory(path, opts, callback, user_data);
}

akav_error_t akav_shim_cache_clear(akav_engine_t* engine)
{
    return engine->impl.cache_clear();
}

akav_error_t akav_shim_cache_stats(akav_engine_t* engine, uint64_t* hits,
                                  uint64_t* misses, uint64_t* entries)
{
    return engine->impl.cache_stats(hits, misses, entries);
}

akav_error_t akav_shim_whitelist_add_hash(akav_engine_t* engine, const uint8_t sha256[32])
{
    return engine->impl.whitelist_add_hash(sha256);
}

akav_error_t akav_shim_whitelist_add_path(akav_engine_t* engine, const char* path_prefix)
{
    return engine->impl.whitelist_add_path(path_prefix);
}

akav_error_t akav_shim_whitelist_add_signer(akav_engine_t* engine, const char* signer_name)
{
    return engine->impl.whitelist_add_signer(signer_name);
}

akav_error_t akav_shim_whitelist_clear(akav_engine_t* engine)
{
    return engine->impl.whitelist_clear();
}

const char* akav_shim_db_version(akav_engine_t* engine)
{
    return engine->impl.db_version();
}

akav_error_t akav_shim_set_siem_callback(akav_engine_t* engine,
                                        akav_siem_callback_t callback, void* user_data)
{
    return engine->impl.set_siem_callback(callback, user_data);
}

akav_error_t akav_shim_siem_start_http_shipper(akav_engine_t* engine,
                                               const char* siem_url, const char* api_key)
{
    return engine->impl.siem_start_http_shipper(siem_url, api_key);
}

akav_error_t akav_shim_siem_stop_http_shipper(akav_engine_t* engine)
{
    return engine->impl.siem_stop_http_shipper();
}

akav_error_t akav_shim_siem_start_jsonl(akav_engine_t* engine, const char* path)
{
    return engine->impl.siem_start_jsonl(path);
}

akav_error_t akav_shim_siem_stop_jsonl(akav_engine_t* engine)
{
    return engine->impl.siem_stop_jsonl();
}

akav_error_t akav_shim_load_plugins(akav_engine_t* engine, const char* plugin_dir)
{
    return engine->impl.load_plugins(plugin_dir);
}

akav_error_t akav_shim_update_signatures(akav_engine_t* engine, const char* update_url)
{
    if (!engine || !update_url)
        return AKAV_ERROR;

    /* Build update config from engine state */
    akav_update_config_t config;
    memset(&config, 0, sizeof(config));
    config.update_url = update_url;
    /* Use the engine's current DB path (stored during load_signatures).
     * For now we use a default path — the service sets the real path. */
    config.db_path = nullptr;  /* caller must ensure DB path is set */
    config.current_version = 0;
    config.pinned_cert_sha256 = nullptr;  /* production: set from compiled-in fingerprint */
    config.rsa_public_key = AKAV_UPDATE_RSA_PUBKEY;
    config.rsa_public_key_len = AKAV_UPDATE_RSA_PUBKEY_LEN;

    akav_update_result_t result;
    if (!akav_update_check(&config, &result))
        return AKAV_ERROR;

    /* If updated, reload signatures */
    if (result.updated && config.db_path) {
        return engine->impl.load_signatures(config.db_path);
    }

    return AKAV_OK;
}

} /* extern "C" */
