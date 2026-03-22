#ifndef AKAV_ENGINE_INTERNAL_H
#define AKAV_ENGINE_INTERNAL_H

#include "akesoav.h"
#include "scanner.h"
#include "scan_cache.h"
#include "whitelist.h"
#include "siem/siem_shipper.h"
#include <stdbool.h>

#ifdef __cplusplus
#include <atomic>
#include <string>
#include <memory>

namespace akav
{

class Engine
{
public:
    Engine();
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    akav_error_t init(const char* config_path);
    akav_error_t load_signatures(const char* db_path);

    akav_error_t scan_file(const char* path, const akav_scan_options_t* opts,
                          akav_scan_result_t* result);
    akav_error_t scan_buffer(const uint8_t* buf, size_t len, const char* name,
                            const akav_scan_options_t* opts, akav_scan_result_t* result);
    akav_error_t scan_directory(const char* path, const akav_scan_options_t* opts,
                               akav_scan_callback_t callback, void* user_data);

    akav_error_t cache_clear();
    akav_error_t cache_stats(uint64_t* hits, uint64_t* misses, uint64_t* entries);

    akav_error_t whitelist_add_hash(const uint8_t sha256[32]);
    akav_error_t whitelist_add_path(const char* path_prefix);
    akav_error_t whitelist_add_signer(const char* signer_name);
    akav_error_t whitelist_clear();

    const char* db_version() const;

    akav_error_t set_siem_callback(akav_siem_callback_t callback, void* user_data);
    akav_error_t siem_start_http_shipper(const char* siem_url, const char* api_key);
    akav_error_t siem_stop_http_shipper();
    akav_error_t siem_start_jsonl(const char* path);
    akav_error_t siem_stop_jsonl();

    /* Access the SIEM shipper for JSONL init and direct event submission */
    SiemShipper* siem_shipper() { return siem_.get(); }

    bool is_initialized() const { return initialized_.load(std::memory_order_acquire); }

    /* Archive scanning (recursive) */
    akav_error_t scan_archive_zip(const uint8_t* buf, size_t len,
                                  const akav_scan_options_t* opts,
                                  akav_scan_result_t* result, int depth);
    akav_error_t scan_archive_gzip(const uint8_t* buf, size_t len,
                                   const akav_scan_options_t* opts,
                                   akav_scan_result_t* result, int depth);
    akav_error_t scan_archive_tar(const uint8_t* buf, size_t len,
                                  const akav_scan_options_t* opts,
                                  akav_scan_result_t* result, int depth);

private:
    std::atomic<bool> initialized_{false};
    std::string config_path_;
    std::string db_version_str_;
    akav_scanner_t scanner_{};
    bool scanner_loaded_{false};
    std::unique_ptr<ScanCache> cache_;
    std::unique_ptr<Whitelist> whitelist_;
    std::unique_ptr<SiemShipper> siem_;
};

} /* namespace akav */

extern "C" {
#endif /* __cplusplus */

/* C-visible opaque struct -- wraps the C++ Engine */
struct akav_engine
{
#ifdef __cplusplus
    akav::Engine impl;
#else
    char opaque[1]; /* placeholder for C compilation units */
#endif
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AKAV_ENGINE_INTERNAL_H */
