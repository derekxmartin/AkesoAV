#ifndef AKESOAV_H
#define AKESOAV_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DLL export/import */
#ifdef AKAV_BUILD_DLL
  #define AKAV_API __declspec(dllexport)
#else
  #define AKAV_API __declspec(dllimport)
#endif

/* -- Opaque handles -- */
typedef struct akav_engine akav_engine_t;

/* -- Error codes -- */
typedef enum {
    AKAV_OK                = 0,
    AKAV_ERROR             = -1,   /* Generic error */
    AKAV_ERROR_INVALID     = -2,   /* Invalid parameter or malformed input */
    AKAV_ERROR_NOMEM       = -3,   /* Allocation failure */
    AKAV_ERROR_IO          = -4,   /* File I/O error */
    AKAV_ERROR_DB          = -5,   /* Signature database error (corrupt, bad sig, version) */
    AKAV_ERROR_TIMEOUT     = -6,   /* Per-file scan timeout exceeded */
    AKAV_ERROR_SIGNATURE   = -7,   /* RSA signature verification failed */
    AKAV_ERROR_NOT_INIT    = -8,   /* Engine not initialized */
    AKAV_ERROR_BOMB        = -9,   /* Decompression bomb detected */
    AKAV_ERROR_SCAN        = -10,  /* Scan-stage error (parser crash, partial failure) */
} akav_error_t;

/* -- Heuristic level -- */
typedef enum {
    AKAV_HEUR_OFF    = 0,
    AKAV_HEUR_LOW    = 1,   /* Score > 100 = suspicious */
    AKAV_HEUR_MEDIUM = 2,   /* Score > 75  = suspicious */
    AKAV_HEUR_HIGH   = 3,   /* Score > 50  = suspicious */
} akav_heur_level_t;

/* -- Scan options -- */
typedef struct {
    int              scan_archives;       /* Recurse into ZIP/GZIP/TAR/OLE2/OOXML     */
    int              scan_packed;         /* Attempt UPX / emulator-assisted unpacking  */
    int              use_heuristics;      /* Enable static + dynamic heuristic engine   */
    akav_heur_level_t heuristic_level;     /* Sensitivity threshold                      */
    int64_t          max_filesize;        /* Skip files larger than this (bytes, 0=no limit) */
    int              max_scan_depth;      /* Archive recursion depth limit (default 10) */
    int              timeout_ms;          /* Per-file scan timeout in ms (default 30000) */
    int              scan_memory;         /* Reserved for v2 memory scanning             */
    int              use_cache;           /* Check/update scan cache (default 1)         */
    int              use_whitelist;       /* Skip whitelisted files (default 1)          */
} akav_scan_options_t;

/* -- Scan result -- */
#define AKAV_MAX_MALWARE_NAME  256
#define AKAV_MAX_SIG_ID         64
#define AKAV_MAX_SCANNER_ID     64
#define AKAV_MAX_FILE_TYPE      32
#define AKAV_MAX_WARNINGS        8
#define AKAV_MAX_WARNING_LEN   128

typedef struct {
    int              found;                                /* 1 = malware detected          */
    char             malware_name[AKAV_MAX_MALWARE_NAME];   /* Detection name                */
    char             signature_id[AKAV_MAX_SIG_ID];         /* Matched signature identifier  */
    char             scanner_id[AKAV_MAX_SCANNER_ID];       /* Engine layer that matched     */
    char             file_type[AKAV_MAX_FILE_TYPE];         /* Detected format (PE32, ELF, etc) */
    double           heuristic_score;                      /* Combined heuristic score      */
    uint32_t         crc1;                                 /* Primary CRC (debug/analysis)  */
    uint32_t         crc2;                                 /* Secondary CRC                 */
    int              in_whitelist;                          /* 1 = file is whitelisted       */
    int64_t          total_size;                            /* File total size               */
    int64_t          scanned_size;                          /* Bytes actually analyzed        */
    int              cached;                                /* 1 = result served from cache  */
    int              scan_time_ms;                          /* Wall-clock scan time           */
    int              warning_count;                         /* Number of pipeline warnings   */
    char             warnings[AKAV_MAX_WARNINGS][AKAV_MAX_WARNING_LEN]; /* Stage error descriptions */
} akav_scan_result_t;

/* -- Engine lifecycle --
 * Thread safety: akav_engine_create/init/destroy are NOT thread-safe (call from one thread).
 * akav_scan_file, akav_scan_buffer, akav_scan_directory ARE thread-safe after init completes.
 * The signature database is mapped read-only and shared across threads.
 * Each scan call allocates its own Aho-Corasick walk state on the stack (no shared mutable state).
 * akav_engine_load_signatures acquires an internal write lock -- concurrent scans will block briefly
 * during reload, then resume with the new database.
 */
AKAV_API akav_error_t akav_engine_create(_Out_ akav_engine_t** engine);
AKAV_API akav_error_t akav_engine_init(_In_ akav_engine_t* engine, _In_opt_z_ const char* config_path);
AKAV_API akav_error_t akav_engine_load_signatures(_In_ akav_engine_t* engine, _In_z_ const char* db_path);
AKAV_API akav_error_t akav_engine_destroy(_In_ akav_engine_t* engine);

/* -- Scanning (thread-safe after init) -- */
AKAV_API akav_error_t akav_scan_file(_In_ akav_engine_t* engine, _In_z_ const char* path,
                                   _In_opt_ const akav_scan_options_t* opts,
                                   _Out_ akav_scan_result_t* result);
AKAV_API akav_error_t akav_scan_buffer(_In_ akav_engine_t* engine,
                                     _In_reads_bytes_(len) const uint8_t* buf, size_t len,
                                     _In_opt_z_ const char* name,
                                     _In_opt_ const akav_scan_options_t* opts,
                                     _Out_ akav_scan_result_t* result);

/* -- Directory scanning (callback, thread-safe) -- */
typedef void (*akav_scan_callback_t)(_In_z_ const char* path,
                                     _In_ const akav_scan_result_t* result,
                                     _In_opt_ void* user_data);
AKAV_API akav_error_t akav_scan_directory(_In_ akav_engine_t* engine, _In_z_ const char* path,
                                        _In_opt_ const akav_scan_options_t* opts,
                                        _In_ akav_scan_callback_t callback,
                                        _In_opt_ void* user_data);

/* -- Cache management -- */
AKAV_API akav_error_t akav_cache_clear(_In_ akav_engine_t* engine);
AKAV_API akav_error_t akav_cache_stats(_In_ akav_engine_t* engine,
                                     _Out_ uint64_t* hits, _Out_ uint64_t* misses,
                                     _Out_ uint64_t* entries);

/* -- Whitelist management -- */
AKAV_API akav_error_t akav_whitelist_add_hash(_In_ akav_engine_t* engine,
                                            _In_reads_bytes_(32) const uint8_t sha256[32]);
AKAV_API akav_error_t akav_whitelist_add_path(_In_ akav_engine_t* engine,
                                            _In_z_ const char* path_prefix);
AKAV_API akav_error_t akav_whitelist_add_signer(_In_ akav_engine_t* engine,
                                              _In_z_ const char* signer_name);
AKAV_API akav_error_t akav_whitelist_clear(_In_ akav_engine_t* engine);

/* -- Info -- */
AKAV_API const char* akav_engine_version(void);
AKAV_API const char* akav_db_version(_In_ akav_engine_t* engine);
AKAV_API const char* akav_strerror(akav_error_t err);

/* -- Update -- */
AKAV_API akav_error_t akav_update_signatures(_In_ akav_engine_t* engine,
                                           _In_z_ const char* update_url);

/* -- SIEM event shipping -- */
typedef struct {
    char event_id[64];             /* UUID v4 string                           */
    char timestamp[32];            /* ISO 8601 with ms: "2026-03-14T15:30:00.456Z" */
    char source_type[32];          /* Always "akeso_av"                     */
    char event_type[32];           /* av:scan_result, av:quarantine, etc.      */
    char agent_id[128];            /* Hostname                                 */
    char payload_json[8192];       /* JSON-serialized payload                  */
} akav_siem_event_t;

typedef void (*akav_siem_callback_t)(_In_ const akav_siem_event_t* event,
                                     _In_opt_ void* user_data);

AKAV_API akav_error_t akav_set_siem_callback(_In_ akav_engine_t* engine,
                                           _In_opt_ akav_siem_callback_t callback,
                                           _In_opt_ void* user_data);

AKAV_API akav_error_t akav_siem_start_http_shipper(_In_ akav_engine_t* engine,
                                                  _In_z_ const char* siem_url,
                                                  _In_z_ const char* api_key);
AKAV_API akav_error_t akav_siem_stop_http_shipper(_In_ akav_engine_t* engine);

/* Start local JSONL event logging. path may be NULL for default location. */
AKAV_API akav_error_t akav_siem_start_jsonl(_In_ akav_engine_t* engine,
                                           _In_opt_z_ const char* path);
AKAV_API akav_error_t akav_siem_stop_jsonl(_In_ akav_engine_t* engine);

/* -- Defaults -- */
AKAV_API void akav_scan_options_default(_Out_ akav_scan_options_t* opts);

#ifdef __cplusplus
}
#endif

#endif /* AKESOAV_H */
