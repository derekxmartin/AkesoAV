#ifndef AKAV_SELF_PROTECT_H
#define AKAV_SELF_PROTECT_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── DACL Hardening ─────────────────────────────────────────────── */

/**
 * Harden the current process DACL by denying PROCESS_TERMINATE
 * from non-admin callers. Also denies PROCESS_VM_WRITE and
 * PROCESS_VM_OPERATION to prevent memory tampering.
 * Must be called early in service startup.
 * Returns true on success.
 */
bool akav_self_protect_harden_process(void);

/* ── Authenticode Verification ──────────────────────────────────── */

/** Result of an Authenticode verification */
typedef enum {
    AKAV_VERIFY_OK           = 0,  /* Valid Authenticode signature */
    AKAV_VERIFY_NO_SIGNATURE = 1,  /* File not signed */
    AKAV_VERIFY_INVALID      = 2,  /* Signature invalid or tampered */
    AKAV_VERIFY_UNTRUSTED    = 3,  /* Signed but signer not trusted */
    AKAV_VERIFY_ERROR        = 4   /* WinVerifyTrust call failed */
} akav_verify_result_t;

/**
 * Verify Authenticode signature on a file using WinVerifyTrust.
 * Returns AKAV_VERIFY_OK if the file has a valid, trusted signature.
 */
akav_verify_result_t akav_self_protect_verify_authenticode(const char* file_path);

/**
 * Verify a DLL or plugin before loading. Checks Authenticode signature.
 * In production mode (require_signed=true), unsigned/invalid files are rejected.
 * In dev mode (require_signed=false), unsigned files are allowed with a warning.
 * Returns true if the file is safe to load.
 */
bool akav_self_protect_verify_dll(const char* dll_path, bool require_signed);

/* ── File Integrity Monitoring ──────────────────────────────────── */

#define AKAV_SELF_PROTECT_MAX_FILES  64
#define AKAV_SELF_PROTECT_HASH_LEN   32  /* SHA-256 */

/** A monitored file entry */
typedef struct {
    char     path[520];                         /* File path */
    uint8_t  baseline_hash[AKAV_SELF_PROTECT_HASH_LEN]; /* SHA-256 at startup */
    bool     valid;                             /* Entry in use */
} akav_monitored_file_t;

/** File integrity monitor state */
typedef struct {
    akav_monitored_file_t files[AKAV_SELF_PROTECT_MAX_FILES];
    int                   file_count;
    uint32_t              check_interval_sec;   /* Default 60 */
    bool                  initialized;
} akav_integrity_monitor_t;

/**
 * Initialize the file integrity monitor.
 * check_interval_sec: how often to re-check (default 60).
 */
void akav_integrity_monitor_init(akav_integrity_monitor_t* mon,
                                  uint32_t check_interval_sec);

/**
 * Add a file to the monitor. Computes its SHA-256 baseline hash.
 * Returns true on success, false if file can't be read or monitor is full.
 */
bool akav_integrity_monitor_add(akav_integrity_monitor_t* mon,
                                 const char* file_path);

/**
 * Add all engine files from a directory (*.dll, *.exe).
 * Returns the number of files added.
 */
int akav_integrity_monitor_add_dir(akav_integrity_monitor_t* mon,
                                    const char* dir_path);

/** Result of an integrity check */
typedef struct {
    int  files_checked;
    int  files_ok;
    int  files_modified;    /* Hash mismatch */
    int  files_missing;     /* File deleted */
    int  files_error;       /* Could not read */
    char modified_paths[4][520]; /* Up to 4 modified file paths */
} akav_integrity_result_t;

/**
 * Check all monitored files against their baseline hashes.
 * Returns the result summary.
 */
akav_integrity_result_t akav_integrity_monitor_check(
    const akav_integrity_monitor_t* mon);

/**
 * Free resources held by the monitor.
 */
void akav_integrity_monitor_destroy(akav_integrity_monitor_t* mon);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_SELF_PROTECT_H */
