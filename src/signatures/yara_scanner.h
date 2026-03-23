/* yara_scanner.h -- YARA rule matching integration (P9-T1).
 *
 * Wraps libyara to compile rules from source text (stored in .akavdb
 * YARA section) and scan buffers against them. Supports hot-reload:
 * destroy + re-init + load picks up new rules.
 */

#ifndef AKAV_YARA_SCANNER_H
#define AKAV_YARA_SCANNER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────── */

#define AKAV_YARA_MAX_RULES        4096   /* max rules per compilation unit */
#define AKAV_YARA_SCAN_TIMEOUT     30     /* seconds per scan */
#define AKAV_YARA_MAX_MATCH_NAME   256

/* ── Scanner state ─────────────────────────────────────────────── */

typedef struct {
    void*    rules;              /* YR_RULES* (opaque to avoid yara.h in header) */
    bool     loaded;
    uint32_t rule_count;
    char     compile_error[256]; /* last compilation error message */
} akav_yara_scanner_t;

/* ── Match result from a single scan ──────────────────────────── */

typedef struct {
    bool     matched;
    char     rule_name[AKAV_YARA_MAX_MATCH_NAME];  /* first matching rule */
    char     rule_ns[AKAV_YARA_MAX_MATCH_NAME];    /* namespace (or "default") */
    uint32_t match_count;                           /* total rules matched */
} akav_yara_match_t;

/* ── Public API ───────────────────────────────────────────────── */

/**
 * Initialize global YARA library. Call once at engine startup.
 * Returns true on success.
 */
bool akav_yara_global_init(void);

/**
 * Finalize global YARA library. Call once at engine shutdown.
 */
void akav_yara_global_cleanup(void);

/**
 * Initialize a YARA scanner to empty state.
 */
void akav_yara_scanner_init(akav_yara_scanner_t* scanner);

/**
 * Destroy a YARA scanner and release compiled rules.
 */
void akav_yara_scanner_destroy(akav_yara_scanner_t* scanner);

/**
 * Compile YARA rules from source text.
 *
 * source: null-terminated UTF-8 YARA rule source (may contain
 *         multiple rules). Multiple calls accumulate rules.
 *
 * Returns true if compilation succeeded with no errors.
 * On failure, scanner->compile_error describes the problem.
 */
bool akav_yara_load_source(akav_yara_scanner_t* scanner,
                            const char* source, size_t source_len);

/**
 * Load rules from a raw .akavdb YARA section blob.
 *
 * The section stores YARA rule source text as a UTF-8 blob.
 * This is a convenience wrapper around akav_yara_load_source.
 */
bool akav_yara_load_section(akav_yara_scanner_t* scanner,
                             const uint8_t* section_data,
                             size_t section_size);

/**
 * Scan a buffer against compiled YARA rules.
 *
 * Populates match with the first matching rule's details.
 * Returns true if at least one rule matched.
 */
bool akav_yara_scan_buffer(const akav_yara_scanner_t* scanner,
                            const uint8_t* data, size_t data_len,
                            akav_yara_match_t* match);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_YARA_SCANNER_H */
