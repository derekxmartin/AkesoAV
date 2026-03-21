#ifndef AKAV_ZIP_H
#define AKAV_ZIP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── ZIP format constants ────────────────────────────────────────── */

#define AKAV_ZIP_LOCAL_FILE_SIG    0x04034B50  /* PK\x03\x04 */
#define AKAV_ZIP_CENTRAL_DIR_SIG   0x02014B50  /* PK\x01\x02 */
#define AKAV_ZIP_END_CENTRAL_SIG   0x06054B50  /* PK\x05\x06 */

#define AKAV_ZIP_METHOD_STORED     0
#define AKAV_ZIP_METHOD_DEFLATE    8

/* ── Anti-DoS limits (§5.5) ──────────────────────────────────────── */

#define AKAV_ZIP_MAX_DECOMPRESSED  (100 * 1024 * 1024)  /* 100 MB */
#define AKAV_ZIP_MAX_DEPTH         10
#define AKAV_ZIP_MAX_RATIO         100                   /* 100:1 */
#define AKAV_ZIP_MAX_FILES         10000
#define AKAV_ZIP_MAX_FILENAME      512

/* ── ZIP entry (parsed from local file header) ───────────────────── */

typedef struct {
    char     filename[AKAV_ZIP_MAX_FILENAME];
    uint16_t compression_method;    /* 0=stored, 8=deflate */
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint32_t crc32;
    uint32_t data_offset;           /* file offset of compressed data */
} akav_zip_entry_t;

/* ── ZIP extraction context ──────────────────────────────────────── */

typedef struct {
    uint32_t num_entries;
    uint64_t total_uncompressed;    /* running total for bomb detection */
    uint64_t total_compressed;
    int      current_depth;
    bool     bomb_detected;
    char     error[128];
} akav_zip_context_t;

/* ── Callback for each extracted entry ───────────────────────────── */

/* Return false from callback to stop extraction (e.g., malware found). */
typedef bool (*akav_zip_entry_callback_t)(
    const char*     filename,       /* entry filename */
    const uint8_t*  data,           /* decompressed data */
    size_t          data_len,       /* decompressed size */
    int             depth,          /* nesting depth */
    void*           user_data
);

/**
 * Initialize a ZIP context.
 */
void akav_zip_init(akav_zip_context_t* ctx, int initial_depth);

/**
 * Iterate over ZIP entries in a buffer, decompress each, and invoke callback.
 *
 * Returns true if extraction completed (or was stopped by callback).
 * Returns false on error (bomb detected, corrupt archive).
 * On bomb detection, ctx->bomb_detected is set and ctx->error describes it.
 *
 * The function enforces all anti-DoS limits: max decompressed size,
 * max ratio, max depth, max files.
 */
bool akav_zip_extract(akav_zip_context_t* ctx,
                      const uint8_t* data, size_t data_len,
                      akav_zip_entry_callback_t callback,
                      void* user_data);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_ZIP_H */
