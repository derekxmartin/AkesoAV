#ifndef AKAV_TAR_H
#define AKAV_TAR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── TAR format constants ────────────────────────────────────────── */

#define AKAV_TAR_BLOCK_SIZE     512
#define AKAV_TAR_USTAR_MAGIC    "ustar"

/* TAR file types (typeflag field) */
#define AKAV_TAR_TYPE_REGULAR   '0'
#define AKAV_TAR_TYPE_REGULAR0  '\0'  /* older tars use NUL for regular files */
#define AKAV_TAR_TYPE_HARDLINK  '1'
#define AKAV_TAR_TYPE_SYMLINK   '2'
#define AKAV_TAR_TYPE_DIR       '5'

/* ── Anti-DoS limits ─────────────────────────────────────────────── */

#define AKAV_TAR_MAX_FILES          10000
#define AKAV_TAR_MAX_ENTRY_SIZE     (100 * 1024 * 1024)  /* 100 MB per entry */
#define AKAV_TAR_MAX_TOTAL_SIZE     (500 * 1024 * 1024)  /* 500 MB cumulative */
#define AKAV_TAR_MAX_FILENAME       512

/* ── TAR extraction context ──────────────────────────────────────── */

typedef struct {
    uint32_t num_entries;
    uint64_t total_extracted;   /* cumulative bytes extracted */
    bool     bomb_detected;
    char     error[128];
} akav_tar_context_t;

/* ── Callback for each extracted TAR entry ───────────────────────── */

/* Return false from callback to stop extraction. */
typedef bool (*akav_tar_entry_callback_t)(
    const char*     filename,
    const uint8_t*  data,
    size_t          data_len,
    void*           user_data
);

/**
 * Initialize a TAR context.
 */
void akav_tar_init(akav_tar_context_t* ctx);

/**
 * Iterate over TAR entries in a buffer, invoke callback for each regular file.
 *
 * Returns true if extraction completed (or stopped by callback).
 * Returns false on error (bomb, corrupt, etc).
 */
bool akav_tar_extract(akav_tar_context_t* ctx,
                       const uint8_t* data, size_t data_len,
                       akav_tar_entry_callback_t callback,
                       void* user_data);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_TAR_H */
