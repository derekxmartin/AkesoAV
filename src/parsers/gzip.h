#ifndef AKAV_GZIP_H
#define AKAV_GZIP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── GZIP anti-DoS limits ────────────────────────────────────────── */

#define AKAV_GZIP_MAX_DECOMPRESSED  (100 * 1024 * 1024)  /* 100 MB */
#define AKAV_GZIP_MAX_RATIO         100                    /* 100:1 */

/* ── GZIP decompression context ──────────────────────────────────── */

typedef struct {
    uint64_t total_in;
    uint64_t total_out;
    bool     bomb_detected;
    char     error[128];
} akav_gzip_context_t;

/**
 * Initialize a GZIP context.
 */
void akav_gzip_init(akav_gzip_context_t* ctx);

/**
 * Decompress a GZIP buffer in memory.
 *
 * On success, *out_data is malloc'd and must be freed by the caller.
 * *out_len is set to the decompressed size.
 *
 * Returns true on success, false on error (bomb, corrupt, OOM).
 * On bomb detection, ctx->bomb_detected is set.
 */
bool akav_gzip_decompress(akav_gzip_context_t* ctx,
                           const uint8_t* data, size_t data_len,
                           uint8_t** out_data, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_GZIP_H */
