#include "tar.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Helpers ─────────────────────────────────────────────────────── */

static void tar_error(akav_tar_context_t* ctx, const char* msg)
{
    strncpy_s(ctx->error, sizeof(ctx->error), msg, _TRUNCATE);
}

/* Parse an octal string field (TAR sizes/modes are stored as ASCII octal).
 * Returns the parsed value, or 0 on error. */
static uint64_t parse_octal(const char* field, size_t len)
{
    uint64_t result = 0;
    for (size_t i = 0; i < len; i++) {
        char c = field[i];
        if (c == '\0' || c == ' ')
            break;
        if (c < '0' || c > '7')
            return 0;
        result = (result << 3) | (uint64_t)(c - '0');
    }
    return result;
}

/* Check if a 512-byte block is all zeros (end-of-archive marker). */
static bool is_zero_block(const uint8_t* block)
{
    for (int i = 0; i < AKAV_TAR_BLOCK_SIZE; i++) {
        if (block[i] != 0)
            return false;
    }
    return true;
}

/* ── Initialize context ──────────────────────────────────────────── */

void akav_tar_init(akav_tar_context_t* ctx)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
}

/* ── Extract TAR entries ─────────────────────────────────────────── */

/*
 * POSIX ustar header layout (512 bytes):
 *   0   100  filename (null-terminated)
 *   100   8  mode (octal)
 *   108   8  uid (octal)
 *   116   8  gid (octal)
 *   124  12  size (octal)
 *   136  12  mtime (octal)
 *   148   8  checksum (octal)
 *   156   1  typeflag
 *   157 100  linkname
 *   257   6  magic ("ustar\0" or "ustar ")
 *   263   2  version
 *   265  32  uname
 *   297  32  gname
 *   329   8  devmajor
 *   337   8  devminor
 *   345 155  prefix
 *   500  12  padding
 */

bool akav_tar_extract(akav_tar_context_t* ctx,
                       const uint8_t* data, size_t data_len,
                       akav_tar_entry_callback_t callback,
                       void* user_data)
{
    if (!ctx || !data || data_len == 0 || !callback) {
        if (ctx) tar_error(ctx, "Invalid parameters");
        return false;
    }

    size_t pos = 0;

    while (pos + AKAV_TAR_BLOCK_SIZE <= data_len) {
        const uint8_t* header = data + pos;

        /* End-of-archive: two consecutive zero blocks */
        if (is_zero_block(header))
            break;

        /* Parse header fields */
        char filename[AKAV_TAR_MAX_FILENAME] = {0};

        /* Check for ustar prefix (offset 345, 155 bytes) to build full path */
        const char* prefix = (const char*)(header + 345);
        const char* name   = (const char*)(header + 0);
        size_t prefix_len  = strnlen(prefix, 155);
        size_t name_len    = strnlen(name, 100);

        if (prefix_len > 0 && (prefix_len + 1 + name_len) < AKAV_TAR_MAX_FILENAME) {
            snprintf(filename, sizeof(filename), "%.*s/%.*s",
                     (int)prefix_len, prefix, (int)name_len, name);
        } else {
            snprintf(filename, sizeof(filename), "%.*s", (int)name_len, name);
        }

        /* Parse size (octal, 12 bytes at offset 124) */
        uint64_t entry_size = parse_octal((const char*)(header + 124), 12);

        /* Parse typeflag (offset 156) */
        char typeflag = (char)header[156];

        /* Advance past header */
        pos += AKAV_TAR_BLOCK_SIZE;

        /* Only process regular files */
        if (typeflag != AKAV_TAR_TYPE_REGULAR &&
            typeflag != AKAV_TAR_TYPE_REGULAR0) {
            /* Skip data blocks for non-regular entries */
            size_t blocks = (entry_size + AKAV_TAR_BLOCK_SIZE - 1) / AKAV_TAR_BLOCK_SIZE;
            pos += blocks * AKAV_TAR_BLOCK_SIZE;
            continue;
        }

        /* ── Anti-DoS checks ──────────────────────────────────── */

        if (ctx->num_entries >= AKAV_TAR_MAX_FILES) {
            tar_error(ctx, "Maximum file count exceeded");
            return false;
        }

        if (entry_size > AKAV_TAR_MAX_ENTRY_SIZE) {
            ctx->bomb_detected = true;
            tar_error(ctx, "Entry exceeds maximum size (100MB)");
            return false;
        }

        ctx->total_extracted += entry_size;
        if (ctx->total_extracted > AKAV_TAR_MAX_TOTAL_SIZE) {
            ctx->bomb_detected = true;
            tar_error(ctx, "Cumulative extracted size exceeds 500MB");
            return false;
        }

        /* Verify data is within bounds */
        if (pos + entry_size > data_len) {
            tar_error(ctx, "Entry data extends beyond buffer");
            return false;
        }

        const uint8_t* entry_data = data + pos;

        /* Skip data blocks (round up to 512-byte boundary) */
        size_t blocks = (entry_size + AKAV_TAR_BLOCK_SIZE - 1) / AKAV_TAR_BLOCK_SIZE;
        pos += blocks * AKAV_TAR_BLOCK_SIZE;

        ctx->num_entries++;

        /* Skip zero-length files */
        if (entry_size == 0)
            continue;

        /* Invoke callback */
        bool should_continue = callback(filename, entry_data, (size_t)entry_size, user_data);
        if (!should_continue)
            return true; /* Callback requested stop */
    }

    return true;
}
