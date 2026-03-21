#include "zip.h"
#include "safe_reader.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* ── Helpers ─────────────────────────────────────────────────────── */

static void zip_error(akav_zip_context_t* ctx, const char* msg)
{
    strncpy_s(ctx->error, sizeof(ctx->error), msg, _TRUNCATE);
}

/* ── Initialize context ──────────────────────────────────────────── */

void akav_zip_init(akav_zip_context_t* ctx, int initial_depth)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->current_depth = initial_depth;
}

/* ── Decompress a stored entry (just copy) ───────────────────────── */

static bool decompress_stored(const uint8_t* src, size_t src_len,
                               uint8_t* dst, size_t dst_len)
{
    if (src_len != dst_len) return false;
    memcpy(dst, src, src_len);
    return true;
}

/* ── Decompress a deflated entry via zlib ────────────────────────── */

static bool decompress_deflate(const uint8_t* src, size_t src_len,
                                uint8_t* dst, size_t dst_len)
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    strm.next_in = (Bytef*)src;
    strm.avail_in = (uInt)src_len;
    strm.next_out = (Bytef*)dst;
    strm.avail_out = (uInt)dst_len;

    /* -MAX_WBITS for raw deflate (no zlib/gzip header) */
    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK)
        return false;

    int ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);

    return (ret == Z_STREAM_END);
}

/* ── Extract ZIP entries ─────────────────────────────────────────── */

bool akav_zip_extract(akav_zip_context_t* ctx,
                      const uint8_t* data, size_t data_len,
                      akav_zip_entry_callback_t callback,
                      void* user_data)
{
    if (!ctx || !data || data_len == 0 || !callback) {
        if (ctx) zip_error(ctx, "Invalid parameters");
        return false;
    }

    /* Depth check */
    if (ctx->current_depth >= AKAV_ZIP_MAX_DEPTH) {
        zip_error(ctx, "Maximum archive nesting depth exceeded");
        return false;
    }

    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);

    while (akav_reader_remaining(&r) >= 4) {
        /* Read signature */
        uint32_t sig;
        if (!akav_reader_read_u32_le(&r, &sig))
            break;

        /* Stop at central directory or end marker */
        if (sig == AKAV_ZIP_CENTRAL_DIR_SIG || sig == AKAV_ZIP_END_CENTRAL_SIG)
            break;

        if (sig != AKAV_ZIP_LOCAL_FILE_SIG) {
            /* Not a local file header — try to skip forward */
            break;
        }

        /* Local file header (after signature):
         * version_needed(2), flags(2), method(2), mod_time(2), mod_date(2),
         * crc32(4), compressed_size(4), uncompressed_size(4),
         * filename_len(2), extra_len(2) */
        uint16_t version_needed, flags, method, mod_time, mod_date;
        uint32_t crc32_val, comp_size, uncomp_size;
        uint16_t fname_len, extra_len;

        if (!akav_reader_read_u16_le(&r, &version_needed) ||
            !akav_reader_read_u16_le(&r, &flags) ||
            !akav_reader_read_u16_le(&r, &method) ||
            !akav_reader_read_u16_le(&r, &mod_time) ||
            !akav_reader_read_u16_le(&r, &mod_date) ||
            !akav_reader_read_u32_le(&r, &crc32_val) ||
            !akav_reader_read_u32_le(&r, &comp_size) ||
            !akav_reader_read_u32_le(&r, &uncomp_size) ||
            !akav_reader_read_u16_le(&r, &fname_len) ||
            !akav_reader_read_u16_le(&r, &extra_len)) {
            zip_error(ctx, "Truncated local file header");
            return false;
        }

        /* Read filename */
        char filename[AKAV_ZIP_MAX_FILENAME] = {0};
        if (fname_len > 0) {
            uint16_t copy_len = fname_len < (AKAV_ZIP_MAX_FILENAME - 1)
                                ? fname_len : (AKAV_ZIP_MAX_FILENAME - 1);
            if (!akav_reader_read_bytes(&r, (uint8_t*)filename, copy_len)) {
                zip_error(ctx, "Truncated filename");
                return false;
            }
            filename[copy_len] = '\0';

            /* Skip remaining filename bytes if truncated */
            if (fname_len > copy_len) {
                if (!akav_reader_skip(&r, fname_len - copy_len)) {
                    zip_error(ctx, "Truncated filename (skip)");
                    return false;
                }
            }
        }

        /* Skip extra field */
        if (extra_len > 0 && !akav_reader_skip(&r, extra_len)) {
            zip_error(ctx, "Truncated extra field");
            return false;
        }

        /* Data descriptor handling: if bit 3 is set, sizes may be in
         * a data descriptor after the compressed data. For simplicity,
         * if comp_size==0 and uncomp_size==0 with bit 3, skip entry. */
        if ((flags & 0x0008) && comp_size == 0) {
            /* Can't safely decompress without knowing the size */
            continue;
        }

        /* Skip directories (filename ends with /) */
        if (fname_len > 0 && filename[fname_len - 1] == '/') {
            if (comp_size > 0 && !akav_reader_skip(&r, comp_size)) break;
            continue;
        }

        /* Only support stored and deflate */
        if (method != AKAV_ZIP_METHOD_STORED && method != AKAV_ZIP_METHOD_DEFLATE) {
            if (comp_size > 0 && !akav_reader_skip(&r, comp_size))
                break;
            continue;
        }

        /* ── Anti-DoS checks ────────────────────────────────────── */

        /* Max files */
        if (ctx->num_entries >= AKAV_ZIP_MAX_FILES) {
            zip_error(ctx, "Maximum file count exceeded");
            return false;
        }

        /* Max decompressed size (per entry) */
        if (uncomp_size > AKAV_ZIP_MAX_DECOMPRESSED) {
            ctx->bomb_detected = true;
            zip_error(ctx, "Entry exceeds maximum decompressed size (100MB)");
            return false;
        }

        /* Compression ratio check */
        if (comp_size > 0 && uncomp_size > 0) {
            uint64_t ratio = (uint64_t)uncomp_size / (uint64_t)comp_size;
            if (ratio > AKAV_ZIP_MAX_RATIO) {
                ctx->bomb_detected = true;
                zip_error(ctx, "Decompression bomb: ratio exceeds 100:1");
                return false;
            }
        }

        /* Cumulative decompressed size check */
        ctx->total_uncompressed += uncomp_size;
        ctx->total_compressed += comp_size;
        if (ctx->total_uncompressed > AKAV_ZIP_MAX_DECOMPRESSED) {
            ctx->bomb_detected = true;
            zip_error(ctx, "Cumulative decompressed size exceeds 100MB");
            return false;
        }

        /* Read compressed data */
        size_t data_pos = akav_reader_position(&r);
        if (comp_size > akav_reader_remaining(&r)) {
            zip_error(ctx, "Compressed data extends beyond buffer");
            return false;
        }

        const uint8_t* comp_data = data + data_pos;
        if (!akav_reader_skip(&r, comp_size)) {
            zip_error(ctx, "Cannot skip compressed data");
            return false;
        }

        /* Allocate decompression buffer */
        size_t out_size = (method == AKAV_ZIP_METHOD_STORED) ? comp_size : uncomp_size;
        if (out_size == 0) {
            ctx->num_entries++;
            continue;
        }

        uint8_t* out_buf = (uint8_t*)malloc(out_size);
        if (!out_buf) {
            zip_error(ctx, "Allocation failure during decompression");
            return false;
        }

        /* Decompress */
        bool ok;
        if (method == AKAV_ZIP_METHOD_STORED) {
            ok = decompress_stored(comp_data, comp_size, out_buf, out_size);
        } else {
            ok = decompress_deflate(comp_data, comp_size, out_buf, out_size);
        }

        if (!ok) {
            free(out_buf);
            /* Non-fatal: skip corrupt entries */
            ctx->num_entries++;
            continue;
        }

        ctx->num_entries++;

        /* Invoke callback with decompressed data */
        bool should_continue = callback(filename, out_buf, out_size,
                                         ctx->current_depth + 1, user_data);
        free(out_buf);

        if (!should_continue)
            return true; /* Callback requested stop (e.g., malware found) */
    }

    return true;
}
