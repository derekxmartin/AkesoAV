#include "gzip.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* ── Helpers ─────────────────────────────────────────────────────── */

static void gzip_error(akav_gzip_context_t* ctx, const char* msg)
{
    strncpy_s(ctx->error, sizeof(ctx->error), msg, _TRUNCATE);
}

/* ── Initialize context ──────────────────────────────────────────── */

void akav_gzip_init(akav_gzip_context_t* ctx)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
}

/* ── Decompress GZIP buffer ──────────────────────────────────────── */

bool akav_gzip_decompress(akav_gzip_context_t* ctx,
                           const uint8_t* data, size_t data_len,
                           uint8_t** out_data, size_t* out_len)
{
    if (!ctx || !data || data_len == 0 || !out_data || !out_len) {
        if (ctx) gzip_error(ctx, "Invalid parameters");
        return false;
    }

    *out_data = NULL;
    *out_len = 0;

    /* Validate GZIP magic (1F 8B) */
    if (data_len < 2 || data[0] != 0x1F || data[1] != 0x8B) {
        gzip_error(ctx, "Not a GZIP stream");
        return false;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    /* 16 + MAX_WBITS enables gzip decoding */
    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        gzip_error(ctx, "inflateInit2 failed");
        return false;
    }

    strm.next_in = (Bytef*)data;
    strm.avail_in = (uInt)data_len;

    /* Incremental decompression with bomb checks */
    size_t buf_size = 256 * 1024; /* start with 256KB */
    size_t total_out = 0;
    uint8_t* buf = (uint8_t*)malloc(buf_size);
    if (!buf) {
        inflateEnd(&strm);
        gzip_error(ctx, "Allocation failure");
        return false;
    }

    int ret;
    do {
        /* Check cumulative output against max */
        if (total_out >= AKAV_GZIP_MAX_DECOMPRESSED) {
            free(buf);
            inflateEnd(&strm);
            ctx->bomb_detected = true;
            gzip_error(ctx, "Decompressed size exceeds 100MB limit");
            return false;
        }

        /* Grow buffer if needed */
        if (total_out >= buf_size) {
            size_t new_size = buf_size * 2;
            if (new_size > AKAV_GZIP_MAX_DECOMPRESSED)
                new_size = AKAV_GZIP_MAX_DECOMPRESSED + 1; /* allow one check iteration */
            uint8_t* new_buf = (uint8_t*)realloc(buf, new_size);
            if (!new_buf) {
                free(buf);
                inflateEnd(&strm);
                gzip_error(ctx, "Allocation failure during decompression");
                return false;
            }
            buf = new_buf;
            buf_size = new_size;
        }

        strm.next_out = (Bytef*)(buf + total_out);
        strm.avail_out = (uInt)(buf_size - total_out);

        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_MEM_ERROR) {
            free(buf);
            inflateEnd(&strm);
            gzip_error(ctx, "zlib memory error");
            return false;
        }
        if (ret == Z_DATA_ERROR || ret == Z_NEED_DICT) {
            free(buf);
            inflateEnd(&strm);
            gzip_error(ctx, "Corrupt GZIP data");
            return false;
        }

        total_out = strm.total_out;

        /* Compression ratio check */
        if (strm.total_in > 0 && total_out > 0) {
            uint64_t ratio = (uint64_t)total_out / (uint64_t)strm.total_in;
            if (ratio > AKAV_GZIP_MAX_RATIO) {
                free(buf);
                inflateEnd(&strm);
                ctx->bomb_detected = true;
                gzip_error(ctx, "Decompression bomb: ratio exceeds 100:1");
                return false;
            }
        }
    } while (ret != Z_STREAM_END);

    ctx->total_in = strm.total_in;
    ctx->total_out = strm.total_out;
    inflateEnd(&strm);

    *out_data = buf;
    *out_len = total_out;
    return true;
}
