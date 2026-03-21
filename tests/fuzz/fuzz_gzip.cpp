/* fuzz_gzip.cpp — libFuzzer target for GZIP and TAR parsers.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * Feeds arbitrary bytes into the GZIP decompressor and TAR extractor
 * to find crashes, hangs, or memory errors in header parsing,
 * decompression, and anti-DoS limit enforcement.
 */

#include "parsers/gzip.h"
#include "parsers/tar.h"
#include <cstdint>
#include <cstddef>
#include <cstdlib>

static bool tar_fuzz_callback(const char* /*filename*/, const uint8_t* /*data*/,
                               size_t /*data_len*/, void* ud)
{
    int* count = (int*)ud;
    (*count)++;
    return *count < 100;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* ── Fuzz GZIP decompressor ──────────────────────────────────── */
    {
        akav_gzip_context_t ctx;
        akav_gzip_init(&ctx);

        uint8_t* out = nullptr;
        size_t out_len = 0;
        if (akav_gzip_decompress(&ctx, data, size, &out, &out_len)) {
            /* If decompression succeeded, also fuzz the TAR parser on
             * the decompressed output (simulates .tar.gz processing) */
            akav_tar_context_t tar_ctx;
            akav_tar_init(&tar_ctx);
            int count = 0;
            akav_tar_extract(&tar_ctx, out, out_len, tar_fuzz_callback, &count);
            free(out);
        }
    }

    /* ── Fuzz TAR parser directly ────────────────────────────────── */
    {
        akav_tar_context_t ctx;
        akav_tar_init(&ctx);
        int count = 0;
        akav_tar_extract(&ctx, data, size, tar_fuzz_callback, &count);
    }

    return 0;
}
