/* fuzz_zip.cpp — libFuzzer target for ZIP parser.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * Feeds arbitrary bytes into the ZIP parser to find crashes,
 * hangs, or memory errors in header parsing, deflate decompression,
 * and anti-DoS limit enforcement.
 */

#include "parsers/zip.h"
#include <cstdint>
#include <cstddef>

static bool fuzz_callback(const char* /*filename*/, const uint8_t* /*data*/,
                           size_t /*data_len*/, int /*depth*/, void* ud)
{
    int* count = (int*)ud;
    (*count)++;
    /* Stop after 100 entries to bound runtime */
    return *count < 100;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    int count = 0;
    akav_zip_extract(&ctx, data, size, fuzz_callback, &count);

    /* Also test with non-zero initial depth */
    akav_zip_init(&ctx, 5);
    count = 0;
    akav_zip_extract(&ctx, data, size, fuzz_callback, &count);

    return 0;
}
