/* fuzz_scan_buffer.cpp — libFuzzer target for akav_scan_buffer.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * This target feeds arbitrary bytes into the scan engine to find
 * crashes, hangs, or memory errors in the scan pipeline.
 */

#include "akesoav.h"
#include <cstdint>
#include <cstddef>

static akav_engine_t* g_engine = nullptr;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    akav_engine_create(&g_engine);
    akav_engine_init(g_engine, nullptr);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!g_engine)
        return 0;

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.timeout_ms = 1000; /* Short timeout for fuzzing */

    akav_scan_buffer(g_engine, data, size, "fuzz_input", &opts, &result);
    return 0;
}
