/* fuzz_ole2.cpp — libFuzzer target for OLE2/MS-CFB parser.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * Feeds arbitrary bytes into the OLE2 parser (header, FAT/DIFAT chain
 * traversal, directory parsing, stream extraction, VBA extraction,
 * OVBA decompression) to find crashes, hangs, or memory errors.
 */

#include "parsers/ole2.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* ── Full pipeline: parse → analyze → extract → VBA ─────────── */
    {
        akav_ole2_t ole2;
        memset(&ole2, 0, sizeof(ole2));

        /* analyze() calls parse + extract_streams + extract_vba internally */
        akav_ole2_analyze(&ole2, data, size);

        /* Exercise find_entry on common stream names */
        if (ole2.valid) {
            akav_ole2_find_entry(&ole2, "Root Entry");
            akav_ole2_find_entry(&ole2, "VBA");
            akav_ole2_find_entry(&ole2, "dir");
            akav_ole2_find_entry(&ole2, "ThisDocument");
            akav_ole2_find_entry(&ole2, "\x01CompObj");
            akav_ole2_find_entry(&ole2, "Macros");
        }

        akav_ole2_free(&ole2);
    }

    /* ── Parse-only path (no stream extraction) ────────────────── */
    {
        akav_ole2_t ole2;
        memset(&ole2, 0, sizeof(ole2));

        if (akav_ole2_parse(&ole2, data, size)) {
            /* Extract streams separately */
            akav_ole2_extract_streams(&ole2, data, size);

            /* Extract VBA */
            akav_ole2_extract_vba(&ole2, data, size);
        }

        akav_ole2_free(&ole2);
    }

    /* ── Standalone OVBA decompressor ──────────────────────────── */
    {
        uint8_t* out = nullptr;
        size_t out_len = 0;
        if (akav_ole2_ovba_decompress(data, size, &out, &out_len)) {
            free(out);
        }
    }

    /* ── Double-free safety: free without parse ────────────────── */
    {
        akav_ole2_t ole2;
        memset(&ole2, 0, sizeof(ole2));
        akav_ole2_free(&ole2);
    }

    return 0;
}
