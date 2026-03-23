/* fuzz_x86_decode.cpp — libFuzzer target for x86 instruction decoder.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * Feeds arbitrary bytes into the x86 decoder to find crashes, hangs,
 * or memory errors in prefix/opcode/ModRM/SIB/displacement parsing.
 */

#include "emulator/x86_decode.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) return 0;

    /* Decode instructions sequentially through the entire input buffer,
     * just like the emulator's fetch-decode loop would. */
    size_t offset = 0;
    int count = 0;
    const int max_insns = 10000;  /* cap to avoid excessive time on large inputs */

    while (offset < size && count < max_insns) {
        akav_x86_insn_t insn;

        bool ok = akav_x86_decode(&insn, data + offset, size - offset);
        if (!ok) {
            /* Decoder rejected this byte sequence — skip one byte and continue.
             * This exercises error paths and recovery. */
            offset++;
        } else {
            /* Consume the decoded instruction length */
            if (insn.length == 0) break;  /* safety: avoid infinite loop */
            offset += insn.length;
        }
        count++;
    }

    return 0;
}
