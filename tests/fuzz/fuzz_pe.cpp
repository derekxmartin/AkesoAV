/* fuzz_pe.cpp — libFuzzer target for PE parser.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * Feeds arbitrary bytes into the PE parser (parse, imports, exports,
 * metadata analysis) to find crashes, hangs, or memory errors.
 */

#include "parsers/pe.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    akav_pe_t pe;

    /* Core parse */
    if (!akav_pe_parse(&pe, data, size))
        return 0;

    /* Import/export parsing */
    akav_pe_parse_imports(&pe, data, size);
    akav_pe_parse_exports(&pe, data, size);

    /* Metadata analysis (entropy, overlay, rich header, authenticode, resources) */
    akav_pe_analyze_metadata(&pe, data, size);

    /* Exercise utility functions */
    akav_pe_find_section(&pe, ".text");
    akav_pe_find_section(&pe, ".rsrc");
    akav_pe_machine_name(pe.machine);

    if (pe.num_sections > 0) {
        akav_pe_rva_to_offset(&pe, pe.sections[0].virtual_address);
    }

    akav_pe_free(&pe);
    return 0;
}
