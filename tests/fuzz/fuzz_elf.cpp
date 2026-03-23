/* fuzz_elf.cpp — libFuzzer target for ELF parser.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * Feeds arbitrary bytes into the ELF parser (core parse, sections,
 * symbols, dynamic, notes, interp, analysis) to find crashes, hangs,
 * or memory errors.
 */

#include "parsers/elf.h"
#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    akav_elf_t elf;
    memset(&elf, 0, sizeof(elf));

    /* Core header + section/program header parse */
    if (!akav_elf_parse(&elf, data, size)) {
        akav_elf_free(&elf);
        return 0;
    }

    /* Symbol tables (static + dynamic) */
    akav_elf_parse_symtab(&elf, data, size);
    akav_elf_parse_dynsym(&elf, data, size);

    /* Dynamic section */
    akav_elf_parse_dynamic(&elf, data, size);

    /* Notes (.note.gnu.build-id, etc.) */
    akav_elf_parse_notes(&elf, data, size);

    /* Interpreter string (.interp) */
    akav_elf_parse_interp(&elf, data, size);

    /* Full analysis (entropy, anomalies, etc.) */
    akav_elf_analyze(&elf, data, size);

    /* Exercise utility functions that read parsed state */
    akav_elf_machine_name(elf.e_machine);
    akav_elf_type_name(elf.e_type);

    if (elf.num_sections > 0) {
        akav_elf_find_section(&elf, ".text");
        akav_elf_find_section(&elf, ".symtab");
        akav_elf_find_section(&elf, ".dynamic");
        akav_elf_find_section(&elf, ".note");
    }

    akav_elf_free(&elf);
    return 0;
}
