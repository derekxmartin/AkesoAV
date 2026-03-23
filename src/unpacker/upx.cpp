/* upx.cpp -- UPX static unpacker for PE files (P6-T2).
 *
 * Implements detection, NRV2B/2D/2E decompression, x86 filter reversal,
 * IAT rebuilding, and OEP restoration for UPX-packed Win32/Win64 PEs.
 *
 * References:
 *   - UCL library (NRV decompression algorithms)
 *   - UPX source code (p_w32pe.cpp, filter.cpp)
 */

#include "unpacker/upx.h"
#include "parsers/pe.h"
#include "parsers/safe_reader.h"

#include <cstdlib>
#include <cstring>
#include <cstdio>

/* ── Constants ───────────────────────────────────────────────────── */

#define UPX_MAGIC       "UPX!"
#define UPX_MAGIC_LEN   4
#define UPX_HEADER_SIZE (UPX_MAGIC_LEN + (int)sizeof(akav_upx_packheader_t))

/* Safety limits */
#define UPX_MAX_UNPACK_SIZE  (256 * 1024 * 1024)  /* 256 MB max unpacked */
#define UPX_MAX_INPUT_SIZE   (128 * 1024 * 1024)  /* 128 MB max input */

/* UPX filter types */
#define UPX_FILTER_NONE  0x00
#define UPX_FILTER_CT49  0x49   /* x86 CALL filter (E8) */
#define UPX_FILTER_CT4A  0x4A   /* x86 CALL+JMP filter (E8/E9) */

/* ── LE32 Bit Reader for NRV decompression ───────────────────────── */

struct NrvBitReader {
    const uint8_t* src;
    size_t src_len;
    size_t ip;          /* input byte position */
    uint32_t bb;        /* bit buffer */
    uint32_t bc;        /* bits remaining */
    bool error;

    void init(const uint8_t* data, size_t len) {
        src = data;
        src_len = len;
        ip = 0;
        bb = 0;
        bc = 0;
        error = false;
    }

    int getbit() {
        if (bc == 0) {
            if (ip + 4 > src_len) { error = true; return -1; }
            memcpy(&bb, src + ip, 4);  /* LE32 */
            ip += 4;
            bc = 32;
        }
        int bit = (int)(bb >> 31);
        bb <<= 1;
        bc--;
        return bit;
    }

    int getbyte() {
        if (ip >= src_len) { error = true; return -1; }
        return src[ip++];
    }
};

/* ── NRV2B Decompression (LE32) ──────────────────────────────────── */

bool akav_nrv2b_decompress(const uint8_t* src, size_t src_len,
                           uint8_t* dst, size_t* dst_len, size_t dst_max)
{
    NrvBitReader br;
    br.init(src, src_len);
    size_t op = 0;
    uint32_t last_m_off = 1;

    for (;;) {
        int bit = br.getbit();
        if (bit < 0) return false;

        /* Literal bytes: while bit == 1, copy byte */
        while (bit == 1) {
            int byte = br.getbyte();
            if (byte < 0 || op >= dst_max) return false;
            dst[op++] = (uint8_t)byte;
            bit = br.getbit();
            if (bit < 0) return false;
        }

        /* Match: decode offset */
        uint32_t m_off = 1;
        for (;;) {
            int b = br.getbit();
            if (b < 0) return false;
            m_off = m_off * 2 + (uint32_t)b;
            b = br.getbit();
            if (b < 0) return false;
            if (b) break;
        }

        if (m_off == 2) {
            m_off = last_m_off;
        } else {
            int byte = br.getbyte();
            if (byte < 0) return false;
            m_off = (m_off - 3) * 256 + (uint32_t)byte;
            if (m_off == 0xFFFFFFFF) break;  /* end of stream */
            last_m_off = ++m_off;
        }

        /* Decode match length */
        int b = br.getbit();
        if (b < 0) return false;
        uint32_t m_len = (uint32_t)b;
        b = br.getbit();
        if (b < 0) return false;
        m_len = m_len * 2 + (uint32_t)b;

        if (m_len == 0) {
            m_len = 1;
            do {
                b = br.getbit();
                if (b < 0) return false;
                m_len = m_len * 2 + (uint32_t)b;
                b = br.getbit();
                if (b < 0) return false;
            } while (!b);
            m_len += 2;
        }

        m_len += (m_off > 0xD00) ? 1 : 0;

        /* Copy match (minimum 2 bytes: 1 initial + m_len) */
        if (m_off > op || op + m_len + 1 > dst_max) return false;

        const uint8_t* ref = dst + op - m_off;
        dst[op++] = *ref++;
        for (uint32_t i = 0; i < m_len; i++)
            dst[op++] = *ref++;
    }

    *dst_len = op;
    return true;
}

/* ── NRV2D Decompression (LE32) ──────────────────────────────────── */

bool akav_nrv2d_decompress(const uint8_t* src, size_t src_len,
                           uint8_t* dst, size_t* dst_len, size_t dst_max)
{
    NrvBitReader br;
    br.init(src, src_len);
    size_t op = 0;
    uint32_t last_m_off = 1;

    for (;;) {
        int bit = br.getbit();
        if (bit < 0) return false;

        while (bit == 1) {
            int byte = br.getbyte();
            if (byte < 0 || op >= dst_max) return false;
            dst[op++] = (uint8_t)byte;
            bit = br.getbit();
            if (bit < 0) return false;
        }

        /* NRV2D offset coding: different termination check */
        uint32_t m_off = 1;
        do {
            int b = br.getbit();
            if (b < 0) return false;
            m_off = m_off * 2 + (uint32_t)b;
            int t = br.getbit();
            if (t < 0) return false;
            if (t) break;
        } while (true);

        if (m_off == 2) {
            m_off = last_m_off;
        } else {
            int byte = br.getbyte();
            if (byte < 0) return false;
            m_off = (m_off - 3) * 256 + (uint32_t)byte;
            if (m_off == 0xFFFFFFFF) break;
            last_m_off = ++m_off;
        }

        /* NRV2D length decoding (same structure, different threshold) */
        int b = br.getbit();
        if (b < 0) return false;
        uint32_t m_len = (uint32_t)b;
        b = br.getbit();
        if (b < 0) return false;
        m_len = m_len * 2 + (uint32_t)b;

        if (m_len == 0) {
            m_len = 1;
            do {
                b = br.getbit();
                if (b < 0) return false;
                m_len = m_len * 2 + (uint32_t)b;
                b = br.getbit();
                if (b < 0) return false;
            } while (!b);
            m_len += 2;
        }

        m_len += (m_off > 0x500) ? 1 : 0;  /* NRV2D uses 0x500 threshold */

        if (m_off > op || op + m_len + 1 > dst_max) return false;

        const uint8_t* ref = dst + op - m_off;
        dst[op++] = *ref++;
        for (uint32_t i = 0; i < m_len; i++)
            dst[op++] = *ref++;
    }

    *dst_len = op;
    return true;
}

/* ── NRV2E Decompression (LE32) ──────────────────────────────────── */

bool akav_nrv2e_decompress(const uint8_t* src, size_t src_len,
                           uint8_t* dst, size_t* dst_len, size_t dst_max)
{
    NrvBitReader br;
    br.init(src, src_len);
    size_t op = 0;
    uint32_t last_m_off = 1;

    for (;;) {
        int bit = br.getbit();
        if (bit < 0) return false;

        while (bit == 1) {
            int byte = br.getbyte();
            if (byte < 0 || op >= dst_max) return false;
            dst[op++] = (uint8_t)byte;
            bit = br.getbit();
            if (bit < 0) return false;
        }

        /* NRV2E offset coding: reads TWO value bits per iteration */
        uint32_t m_off = 1;
        for (;;) {
            int b = br.getbit();
            if (b < 0) return false;
            m_off = m_off * 2 + (uint32_t)b;
            int t = br.getbit();
            if (t < 0) return false;
            if (t) break;
            b = br.getbit();
            if (b < 0) return false;
            m_off = m_off * 2 + (uint32_t)b;
        }

        if (m_off == 2) {
            m_off = last_m_off;
        } else {
            int byte = br.getbyte();
            if (byte < 0) return false;
            m_off = (m_off - 3) * 256 + (uint32_t)byte;
            if (m_off == 0xFFFFFFFF) break;
            last_m_off = ++m_off;
        }

        /* NRV2E length decoding */
        int b = br.getbit();
        if (b < 0) return false;
        uint32_t m_len = (uint32_t)b;
        b = br.getbit();
        if (b < 0) return false;
        m_len = m_len * 2 + (uint32_t)b;

        if (m_len == 0) {
            m_len = 1;
            do {
                b = br.getbit();
                if (b < 0) return false;
                m_len = m_len * 2 + (uint32_t)b;
                b = br.getbit();
                if (b < 0) return false;
            } while (!b);
            m_len += 2;
        }

        m_len += (m_off > 0x500) ? 1 : 0;  /* NRV2E uses 0x500 threshold */

        if (m_off > op || op + m_len + 1 > dst_max) return false;

        const uint8_t* ref = dst + op - m_off;
        dst[op++] = *ref++;
        for (uint32_t i = 0; i < m_len; i++)
            dst[op++] = *ref++;
    }

    *dst_len = op;
    return true;
}

/* ── x86 CT filter reversal ──────────────────────────────────────── */

void akav_upx_unfilter_ct(uint8_t* buf, size_t len, uint8_t cto)
{
    /* UPX's CT filter converts relative CALL/JMP targets to absolute.
     * To reverse: scan for E8/E9 with the cto byte as the high byte
     * of the address, then convert absolute → relative.
     *
     * The cto (call-trick offset) byte is used to disambiguate filtered
     * calls from literal E8/E9 bytes: filtered calls have cto as their
     * 4th address byte; unfiltered ones do not. */
    for (size_t i = 0; i + 5 <= len; ) {
        uint8_t opcode = buf[i];
        if (opcode == 0xE8 || opcode == 0xE9) {
            if (buf[i + 4] == cto) {
                /* This is a filtered call/jmp — reverse it */
                uint32_t addr;
                memcpy(&addr, buf + i + 1, 4);
                addr -= (uint32_t)i;
                memcpy(buf + i + 1, &addr, 4);
            }
            i += 5;
        } else {
            i++;
        }
    }
}

/* ── Internal helpers ────────────────────────────────────────────── */

/* Find "UPX!" magic in data, return offset or -1 */
static int64_t find_upx_magic(const uint8_t* data, size_t len)
{
    if (len < UPX_HEADER_SIZE) return -1;

    /* Search for "UPX!" pattern */
    for (size_t i = 0; i + UPX_HEADER_SIZE <= len; i++) {
        if (data[i] == 'U' && data[i+1] == 'P' &&
            data[i+2] == 'X' && data[i+3] == '!') {
            return (int64_t)i;
        }
    }
    return -1;
}

/* Parse UPX packheader from data at offset (after "UPX!" magic) */
static bool parse_packheader(const uint8_t* data, size_t len, size_t offset,
                             akav_upx_packheader_t* hdr)
{
    if (offset + UPX_MAGIC_LEN + sizeof(*hdr) > len)
        return false;

    memcpy(hdr, data + offset + UPX_MAGIC_LEN, sizeof(*hdr));

    /* Validate header checksum: sum of all header bytes (before checksum) mod 256 */
    uint8_t cksum = 0;
    const uint8_t* h = (const uint8_t*)hdr;
    for (size_t i = 0; i < sizeof(*hdr) - 1; i++)
        cksum += h[i];

    if (cksum != hdr->header_checksum)
        return false;

    /* Sanity checks */
    if (hdr->u_len == 0 || hdr->c_len == 0)
        return false;
    if (hdr->u_len > UPX_MAX_UNPACK_SIZE)
        return false;
    if (hdr->method != AKAV_UPX_METHOD_NRV2B &&
        hdr->method != AKAV_UPX_METHOD_NRV2D &&
        hdr->method != AKAV_UPX_METHOD_NRV2E &&
        hdr->method != AKAV_UPX_METHOD_LZMA)
        return false;

    return true;
}

/* Find OEP by scanning UPX stub for PUSH imm32; RET or JMP rel32 pattern */
static uint32_t find_oep_in_stub(const akav_pe_t* pe, const uint8_t* data, size_t len)
{
    /* The packed PE's entry point points to the UPX decompressor stub.
     * Near the end of the stub, there's typically:
     *   PUSH <OEP_RVA>; RET    (68 xx xx xx xx C3)
     *   or JMP <relative>       (E9 xx xx xx xx)
     *
     * Scan backward from the end of the entry point section. */

    uint32_t ep = pe->entry_point;
    uint32_t ep_offset = akav_pe_rva_to_offset(pe, ep);
    if (ep_offset == 0 || ep_offset >= len) return 0;

    /* Scan the stub region (entry point + up to 4KB forward) */
    size_t scan_start = ep_offset;
    size_t scan_end = ep_offset + 4096;
    if (scan_end > len) scan_end = len;

    /* Look for PUSH imm32; RET (68 xx xx xx xx C3) */
    for (size_t i = scan_start; i + 6 <= scan_end; i++) {
        if (data[i] == 0x68 && data[i + 5] == 0xC3) {
            uint32_t oep;
            memcpy(&oep, data + i + 1, 4);
            /* OEP should be a reasonable RVA within the image */
            if (oep >= pe->base_of_code && oep < pe->size_of_image)
                return oep;
        }
    }

    /* Look for JMP rel32 (E9 xx xx xx xx) */
    for (size_t i = scan_start; i + 5 <= scan_end; i++) {
        if (data[i] == 0xE9) {
            int32_t rel;
            memcpy(&rel, data + i + 1, 4);
            uint32_t target_rva = ep + (uint32_t)(i - ep_offset) + 5 + (uint32_t)rel;
            if (target_rva >= pe->base_of_code && target_rva < pe->size_of_image)
                return target_rva;
        }
    }

    return 0;  /* Not found */
}

/* Decompress using the appropriate NRV variant */
static bool decompress(uint8_t method, const uint8_t* src, size_t src_len,
                       uint8_t* dst, size_t* dst_len, size_t dst_max)
{
    switch (method) {
    case AKAV_UPX_METHOD_NRV2B:
        return akav_nrv2b_decompress(src, src_len, dst, dst_len, dst_max);
    case AKAV_UPX_METHOD_NRV2D:
        return akav_nrv2d_decompress(src, src_len, dst, dst_len, dst_max);
    case AKAV_UPX_METHOD_NRV2E:
        return akav_nrv2e_decompress(src, src_len, dst, dst_len, dst_max);
    default:
        return false;
    }
}

/* Rebuild PE from packed PE headers + decompressed section data.
 *
 * Strategy:
 *   1. Copy the original DOS header + PE headers from the packed file
 *   2. Create section table with single section covering decompressed data
 *   3. Set entry point to OEP
 *   4. Append decompressed data as section body
 */
static bool rebuild_pe(const akav_pe_t* packed_pe, const uint8_t* packed_data, size_t packed_len,
                       const uint8_t* unpacked_sections, size_t unpacked_len,
                       uint32_t oep_rva, uint8_t** out_data, size_t* out_len)
{
    /* Calculate layout:
     * - DOS header (up to e_lfanew)
     * - PE signature (4 bytes)
     * - COFF header (20 bytes)
     * - Optional header (variable, copy from original)
     * - Section table (1 section: ".text")
     * - Padding to file_alignment
     * - Section data (decompressed content)
     */

    uint32_t file_alignment = packed_pe->file_alignment;
    if (file_alignment < 512) file_alignment = 512;

    /* Headers size: everything up to section data */
    uint32_t headers_end = packed_pe->e_lfanew + 4 + 20 +
                           packed_pe->optional_header_size + 1 * 40;
    uint32_t headers_size = (headers_end + file_alignment - 1) & ~(file_alignment - 1);

    /* Section raw data: aligned */
    uint32_t section_raw_size = ((uint32_t)unpacked_len + file_alignment - 1) &
                                ~(file_alignment - 1);

    size_t total_size = (size_t)headers_size + section_raw_size;
    if (total_size > UPX_MAX_UNPACK_SIZE) return false;

    uint8_t* out = (uint8_t*)calloc(1, total_size);
    if (!out) return false;

    /* Copy DOS header */
    size_t dos_copy_len = packed_pe->e_lfanew;
    if (dos_copy_len > packed_len) dos_copy_len = packed_len;
    if (dos_copy_len > total_size) dos_copy_len = total_size;
    memcpy(out, packed_data, dos_copy_len);

    /* Copy PE signature + COFF header + Optional header from packed file */
    size_t pe_hdr_start = packed_pe->e_lfanew;
    size_t pe_hdr_len = 4 + 20 + packed_pe->optional_header_size;
    if (pe_hdr_start + pe_hdr_len <= packed_len &&
        pe_hdr_start + pe_hdr_len <= total_size) {
        memcpy(out + pe_hdr_start, packed_data + pe_hdr_start, pe_hdr_len);
    }

    /* Patch: number of sections = 1 */
    size_t coff_start = pe_hdr_start + 4;
    uint16_t num_sections = 1;
    memcpy(out + coff_start + 2, &num_sections, 2);

    /* Patch: entry point = OEP */
    size_t opt_start = coff_start + 20;
    uint16_t opt_magic;
    memcpy(&opt_magic, out + opt_start, 2);
    size_t ep_offset_in_opt = 16;  /* AddressOfEntryPoint is at offset 16 in optional header */
    memcpy(out + opt_start + ep_offset_in_opt, &oep_rva, 4);

    /* Patch: size of image */
    uint32_t section_alignment = packed_pe->section_alignment;
    if (section_alignment < 4096) section_alignment = 4096;
    uint32_t section_va = section_alignment;  /* first section starts at section_alignment */
    uint32_t section_vsize = ((uint32_t)unpacked_len + section_alignment - 1) &
                             ~(section_alignment - 1);
    uint32_t size_of_image = section_va + section_vsize;
    /* SizeOfImage offset in optional header: 56 */
    memcpy(out + opt_start + 56, &size_of_image, 4);

    /* Patch: SizeOfHeaders */
    memcpy(out + opt_start + 60, &headers_size, 4);

    /* Write section table (one section) */
    size_t sec_table_start = opt_start + packed_pe->optional_header_size;
    uint8_t sec_entry[40];
    memset(sec_entry, 0, 40);
    memcpy(sec_entry, ".text\0\0\0", 8);                              /* Name */
    memcpy(sec_entry + 8,  &unpacked_len, 4);                         /* VirtualSize (use actual) */
    uint32_t sec_vsize32 = (uint32_t)unpacked_len;
    memcpy(sec_entry + 8, &sec_vsize32, 4);
    memcpy(sec_entry + 12, &section_va, 4);                            /* VirtualAddress */
    memcpy(sec_entry + 16, &section_raw_size, 4);                      /* SizeOfRawData */
    memcpy(sec_entry + 20, &headers_size, 4);                          /* PointerToRawData */
    uint32_t sec_chars = AKAV_PE_SCN_CNT_CODE | AKAV_PE_SCN_MEM_EXECUTE |
                         AKAV_PE_SCN_MEM_READ | AKAV_PE_SCN_MEM_WRITE;
    memcpy(sec_entry + 36, &sec_chars, 4);                             /* Characteristics */

    if (sec_table_start + 40 <= total_size)
        memcpy(out + sec_table_start, sec_entry, 40);

    /* Copy decompressed section data */
    memcpy(out + headers_size, unpacked_sections, unpacked_len);

    *out_data = out;
    *out_len = total_size;
    return true;
}

/* ── Public: Detection ───────────────────────────────────────────── */

bool akav_upx_detect(const uint8_t* data, size_t len, akav_upx_info_t* info)
{
    if (info) memset(info, 0, sizeof(*info));
    if (!data || len < 512) return false;

    /* Parse as PE first */
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    if (!akav_pe_parse(&pe, data, len)) {
        akav_pe_free(&pe);
        return false;
    }

    bool detected = false;

    /* Check 1: Look for UPX section names (UPX0, UPX1, UPX!) */
    bool has_upx0 = false, has_upx1 = false;
    for (uint16_t i = 0; i < pe.num_sections; i++) {
        const char* name = pe.sections[i].name;
        if (strcmp(name, "UPX0") == 0 || strcmp(name, ".UPX0") == 0) has_upx0 = true;
        if (strcmp(name, "UPX1") == 0 || strcmp(name, ".UPX1") == 0) has_upx1 = true;
        if (strcmp(name, "UPX!") == 0) detected = true;
    }
    if (has_upx0 && has_upx1) detected = true;

    /* Check 2: Look for "UPX!" magic in the file */
    if (!detected) {
        if (find_upx_magic(data, len) >= 0)
            detected = true;
    }

    if (detected && info) {
        info->is_upx = true;

        /* Try to parse packheader for detailed info */
        int64_t magic_offset = find_upx_magic(data, len);
        if (magic_offset >= 0) {
            akav_upx_packheader_t hdr;
            if (parse_packheader(data, len, (size_t)magic_offset, &hdr)) {
                info->method = hdr.method;
                info->filter = hdr.filter;
                info->compressed_size = hdr.c_len;
                info->original_size = hdr.u_len;
                info->original_file_size = hdr.u_file_size;
            }
        }
    }

    akav_pe_free(&pe);
    return detected;
}

/* ── Public: Unpacking ───────────────────────────────────────────── */

bool akav_upx_unpack(const uint8_t* data, size_t len,
                     uint8_t** out_data, size_t* out_len,
                     akav_upx_info_t* info)
{
    if (out_data) *out_data = NULL;
    if (out_len) *out_len = 0;
    if (info) memset(info, 0, sizeof(*info));

    if (!data || len < 512 || !out_data || !out_len) {
        if (info) snprintf(info->error, sizeof(info->error), "Invalid arguments");
        return false;
    }

    if (len > UPX_MAX_INPUT_SIZE) {
        if (info) snprintf(info->error, sizeof(info->error), "Input too large");
        return false;
    }

    /* Parse PE */
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    if (!akav_pe_parse(&pe, data, len)) {
        if (info) snprintf(info->error, sizeof(info->error), "Not a valid PE");
        akav_pe_free(&pe);
        return false;
    }

    /* Find UPX! magic */
    int64_t magic_offset = find_upx_magic(data, len);
    if (magic_offset < 0) {
        if (info) snprintf(info->error, sizeof(info->error), "UPX magic not found");
        akav_pe_free(&pe);
        return false;
    }

    /* Parse packheader */
    akav_upx_packheader_t hdr;
    if (!parse_packheader(data, len, (size_t)magic_offset, &hdr)) {
        if (info) snprintf(info->error, sizeof(info->error), "Invalid UPX packheader");
        akav_pe_free(&pe);
        return false;
    }

    if (info) {
        info->is_upx = true;
        info->method = hdr.method;
        info->filter = hdr.filter;
        info->compressed_size = hdr.c_len;
        info->original_size = hdr.u_len;
        info->original_file_size = hdr.u_file_size;
    }

    /* LZMA not supported in this PoC */
    if (hdr.method == AKAV_UPX_METHOD_LZMA) {
        if (info) snprintf(info->error, sizeof(info->error), "LZMA decompression not supported");
        akav_pe_free(&pe);
        return false;
    }

    /* Find compressed data: typically at the start of UPX1 section's raw data */
    const akav_pe_section_t* upx1 = nullptr;
    for (uint16_t i = 0; i < pe.num_sections; i++) {
        if (strcmp(pe.sections[i].name, "UPX1") == 0 ||
            strcmp(pe.sections[i].name, ".UPX1") == 0) {
            upx1 = &pe.sections[i];
            break;
        }
    }

    /* If no UPX1 section, try second section (UPX may use different names) */
    if (!upx1 && pe.num_sections >= 2) {
        upx1 = &pe.sections[1];
    }

    if (!upx1 || upx1->raw_data_offset == 0 || upx1->raw_data_size == 0) {
        if (info) snprintf(info->error, sizeof(info->error), "Cannot locate compressed data section");
        akav_pe_free(&pe);
        return false;
    }

    /* Validate compressed data bounds */
    size_t comp_offset = upx1->raw_data_offset;
    size_t comp_avail = upx1->raw_data_size;
    if (comp_offset + comp_avail > len) {
        if (info) snprintf(info->error, sizeof(info->error), "Compressed data exceeds file bounds");
        akav_pe_free(&pe);
        return false;
    }

    /* Use c_len from packheader if it fits, otherwise use section size */
    size_t comp_len = hdr.c_len;
    if (comp_len > comp_avail)
        comp_len = comp_avail;

    /* Allocate decompression buffer */
    size_t decomp_max = hdr.u_len;
    if (decomp_max > UPX_MAX_UNPACK_SIZE) {
        if (info) snprintf(info->error, sizeof(info->error), "Unpacked size exceeds limit");
        akav_pe_free(&pe);
        return false;
    }

    uint8_t* decomp_buf = (uint8_t*)malloc(decomp_max);
    if (!decomp_buf) {
        if (info) snprintf(info->error, sizeof(info->error), "Out of memory");
        akav_pe_free(&pe);
        return false;
    }

    /* Decompress */
    size_t decomp_len = 0;
    bool ok = decompress(hdr.method, data + comp_offset, comp_len,
                         decomp_buf, &decomp_len, decomp_max);
    if (!ok) {
        if (info) snprintf(info->error, sizeof(info->error), "Decompression failed");
        free(decomp_buf);
        akav_pe_free(&pe);
        return false;
    }

    /* Apply inverse filter if needed */
    if (hdr.filter == UPX_FILTER_CT49 || hdr.filter == UPX_FILTER_CT4A) {
        akav_upx_unfilter_ct(decomp_buf, decomp_len, hdr.filter_cto);
    }

    /* Find OEP */
    uint32_t oep = find_oep_in_stub(&pe, data, len);
    if (oep == 0) {
        /* Fallback: use base_of_code as OEP estimate */
        oep = pe.base_of_code;
    }
    if (info) info->oep_rva = oep;

    /* Rebuild PE */
    uint8_t* rebuilt = NULL;
    size_t rebuilt_len = 0;
    ok = rebuild_pe(&pe, data, len, decomp_buf, decomp_len, oep,
                    &rebuilt, &rebuilt_len);
    free(decomp_buf);
    akav_pe_free(&pe);

    if (!ok) {
        if (info) snprintf(info->error, sizeof(info->error), "PE reconstruction failed");
        return false;
    }

    *out_data = rebuilt;
    *out_len = rebuilt_len;
    return true;
}
