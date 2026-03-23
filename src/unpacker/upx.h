/* upx.h -- UPX static unpacker for PE files (P6-T2).
 *
 * Detects UPX-packed PEs by section names and "UPX!" magic,
 * decompresses NRV2B/NRV2D/NRV2E, reverses x86 call/jmp filter,
 * rebuilds the PE with restored IAT and OEP.
 *
 * The unpacked output can be fed through the full scan pipeline.
 */

#ifndef AKAV_UPX_H
#define AKAV_UPX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── UPX compression methods ─────────────────────────────────────── */

#define AKAV_UPX_METHOD_NRV2B  2
#define AKAV_UPX_METHOD_NRV2D  5
#define AKAV_UPX_METHOD_NRV2E  8
#define AKAV_UPX_METHOD_LZMA  14

/* ── UPX pack header (follows "UPX!" magic, 28 bytes) ────────────── */

#pragma pack(push, 1)
typedef struct {
    uint8_t  version;
    uint8_t  format;
    uint8_t  method;          /* compression method (NRV2B=2, NRV2D=5, NRV2E=8, LZMA=14) */
    uint8_t  level;           /* compression level */
    uint32_t u_adler;         /* Adler-32 of uncompressed data */
    uint32_t c_adler;         /* Adler-32 of compressed data */
    uint32_t u_len;           /* uncompressed length */
    uint32_t c_len;           /* compressed length */
    uint32_t u_file_size;     /* original file size */
    uint8_t  filter;          /* filter type (0x49 = CT x86) */
    uint8_t  filter_cto;      /* call-trick offset byte */
    uint8_t  n_mru;           /* unused */
    uint8_t  header_checksum; /* simple checksum of this header */
} akav_upx_packheader_t;
#pragma pack(pop)

/* ── Detection info ──────────────────────────────────────────────── */

typedef struct {
    bool     is_upx;          /* true if UPX packing detected */
    uint8_t  method;          /* compression method */
    uint8_t  filter;          /* filter type */
    uint32_t compressed_size; /* compressed data size */
    uint32_t original_size;   /* decompressed data size */
    uint32_t original_file_size; /* original PE file size */
    uint32_t oep_rva;         /* original entry point RVA (0 if unknown) */
    char     error[128];      /* error description on failure */
} akav_upx_info_t;

/* ── Public API ──────────────────────────────────────────────────── */

/**
 * Detect if a PE file is UPX-packed.
 * Checks for UPX section names (UPX0/UPX1) and "UPX!" magic.
 * Returns true if UPX packing is detected.
 * If info is non-NULL, populates detection details.
 */
bool akav_upx_detect(const uint8_t* data, size_t len, akav_upx_info_t* info);

/**
 * Unpack a UPX-packed PE file.
 * Decompresses the content, reverses the x86 filter, rebuilds the PE
 * with restored IAT and OEP.
 *
 * On success: *out_data is heap-allocated (caller must free()),
 *             *out_len is set to the unpacked PE size.
 *             Returns true.
 * On failure: *out_data = NULL, *out_len = 0, info->error describes reason.
 *             Returns false.
 */
bool akav_upx_unpack(const uint8_t* data, size_t len,
                     uint8_t** out_data, size_t* out_len,
                     akav_upx_info_t* info);

/* ── NRV decompression (exposed for testing) ─────────────────────── */

/**
 * Decompress NRV2B-compressed data (LE32 bit reading).
 * Returns true on success, false on malformed/truncated input.
 */
bool akav_nrv2b_decompress(const uint8_t* src, size_t src_len,
                           uint8_t* dst, size_t* dst_len, size_t dst_max);

/**
 * Decompress NRV2D-compressed data (LE32 bit reading).
 */
bool akav_nrv2d_decompress(const uint8_t* src, size_t src_len,
                           uint8_t* dst, size_t* dst_len, size_t dst_max);

/**
 * Decompress NRV2E-compressed data (LE32 bit reading).
 */
bool akav_nrv2e_decompress(const uint8_t* src, size_t src_len,
                           uint8_t* dst, size_t* dst_len, size_t dst_max);

/**
 * Reverse UPX's x86 call/jmp (CT) filter.
 * Converts absolute call/jmp targets back to relative.
 */
void akav_upx_unfilter_ct(uint8_t* buf, size_t len, uint8_t cto);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_UPX_H */
