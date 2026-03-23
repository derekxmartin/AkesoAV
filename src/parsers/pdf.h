#ifndef AKAV_PDF_H
#define AKAV_PDF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── PDF format constants ──────────────────────────────────────── */

#define AKAV_PDF_MAX_OBJECTS          65536
#define AKAV_PDF_MAX_XREF_TABLES     64
#define AKAV_PDF_MAX_JS_ENTRIES       256
#define AKAV_PDF_MAX_EMBEDDED         256
#define AKAV_PDF_MAX_FILTERS          8
#define AKAV_PDF_MAX_DECOMPRESSED     (100 * 1024 * 1024)  /* 100 MB */
#define AKAV_PDF_MAX_NAME_LEN         256

/* ── Filter types ──────────────────────────────────────────────── */

typedef enum {
    AKAV_PDF_FILTER_NONE = 0,
    AKAV_PDF_FILTER_FLATE,        /* /FlateDecode */
    AKAV_PDF_FILTER_ASCII85,      /* /ASCII85Decode */
    AKAV_PDF_FILTER_ASCIIHEX,     /* /ASCIIHexDecode */
    AKAV_PDF_FILTER_LZW,          /* /LZWDecode */
    AKAV_PDF_FILTER_UNKNOWN
} akav_pdf_filter_t;

/* ── Cross-reference entry ─────────────────────────────────────── */

typedef struct {
    uint32_t obj_num;
    uint32_t gen_num;
    uint64_t offset;
    bool     in_use;
    bool     compressed;      /* in an object stream (PDF 1.5+) */
    uint32_t stream_obj;      /* containing ObjStm obj number */
    uint32_t stream_idx;      /* index within ObjStm */
} akav_pdf_xref_entry_t;

/* ── Extracted JavaScript ──────────────────────────────────────── */

typedef struct {
    uint32_t source_obj;
    uint8_t* data;            /* heap-allocated, null-terminated */
    size_t   data_len;
    char     trigger[64];     /* e.g. "OpenAction", "AA", "Names" */
} akav_pdf_js_entry_t;

/* ── Extracted embedded file ───────────────────────────────────── */

typedef struct {
    char     filename[AKAV_PDF_MAX_NAME_LEN];
    uint32_t source_obj;
    uint8_t* data;            /* heap-allocated decompressed content */
    size_t   data_len;
} akav_pdf_embedded_file_t;

/* ── Parsed PDF ────────────────────────────────────────────────── */

typedef struct {
    /* PDF version */
    uint8_t  major_version;
    uint8_t  minor_version;

    /* Cross-reference info */
    uint32_t num_xref_tables;
    bool     has_xref_streams;

    /* Object directory */
    akav_pdf_xref_entry_t* objects;        /* heap-allocated */
    uint32_t               num_objects;

    /* Catalog object number */
    uint32_t catalog_obj;

    /* Extracted JavaScript */
    akav_pdf_js_entry_t*   js_entries;     /* heap-allocated */
    uint32_t               num_js;

    /* Extracted embedded files */
    akav_pdf_embedded_file_t* embedded_files; /* heap-allocated */
    uint32_t                  num_embedded;

    /* Suspicious indicators */
    bool     has_javascript;
    bool     has_open_action;
    bool     has_auto_action;
    bool     has_launch_action;
    bool     has_embedded_files;
    bool     has_acroform;
    bool     has_encrypted;

    /* Parse status */
    bool     valid;
    char     error[128];
    int      warning_count;
    char     warnings[4][128];
} akav_pdf_t;

/**
 * Parse a PDF file from a buffer. Locates %PDF header, parses
 * startxref/xref chain, builds object directory. Supports both
 * traditional xref tables and xref streams (PDF 1.5+).
 *
 * Returns true if the basic structure was successfully parsed.
 */
bool akav_pdf_parse(akav_pdf_t* pdf, const uint8_t* data, size_t data_len);

/**
 * Free all heap-allocated data in the PDF struct.
 * Safe to call on a zeroed or partially-parsed pdf.
 */
void akav_pdf_free(akav_pdf_t* pdf);

/**
 * Extract JavaScript from the document.
 * Searches /OpenAction, /AA, /JavaScript name tree, annotation actions.
 * Populates pdf->js_entries and pdf->num_js.
 */
bool akav_pdf_extract_js(akav_pdf_t* pdf, const uint8_t* data, size_t data_len);

/**
 * Extract embedded files from the /EmbeddedFiles name tree.
 * Populates pdf->embedded_files and pdf->num_embedded.
 */
bool akav_pdf_extract_embedded(akav_pdf_t* pdf, const uint8_t* data, size_t data_len);

/**
 * Decompress a stream with a filter chain.
 * On success, *out_data is malloc'd (caller frees), *out_len is set.
 */
bool akav_pdf_decompress_stream(const uint8_t* stream_data, size_t stream_len,
                                 const akav_pdf_filter_t* filters,
                                 uint32_t num_filters,
                                 uint8_t** out_data, size_t* out_len);

/**
 * Convenience: parse + extract JS + extract embedded files + set flags.
 */
void akav_pdf_analyze(akav_pdf_t* pdf, const uint8_t* data, size_t data_len);

/* ── Individual filter decoders (exposed for testing) ──────────── */

bool akav_pdf_decode_flate(const uint8_t* in, size_t in_len,
                            uint8_t** out, size_t* out_len);
bool akav_pdf_decode_ascii85(const uint8_t* in, size_t in_len,
                              uint8_t** out, size_t* out_len);
bool akav_pdf_decode_asciihex(const uint8_t* in, size_t in_len,
                               uint8_t** out, size_t* out_len);
bool akav_pdf_decode_lzw(const uint8_t* in, size_t in_len,
                          uint8_t** out, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_PDF_H */
