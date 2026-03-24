#ifndef AKAV_OOXML_H
#define AKAV_OOXML_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── OOXML Parser (P10-T4) ──────────────────────────────────────── */

/*
 * OOXML files (.docx, .xlsx, .pptx) are ZIP archives with:
 *   [Content_Types].xml  — declares content parts
 *   word/document.xml    — main document content
 *   word/vbaProject.bin  — OLE2 container with VBA macros (optional)
 *   word/media/*         — embedded images/media
 *   word/embeddings/*    — embedded OLE objects
 *
 * This parser:
 *   1. Extracts the ZIP
 *   2. Detects OOXML via [Content_Types].xml
 *   3. Finds vbaProject.bin → feeds to OLE2 parser for VBA extraction
 *   4. Collects embedded files from media/ and embeddings/ directories
 *   5. Reports OOXML type (docx/xlsx/pptx) based on content types
 */

#define AKAV_OOXML_MAX_EMBEDDED   64
#define AKAV_OOXML_MAX_VBA_MODULES 32

/** OOXML document type */
typedef enum {
    AKAV_OOXML_UNKNOWN = 0,
    AKAV_OOXML_DOCX    = 1,
    AKAV_OOXML_XLSX    = 2,
    AKAV_OOXML_PPTX    = 3,
} akav_ooxml_type_t;

/** An embedded file extracted from media/ or embeddings/ */
typedef struct {
    char     filename[256];
    uint8_t* data;
    size_t   data_len;
} akav_ooxml_embedded_t;

/** VBA module extracted from vbaProject.bin */
typedef struct {
    char     name[128];
    uint8_t* source;
    size_t   source_len;
} akav_ooxml_vba_module_t;

/** OOXML parse result */
typedef struct {
    akav_ooxml_type_t       type;
    bool                    is_ooxml;       /* True if [Content_Types].xml found */
    bool                    has_macros;     /* True if vbaProject.bin found */
    bool                    has_vba;        /* True if VBA source extracted */

    /* Extracted VBA modules */
    akav_ooxml_vba_module_t vba_modules[AKAV_OOXML_MAX_VBA_MODULES];
    uint32_t                num_vba_modules;

    /* Embedded files from media/ and embeddings/ */
    akav_ooxml_embedded_t   embedded[AKAV_OOXML_MAX_EMBEDDED];
    uint32_t                num_embedded;

    char                    error[128];
} akav_ooxml_result_t;

/**
 * Parse an OOXML document from a buffer (ZIP data).
 * Extracts VBA macros and embedded files.
 * Returns true if the file is a valid OOXML document.
 */
bool akav_ooxml_parse(const uint8_t* data, size_t data_len,
                       akav_ooxml_result_t* result);

/**
 * Check if a buffer looks like an OOXML document (quick check).
 * Verifies ZIP magic + presence of [Content_Types].xml.
 */
bool akav_ooxml_detect(const uint8_t* data, size_t data_len);

/**
 * Free all allocated memory in the result.
 */
void akav_ooxml_free(akav_ooxml_result_t* result);

/**
 * Return human-readable name for OOXML type.
 */
const char* akav_ooxml_type_name(akav_ooxml_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_OOXML_H */
