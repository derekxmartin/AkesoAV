/*
 * AkesoAV - OOXML Parser (P10-T4)
 *
 * Parses Office Open XML documents (.docx, .xlsx, .pptx):
 *   1. ZIP extraction
 *   2. [Content_Types].xml detection → OOXML type identification
 *   3. vbaProject.bin → OLE2 parser for VBA macro extraction
 *   4. Embedded files from media/ and embeddings/ directories
 */

#include "parsers/ooxml.h"
#include "parsers/zip.h"
#include "parsers/ole2.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ── Helpers ────────────────────────────────────────────────────── */

static bool str_starts_with_ci(const char* s, const char* prefix)
{
    while (*prefix) {
        char a = *s++;
        char b = *prefix++;
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

static bool str_contains(const char* haystack, const char* needle)
{
    return strstr(haystack, needle) != NULL;
}

/* Detect OOXML type from [Content_Types].xml content */
static akav_ooxml_type_t detect_type_from_content_types(const char* xml, size_t len)
{
    /* Look for content type strings that identify the document type */
    /* Word: application/vnd.openxmlformats-officedocument.wordprocessingml */
    /* Excel: application/vnd.openxmlformats-officedocument.spreadsheetml */
    /* PowerPoint: application/vnd.openxmlformats-officedocument.presentationml */

    /* Simple substring search in the XML content */
    const char* end = xml + len;
    (void)end;

    if (str_contains(xml, "wordprocessingml"))
        return AKAV_OOXML_DOCX;
    if (str_contains(xml, "spreadsheetml"))
        return AKAV_OOXML_XLSX;
    if (str_contains(xml, "presentationml"))
        return AKAV_OOXML_PPTX;

    return AKAV_OOXML_UNKNOWN;
}

/* ── ZIP entry callback context ─────────────────────────────────── */

typedef struct {
    akav_ooxml_result_t* result;
    bool                 found_content_types;
    /* Buffer for vbaProject.bin (extracted from ZIP, fed to OLE2) */
    uint8_t*             vba_project_data;
    size_t               vba_project_len;
} ooxml_extract_ctx_t;

static bool is_embedded_path(const char* filename)
{
    return str_starts_with_ci(filename, "word/media/") ||
           str_starts_with_ci(filename, "word/embeddings/") ||
           str_starts_with_ci(filename, "xl/media/") ||
           str_starts_with_ci(filename, "xl/embeddings/") ||
           str_starts_with_ci(filename, "ppt/media/") ||
           str_starts_with_ci(filename, "ppt/embeddings/");
}

static bool is_vba_project(const char* filename)
{
    /* vbaProject.bin can appear in word/, xl/, or ppt/ */
    const char* base = strrchr(filename, '/');
    if (!base) base = filename; else base++;

    /* Case-insensitive compare */
    return (str_starts_with_ci(base, "vbaProject.bin") ||
            str_starts_with_ci(base, "vbaproject.bin"));
}

/* ZIP entry callback for OOXML extraction */
static bool ooxml_zip_callback(const char* filename, const uint8_t* data,
                                size_t data_len, int depth, void* user_data)
{
    (void)depth;
    ooxml_extract_ctx_t* ctx = (ooxml_extract_ctx_t*)user_data;
    akav_ooxml_result_t* result = ctx->result;

    /* 1. [Content_Types].xml — identifies this as OOXML */
    if (strcmp(filename, "[Content_Types].xml") == 0) {
        ctx->found_content_types = true;
        result->is_ooxml = true;

        /* Detect document type from content */
        if (data_len > 0 && data_len < 1024 * 1024) {
            /* Ensure null-terminated for string search */
            char* xml_copy = (char*)malloc(data_len + 1);
            if (xml_copy) {
                memcpy(xml_copy, data, data_len);
                xml_copy[data_len] = '\0';
                result->type = detect_type_from_content_types(xml_copy, data_len);
                free(xml_copy);
            }
        }
        return true;  /* Continue extraction */
    }

    /* 2. vbaProject.bin — OLE2 container with VBA macros */
    if (is_vba_project(filename)) {
        result->has_macros = true;

        /* Save for OLE2 parsing after ZIP extraction completes */
        if (!ctx->vba_project_data && data_len > 0) {
            ctx->vba_project_data = (uint8_t*)malloc(data_len);
            if (ctx->vba_project_data) {
                memcpy(ctx->vba_project_data, data, data_len);
                ctx->vba_project_len = data_len;
            }
        }
        return true;
    }

    /* 3. Embedded files from media/ and embeddings/ */
    if (is_embedded_path(filename) && data_len > 0) {
        if (result->num_embedded < AKAV_OOXML_MAX_EMBEDDED) {
            akav_ooxml_embedded_t* emb = &result->embedded[result->num_embedded];
            snprintf(emb->filename, sizeof(emb->filename), "%s", filename);
            emb->data = (uint8_t*)malloc(data_len);
            if (emb->data) {
                memcpy(emb->data, data, data_len);
                emb->data_len = data_len;
                result->num_embedded++;
            }
        }
        return true;
    }

    return true;  /* Continue to next entry */
}

/* ── Public API ─────────────────────────────────────────────────── */

bool akav_ooxml_parse(const uint8_t* data, size_t data_len,
                       akav_ooxml_result_t* result)
{
    if (!data || !result || data_len < 4)
        return false;

    memset(result, 0, sizeof(*result));

    /* Quick check: must start with PK (ZIP magic) */
    if (data[0] != 0x50 || data[1] != 0x4B)
        return false;

    /* Extract ZIP contents */
    akav_zip_context_t zip_ctx;
    akav_zip_init(&zip_ctx, 0);

    ooxml_extract_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.result = result;

    akav_zip_extract(&zip_ctx, data, data_len, ooxml_zip_callback, &ctx);

    if (zip_ctx.error[0]) {
        snprintf(result->error, sizeof(result->error), "ZIP: %s", zip_ctx.error);
    }

    if (!ctx.found_content_types) {
        /* Not an OOXML document */
        free(ctx.vba_project_data);
        return false;
    }

    /* Parse vbaProject.bin through OLE2 if present (min OLE2 header = 512 bytes) */
    if (ctx.vba_project_data && ctx.vba_project_len >= 512) {
        akav_ole2_t ole2;
        memset(&ole2, 0, sizeof(ole2));

        if (akav_ole2_parse(&ole2, ctx.vba_project_data, ctx.vba_project_len)) {
            akav_ole2_extract_vba(&ole2, ctx.vba_project_data, ctx.vba_project_len);

            if (ole2.has_vba && ole2.num_vba_modules > 0) {
                result->has_vba = true;

                for (uint32_t i = 0; i < ole2.num_vba_modules &&
                     result->num_vba_modules < AKAV_OOXML_MAX_VBA_MODULES; i++) {
                    akav_ooxml_vba_module_t* dst =
                        &result->vba_modules[result->num_vba_modules];

                    snprintf(dst->name, sizeof(dst->name), "%s",
                             ole2.vba_modules[i].module_name);

                    if (ole2.vba_modules[i].source_len > 0) {
                        dst->source = (uint8_t*)malloc(ole2.vba_modules[i].source_len);
                        if (dst->source) {
                            memcpy(dst->source, ole2.vba_modules[i].source,
                                   ole2.vba_modules[i].source_len);
                            dst->source_len = ole2.vba_modules[i].source_len;
                        }
                    }
                    result->num_vba_modules++;
                }
            }
        }

        akav_ole2_free(&ole2);
        free(ctx.vba_project_data);
    }

    return true;
}

bool akav_ooxml_detect(const uint8_t* data, size_t data_len)
{
    if (!data || data_len < 30)
        return false;

    /* Must be a ZIP file */
    if (data[0] != 0x50 || data[1] != 0x4B)
        return false;

    /* Quick scan: look for "[Content_Types].xml" in the first few KB.
     * This string appears as a filename in the ZIP local file headers. */
    const char* needle = "[Content_Types].xml";
    size_t needle_len = strlen(needle);
    size_t scan_len = data_len < 8192 ? data_len : 8192;

    for (size_t i = 0; i + needle_len <= scan_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0)
            return true;
    }
    return false;
}

void akav_ooxml_free(akav_ooxml_result_t* result)
{
    if (!result) return;

    for (uint32_t i = 0; i < result->num_vba_modules; i++) {
        free(result->vba_modules[i].source);
    }
    for (uint32_t i = 0; i < result->num_embedded; i++) {
        free(result->embedded[i].data);
    }
    memset(result, 0, sizeof(*result));
}

const char* akav_ooxml_type_name(akav_ooxml_type_t type)
{
    switch (type) {
    case AKAV_OOXML_DOCX: return "docx";
    case AKAV_OOXML_XLSX: return "xlsx";
    case AKAV_OOXML_PPTX: return "pptx";
    default:              return "unknown";
    }
}
