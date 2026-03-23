#include "engine_internal.h"
#include "file_type.h"
#include "parsers/safe_reader.h"
#include "parsers/zip.h"
#include "parsers/gzip.h"
#include "parsers/tar.h"
#include "signatures/hash_matcher.h"
#include "unpacker/upx.h"
#include "parsers/pdf.h"
#include "parsers/ole2.h"
#include "siem/event_serialize.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>
#include <cstdio>
#include <chrono>

namespace akav
{

Engine::Engine()
    : cache_(std::make_unique<ScanCache>())
    , whitelist_(std::make_unique<Whitelist>())
    , siem_(std::make_unique<SiemShipper>())
{
    akav_scanner_init(&scanner_);
    akav_plugin_manager_init(&plugin_mgr_);

    /* Default trusted signers per section 5.4 */
    whitelist_->add_signer("Microsoft Corporation");
    whitelist_->add_signer("Microsoft Windows");
}

Engine::~Engine()
{
    akav_plugin_manager_destroy(&plugin_mgr_);
    akav_scanner_destroy(&scanner_);
}

akav_error_t Engine::load_plugins(const char* plugin_dir)
{
    if (!plugin_dir)
        return AKAV_ERROR_INVALID;

    int loaded = akav_plugin_manager_load_dir(&plugin_mgr_, plugin_dir);
    plugins_loaded_ = (plugin_mgr_.count > 0);

    fprintf(stderr, "[engine] Loaded %d plugin(s) from '%s'\n", loaded, plugin_dir);
    return AKAV_OK;
}

akav_error_t Engine::init(const char* config_path)
{
    if (config_path)
        config_path_ = config_path;
    db_version_str_ = "none";
    initialized_.store(true, std::memory_order_release);
    return AKAV_OK;
}

akav_error_t Engine::load_signatures(const char* db_path)
{
    if (!is_initialized())
        return AKAV_ERROR_NOT_INIT;
    if (!db_path)
        return AKAV_ERROR_INVALID;

    /* Tear down previous scanner state if reloading */
    if (scanner_loaded_) {
        akav_scanner_destroy(&scanner_);
        akav_scanner_init(&scanner_);
        scanner_loaded_ = false;
    }

    /* Clear scan cache — new signatures may change verdicts */
    if (cache_)
        cache_->clear();

    akav_error_t err = akav_scanner_load(&scanner_, db_path);
    if (err != AKAV_OK)
        return err;

    scanner_loaded_ = true;

    /* Update db version string */
    char version_buf[64];
    snprintf(version_buf, sizeof(version_buf), "v%u (%u sigs)",
             scanner_.sigdb.header->version,
             scanner_.total_signatures);
    db_version_str_ = version_buf;

    return AKAV_OK;
}

akav_error_t Engine::scan_buffer(const uint8_t* buf, size_t len, const char* name,
                                 const akav_scan_options_t* opts, akav_scan_result_t* result)
{
    if (!is_initialized())
        return AKAV_ERROR_NOT_INIT;
    if (!buf && len > 0)
        return AKAV_ERROR_INVALID;
    if (!result)
        return AKAV_ERROR_INVALID;

    auto start = std::chrono::steady_clock::now();

    /* Zero out result */
    memset(result, 0, sizeof(*result));
    result->total_size = (int64_t)len;
    result->scanned_size = (int64_t)len;

    /* Use default options if none provided */
    akav_scan_options_t defaults;
    akav_scan_options_default(&defaults);
    if (!opts)
        opts = &defaults;

    /* Detect file type */
    akav_file_type_t ftype = akav_detect_file_type(buf, len);
    const char* ftype_str = akav_file_type_name(ftype);
    strncpy_s(result->file_type, sizeof(result->file_type), ftype_str, _TRUNCATE);

    /* Run signature scan pipeline (Bloom → MD5 → SHA256 → CRC32 → Fuzzy → Aho-Corasick) */
    if (scanner_loaded_)
    {
        akav_scanner_scan_buffer(&scanner_, buf, len, result);
    }

    /* Run plugin scanners (after built-in pipeline, before unpacker/heuristics) */
    if (!result->found && plugins_loaded_) {
        akav_plugin_manager_scan(&plugin_mgr_, buf, len, opts, result);
    }

    /* If not yet detected and packing analysis enabled, try UPX unpack on PE files */
    if (!result->found && opts->scan_packed && ftype == AKAV_FILETYPE_PE)
    {
        akav_upx_info_t upx_info;
        if (akav_upx_detect(buf, len, &upx_info))
        {
            uint8_t* unpacked = nullptr;
            size_t unpacked_len = 0;
            if (akav_upx_unpack(buf, len, &unpacked, &unpacked_len, &upx_info))
            {
                /* Scan unpacked buffer through full pipeline (with scan_packed=0
                 * to prevent infinite recursion) */
                akav_scan_options_t inner_opts = *opts;
                inner_opts.scan_packed = 0;
                akav_scan_result_t inner_result;
                scan_buffer(unpacked, unpacked_len, name, &inner_opts, &inner_result);

                if (inner_result.found) {
                    *result = inner_result;
                    /* Annotate that detection came from unpacked content */
                    char packed_note[64];
                    snprintf(packed_note, sizeof(packed_note), "upx:%s",
                             inner_result.scanner_id);
                    strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                              packed_note, _TRUNCATE);
                }
                free(unpacked);
            }
        }
    }

    /* If not yet detected and file is PDF, extract and scan streams/JS/embedded */
    if (!result->found && ftype == AKAV_FILETYPE_PDF)
    {
        akav_pdf_t pdf;
        if (akav_pdf_parse(&pdf, buf, len))
        {
            akav_pdf_analyze(&pdf, buf, len);

            /* Scan decompressed streams for signatures */
            for (uint32_t i = 0; i < pdf.num_objects && !result->found; i++)
            {
                if (!pdf.objects[i].in_use || pdf.objects[i].compressed)
                    continue;

                size_t obj_off = (size_t)pdf.objects[i].offset;
                if (obj_off >= len) continue;

                /* Find stream within this object */
                size_t stream_kw = 0;
                for (size_t s = obj_off; s + 6 < len; s++) {
                    if (memcmp(buf + s, "stream", 6) == 0) {
                        stream_kw = s;
                        break;
                    }
                    if (memcmp(buf + s, "endobj", 6) == 0) break;
                }
                if (stream_kw == 0) continue;

                /* Find the dictionary start for this object */
                size_t dict_s = 0;
                for (size_t d = obj_off; d + 1 < stream_kw; d++) {
                    if (buf[d] == '<' && buf[d+1] == '<') { dict_s = d; break; }
                }
                if (dict_s == 0) continue;

                /* Parse filters and stream location */
                size_t stream_start, stream_length;
                akav_pdf_filter_t filters[AKAV_PDF_MAX_FILTERS];
                uint32_t num_filters;

                /* Minimal inline get_object_stream logic using public API */
                /* Find /Length */
                int64_t slen = -1;
                for (size_t p = dict_s; p + 7 < stream_kw; p++) {
                    if (memcmp(buf + p, "/Length", 7) == 0) {
                        size_t np = p + 7;
                        while (np < stream_kw && (buf[np] == ' ' || buf[np] == '\t' ||
                               buf[np] == '\r' || buf[np] == '\n')) np++;
                        slen = 0;
                        while (np < stream_kw && buf[np] >= '0' && buf[np] <= '9') {
                            slen = slen * 10 + (buf[np] - '0');
                            np++;
                        }
                        break;
                    }
                }
                if (slen <= 0) continue;

                /* Locate stream body */
                stream_start = stream_kw + 6;
                if (stream_start < len && buf[stream_start] == '\r') stream_start++;
                if (stream_start < len && buf[stream_start] == '\n') stream_start++;
                stream_length = (size_t)slen;
                if (stream_start + stream_length > len) continue;

                /* Detect /Filter */
                num_filters = 0;
                for (size_t p = dict_s; p + 7 < stream_kw; p++) {
                    if (memcmp(buf + p, "/Filter", 7) == 0) {
                        size_t fp = p + 7;
                        while (fp < stream_kw && buf[fp] == ' ') fp++;
                        if (fp < stream_kw && buf[fp] == '/') {
                            fp++;
                            if (fp + 11 <= stream_kw && memcmp(buf + fp, "FlateDecode", 11) == 0)
                                filters[num_filters++] = AKAV_PDF_FILTER_FLATE;
                            else if (fp + 13 <= stream_kw && memcmp(buf + fp, "ASCII85Decode", 13) == 0)
                                filters[num_filters++] = AKAV_PDF_FILTER_ASCII85;
                            else if (fp + 14 <= stream_kw && memcmp(buf + fp, "ASCIIHexDecode", 14) == 0)
                                filters[num_filters++] = AKAV_PDF_FILTER_ASCIIHEX;
                            else if (fp + 9 <= stream_kw && memcmp(buf + fp, "LZWDecode", 9) == 0)
                                filters[num_filters++] = AKAV_PDF_FILTER_LZW;
                        }
                        break;
                    }
                }

                uint8_t* decoded = nullptr;
                size_t decoded_len = 0;
                if (akav_pdf_decompress_stream(buf + stream_start, stream_length,
                                                filters, num_filters,
                                                &decoded, &decoded_len))
                {
                    akav_scan_options_t inner_opts = *opts;
                    inner_opts.scan_archives = 0;
                    akav_scan_result_t inner_result;
                    memset(&inner_result, 0, sizeof(inner_result));
                    scan_buffer(decoded, decoded_len, name, &inner_opts, &inner_result);
                    if (inner_result.found) {
                        *result = inner_result;
                        char note[64];
                        snprintf(note, sizeof(note), "pdf:%s", inner_result.scanner_id);
                        strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                                  note, _TRUNCATE);
                    }
                    free(decoded);
                }
            }

            /* Scan extracted JavaScript */
            for (uint32_t i = 0; i < pdf.num_js && !result->found; i++)
            {
                akav_scan_options_t inner_opts = *opts;
                inner_opts.scan_archives = 0;
                akav_scan_result_t inner_result;
                memset(&inner_result, 0, sizeof(inner_result));
                scan_buffer(pdf.js_entries[i].data, pdf.js_entries[i].data_len,
                            name, &inner_opts, &inner_result);
                if (inner_result.found) {
                    *result = inner_result;
                    char note[64];
                    snprintf(note, sizeof(note), "pdf-js:%s", inner_result.scanner_id);
                    strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                              note, _TRUNCATE);
                }
            }

            /* Scan extracted embedded files */
            for (uint32_t i = 0; i < pdf.num_embedded && !result->found; i++)
            {
                akav_scan_options_t inner_opts = *opts;
                inner_opts.scan_archives = 0;
                akav_scan_result_t inner_result;
                memset(&inner_result, 0, sizeof(inner_result));
                scan_buffer(pdf.embedded_files[i].data, pdf.embedded_files[i].data_len,
                            name, &inner_opts, &inner_result);
                if (inner_result.found) {
                    *result = inner_result;
                    char note[64];
                    snprintf(note, sizeof(note), "pdf-embed:%s", inner_result.scanner_id);
                    strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                              note, _TRUNCATE);
                }
            }

            akav_pdf_free(&pdf);
        }
    }

    /* If not yet detected and file is OLE2, extract and scan streams + VBA */
    if (!result->found && ftype == AKAV_FILETYPE_OLE2)
    {
        akav_ole2_t ole2;
        memset(&ole2, 0, sizeof(ole2));
        akav_ole2_analyze(&ole2, buf, len);

        if (ole2.valid)
        {
            /* Scan extracted streams */
            for (uint32_t i = 0; i < ole2.num_streams && !result->found; i++)
            {
                if (ole2.streams[i].data && ole2.streams[i].data_len > 0)
                {
                    akav_scan_options_t inner_opts = *opts;
                    inner_opts.scan_archives = 0;
                    akav_scan_result_t inner_result;
                    memset(&inner_result, 0, sizeof(inner_result));
                    scan_buffer(ole2.streams[i].data, ole2.streams[i].data_len,
                                name, &inner_opts, &inner_result);
                    if (inner_result.found) {
                        *result = inner_result;
                        char note[64];
                        snprintf(note, sizeof(note), "ole2:%s",
                                 inner_result.scanner_id);
                        strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                                  note, _TRUNCATE);
                    }
                }
            }

            /* Scan extracted VBA module source code */
            for (uint32_t i = 0; i < ole2.num_vba_modules && !result->found; i++)
            {
                if (ole2.vba_modules[i].source && ole2.vba_modules[i].source_len > 0)
                {
                    akav_scan_options_t inner_opts = *opts;
                    inner_opts.scan_archives = 0;
                    akav_scan_result_t inner_result;
                    memset(&inner_result, 0, sizeof(inner_result));
                    scan_buffer(ole2.vba_modules[i].source,
                                ole2.vba_modules[i].source_len,
                                name, &inner_opts, &inner_result);
                    if (inner_result.found) {
                        *result = inner_result;
                        char note[64];
                        snprintf(note, sizeof(note), "ole2-vba:%s",
                                 inner_result.scanner_id);
                        strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                                  note, _TRUNCATE);
                    }
                }
            }
        }

        akav_ole2_free(&ole2);
    }

    /* If not yet detected and heuristics enabled, run heuristic pipeline on PE files */
    if (!result->found && opts->use_heuristics &&
        opts->heuristic_level != AKAV_HEUR_OFF)
    {
        /* Ensure weights are loaded (lazy init, safe to call multiple times) */
        if (!scanner_.heuristic_weights_loaded) {
            akav_scanner_load_heuristic_weights(&scanner_, "config");
        }

        akav_scanner_run_heuristics(&scanner_, buf, len,
                                     opts->heuristic_level, result);
    }

    /* If not yet detected and archive scanning is enabled, recurse into archives */
    if (!result->found && opts->scan_archives)
    {
        akav_error_t arc_err = AKAV_OK;

        if (ftype == AKAV_FILETYPE_ZIP)
            arc_err = scan_archive_zip(buf, len, opts, result, 0);
        else if (ftype == AKAV_FILETYPE_GZIP)
            arc_err = scan_archive_gzip(buf, len, opts, result, 0);
        else if (ftype == AKAV_FILETYPE_TAR)
            arc_err = scan_archive_tar(buf, len, opts, result, 0);

        if (arc_err == AKAV_ERROR_BOMB)
        {
            auto end = std::chrono::steady_clock::now();
            result->scan_time_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            return AKAV_ERROR_BOMB;
        }
    }

    auto end = std::chrono::steady_clock::now();
    result->scan_time_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    /* Emit SIEM event for detections (buffer scans) */
    if (result->found && siem_) {
        ScanResultPayload srp{};
        srp.result = "malicious";
        srp.scanner_id = result->scanner_id;
        srp.scan_type = "on_demand";
        srp.heuristic_score = result->heuristic_score;
        srp.duration_ms = (uint64_t)result->scan_time_ms;
        srp.sig_name = result->malware_name;
        srp.sig_id = result->signature_id;
        srp.sig_engine = result->scanner_id;
        srp.db_version = db_version_str_;
        srp.file_name = name ? name : "";
        srp.file_type = result->file_type;
        srp.file_size = (uint64_t)result->total_size;
        srp.in_whitelist = (result->in_whitelist != 0);

        akav_siem_event_t siem_event;
        serialize_scan_result(srp, &siem_event);
        siem_->submit(siem_event);
    }

    return AKAV_OK;
}

/* ── ZIP archive recursive scanning ──────────────────────────────── */

struct zip_scan_ctx {
    akav::Engine*              engine;
    const akav_scan_options_t* opts;
    akav_scan_result_t*        result;
    int                        depth;
    bool                       bomb;
};

static bool zip_entry_callback(const char* filename, const uint8_t* data,
                                size_t data_len, int depth, void* user_data)
{
    auto* ctx = (zip_scan_ctx*)user_data;
    (void)filename;

    /* Scan the extracted entry through the signature pipeline */
    akav_scan_result_t entry_result;
    memset(&entry_result, 0, sizeof(entry_result));

    if (ctx->engine->is_initialized()) {
        /* Run signature scan on the entry (archives disabled — we handle
         * nested ZIP recursion explicitly below with proper depth tracking) */
        akav_scan_options_t entry_opts = *ctx->opts;
        entry_opts.scan_archives = 0;
        akav_error_t err = ctx->engine->scan_buffer(
            data, data_len, filename, &entry_opts, &entry_result);

        if (err == AKAV_ERROR_BOMB) {
            ctx->bomb = true;
            return false; /* Stop extraction */
        }

        if (entry_result.found) {
            /* Propagate detection to parent result */
            ctx->result->found = 1;
            memcpy(ctx->result->malware_name, entry_result.malware_name,
                   sizeof(ctx->result->malware_name));
            memcpy(ctx->result->signature_id, entry_result.signature_id,
                   sizeof(ctx->result->signature_id));
            memcpy(ctx->result->scanner_id, entry_result.scanner_id,
                   sizeof(ctx->result->scanner_id));
            return false; /* Stop: malware found */
        }

        /* Check if this entry is itself a ZIP (nested) */
        akav_file_type_t inner_type = akav_detect_file_type(data, data_len);
        if (inner_type == AKAV_FILETYPE_ZIP && ctx->opts->scan_archives) {
            akav_error_t zip_err = ctx->engine->scan_archive_zip(
                data, data_len, ctx->opts, ctx->result, depth);
            if (zip_err == AKAV_ERROR_BOMB) {
                ctx->bomb = true;
                return false;
            }
            if (ctx->result->found)
                return false;
        }
    }

    return true; /* Continue extraction */
}

akav_error_t Engine::scan_archive_zip(const uint8_t* buf, size_t len,
                                       const akav_scan_options_t* opts,
                                       akav_scan_result_t* result, int depth)
{
    if (depth >= opts->max_scan_depth)
        return AKAV_OK; /* Depth limit reached — stop silently */

    akav_zip_context_t zip_ctx;
    akav_zip_init(&zip_ctx, depth);

    zip_scan_ctx scan_ctx;
    scan_ctx.engine = this;
    scan_ctx.opts = opts;
    scan_ctx.result = result;
    scan_ctx.depth = depth;
    scan_ctx.bomb = false;

    bool ok = akav_zip_extract(&zip_ctx, buf, len, zip_entry_callback, &scan_ctx);

    if (scan_ctx.bomb || zip_ctx.bomb_detected)
        return AKAV_ERROR_BOMB;

    if (!ok && !result->found) {
        /* Extraction failed but not due to bomb — add warning */
        if (result->warning_count < AKAV_MAX_WARNINGS) {
            strncpy_s(result->warnings[result->warning_count],
                      AKAV_MAX_WARNING_LEN, zip_ctx.error, _TRUNCATE);
            result->warning_count++;
        }
    }

    return AKAV_OK;
}

/* ── GZIP archive scanning ──────────────────────────────────────── */

akav_error_t Engine::scan_archive_gzip(const uint8_t* buf, size_t len,
                                        const akav_scan_options_t* opts,
                                        akav_scan_result_t* result, int depth)
{
    if (depth >= opts->max_scan_depth)
        return AKAV_OK;

    akav_gzip_context_t gz_ctx;
    akav_gzip_init(&gz_ctx);

    uint8_t* decompressed = nullptr;
    size_t   decomp_len = 0;

    bool ok = akav_gzip_decompress(&gz_ctx, buf, len, &decompressed, &decomp_len);
    if (!ok) {
        if (gz_ctx.bomb_detected)
            return AKAV_ERROR_BOMB;
        /* Corrupt gzip — add warning */
        if (result->warning_count < AKAV_MAX_WARNINGS) {
            strncpy_s(result->warnings[result->warning_count],
                      AKAV_MAX_WARNING_LEN, gz_ctx.error, _TRUNCATE);
            result->warning_count++;
        }
        return AKAV_OK;
    }

    /* Scan the decompressed content through the pipeline */
    akav_scan_options_t inner_opts = *opts;
    inner_opts.scan_archives = 0; /* we handle recursion below */

    akav_scan_result_t inner_result;
    memset(&inner_result, 0, sizeof(inner_result));
    akav_error_t err = scan_buffer(decompressed, decomp_len, "gzip-inner",
                                    &inner_opts, &inner_result);

    if (err == AKAV_ERROR_BOMB) {
        free(decompressed);
        return AKAV_ERROR_BOMB;
    }

    if (inner_result.found) {
        result->found = 1;
        memcpy(result->malware_name, inner_result.malware_name,
               sizeof(result->malware_name));
        memcpy(result->signature_id, inner_result.signature_id,
               sizeof(result->signature_id));
        memcpy(result->scanner_id, inner_result.scanner_id,
               sizeof(result->scanner_id));
        free(decompressed);
        return AKAV_OK;
    }

    /* Check if decompressed data is another archive (e.g., .tar inside .tar.gz) */
    akav_file_type_t inner_type = akav_detect_file_type(decompressed, decomp_len);
    if (inner_type == AKAV_FILETYPE_TAR && opts->scan_archives) {
        err = scan_archive_tar(decompressed, decomp_len, opts, result, depth + 1);
    } else if (inner_type == AKAV_FILETYPE_ZIP && opts->scan_archives) {
        err = scan_archive_zip(decompressed, decomp_len, opts, result, depth + 1);
    } else if (inner_type == AKAV_FILETYPE_GZIP && opts->scan_archives) {
        err = scan_archive_gzip(decompressed, decomp_len, opts, result, depth + 1);
    }

    free(decompressed);
    return err;
}

/* ── TAR archive scanning ───────────────────────────────────────── */

struct tar_scan_ctx {
    akav::Engine*              engine;
    const akav_scan_options_t* opts;
    akav_scan_result_t*        result;
    int                        depth;
    bool                       bomb;
};

static bool tar_entry_callback(const char* filename, const uint8_t* data,
                                size_t data_len, void* user_data)
{
    auto* ctx = (tar_scan_ctx*)user_data;
    (void)filename;

    /* Scan extracted entry (no archive recursion — we handle it here) */
    akav_scan_options_t entry_opts = *ctx->opts;
    entry_opts.scan_archives = 0;

    akav_scan_result_t entry_result;
    memset(&entry_result, 0, sizeof(entry_result));

    akav_error_t err = ctx->engine->scan_buffer(
        data, data_len, filename, &entry_opts, &entry_result);

    if (err == AKAV_ERROR_BOMB) {
        ctx->bomb = true;
        return false;
    }

    if (entry_result.found) {
        ctx->result->found = 1;
        memcpy(ctx->result->malware_name, entry_result.malware_name,
               sizeof(ctx->result->malware_name));
        memcpy(ctx->result->signature_id, entry_result.signature_id,
               sizeof(ctx->result->signature_id));
        memcpy(ctx->result->scanner_id, entry_result.scanner_id,
               sizeof(ctx->result->scanner_id));
        return false; /* Stop: malware found */
    }

    /* Check if entry is itself an archive */
    akav_file_type_t inner_type = akav_detect_file_type(data, data_len);
    akav_error_t arc_err = AKAV_OK;
    if (ctx->opts->scan_archives) {
        if (inner_type == AKAV_FILETYPE_ZIP)
            arc_err = ctx->engine->scan_archive_zip(data, data_len, ctx->opts,
                                                     ctx->result, ctx->depth + 1);
        else if (inner_type == AKAV_FILETYPE_GZIP)
            arc_err = ctx->engine->scan_archive_gzip(data, data_len, ctx->opts,
                                                      ctx->result, ctx->depth + 1);
        else if (inner_type == AKAV_FILETYPE_TAR)
            arc_err = ctx->engine->scan_archive_tar(data, data_len, ctx->opts,
                                                     ctx->result, ctx->depth + 1);
    }

    if (arc_err == AKAV_ERROR_BOMB) {
        ctx->bomb = true;
        return false;
    }
    if (ctx->result->found)
        return false;

    return true; /* Continue extraction */
}

akav_error_t Engine::scan_archive_tar(const uint8_t* buf, size_t len,
                                       const akav_scan_options_t* opts,
                                       akav_scan_result_t* result, int depth)
{
    if (depth >= opts->max_scan_depth)
        return AKAV_OK;

    akav_tar_context_t tar_ctx;
    akav_tar_init(&tar_ctx);

    tar_scan_ctx scan_ctx;
    scan_ctx.engine = this;
    scan_ctx.opts = opts;
    scan_ctx.result = result;
    scan_ctx.depth = depth;
    scan_ctx.bomb = false;

    bool ok = akav_tar_extract(&tar_ctx, buf, len, tar_entry_callback, &scan_ctx);

    if (scan_ctx.bomb || tar_ctx.bomb_detected)
        return AKAV_ERROR_BOMB;

    if (!ok && !result->found) {
        if (result->warning_count < AKAV_MAX_WARNINGS) {
            strncpy_s(result->warnings[result->warning_count],
                      AKAV_MAX_WARNING_LEN, tar_ctx.error, _TRUNCATE);
            result->warning_count++;
        }
    }

    return AKAV_OK;
}

akav_error_t Engine::scan_file(const char* path, const akav_scan_options_t* opts,
                               akav_scan_result_t* result)
{
    if (!is_initialized())
        return AKAV_ERROR_NOT_INIT;
    if (!path || !result)
        return AKAV_ERROR_INVALID;

    /* Use default options if none provided */
    akav_scan_options_t defaults;
    akav_scan_options_default(&defaults);
    if (!opts)
        opts = &defaults;

    /* ── Whitelist check 1: Path exclusion (before any file I/O) ── */
    if (opts->use_whitelist && whitelist_ && whitelist_->is_path_excluded(path)) {
        memset(result, 0, sizeof(*result));
        result->in_whitelist = 1;
        return AKAV_OK;
    }

    /* Open file and get metadata */
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return AKAV_ERROR_IO;

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size))
    {
        CloseHandle(hFile);
        return AKAV_ERROR_IO;
    }

    /* Get last-modified timestamp for cache key */
    FILETIME ft_write{};
    GetFileTime(hFile, nullptr, nullptr, &ft_write);
    int64_t last_modified = ((int64_t)ft_write.dwHighDateTime << 32) |
                            ft_write.dwLowDateTime;

    /* Check max filesize if specified */
    if (opts->max_filesize > 0 && file_size.QuadPart > opts->max_filesize)
    {
        CloseHandle(hFile);
        memset(result, 0, sizeof(*result));
        result->total_size = file_size.QuadPart;
        return AKAV_OK; /* Skip oversized files silently */
    }

    /* Empty file -- not malicious */
    if (file_size.QuadPart == 0)
    {
        CloseHandle(hFile);
        memset(result, 0, sizeof(*result));
        result->total_size = 0;
        return AKAV_OK;
    }

    /* Check scan cache (if enabled) */
    if (opts->use_cache && cache_) {
        if (cache_->lookup(path, last_modified, file_size.QuadPart, result)) {
            CloseHandle(hFile);
            return AKAV_OK;  /* Cache hit — result already populated */
        }
    }

    /* Allocate buffer and read */
    size_t buf_size = (size_t)file_size.QuadPart;
    uint8_t* buf = (uint8_t*)malloc(buf_size);
    if (!buf)
    {
        CloseHandle(hFile);
        return AKAV_ERROR_NOMEM;
    }

    DWORD bytes_read = 0;
    BOOL ok = ReadFile(hFile, buf, (DWORD)buf_size, &bytes_read, NULL);
    CloseHandle(hFile);

    if (!ok || bytes_read != (DWORD)buf_size)
    {
        free(buf);
        return AKAV_ERROR_IO;
    }

    /* ── Whitelist check 2: SHA-256 hash whitelist (after file read) ── */
    if (opts->use_whitelist && whitelist_) {
        uint8_t sha[AKAV_SHA256_LEN];
        if (akav_hash_sha256(buf, buf_size, sha)) {
            if (whitelist_->is_hash_whitelisted(sha)) {
                free(buf);
                memset(result, 0, sizeof(*result));
                result->in_whitelist = 1;
                result->total_size = (int64_t)buf_size;

                /* Still cache the whitelisted result */
                if (opts->use_cache && cache_) {
                    cache_->insert(path, last_modified, file_size.QuadPart, *result);
                }
                return AKAV_OK;
            }
        }
    }

    /* ── Whitelist check 3: Authenticode signer trust ── */
    if (opts->use_whitelist && whitelist_ && whitelist_->is_signer_trusted(path)) {
        free(buf);
        memset(result, 0, sizeof(*result));
        result->in_whitelist = 1;
        result->total_size = (int64_t)buf_size;

        /* Cache the whitelisted result */
        if (opts->use_cache && cache_) {
            cache_->insert(path, last_modified, file_size.QuadPart, *result);
        }
        return AKAV_OK;
    }

    /* Extract filename for display */
    const char* filename = strrchr(path, '\\');
    if (!filename)
        filename = strrchr(path, '/');
    filename = filename ? filename + 1 : path;

    akav_error_t err = scan_buffer(buf, buf_size, filename, opts, result);
    free(buf);

    /* Store result in cache (if scan succeeded and cache enabled) */
    if (err == AKAV_OK && opts->use_cache && cache_) {
        cache_->insert(path, last_modified, file_size.QuadPart, *result);
    }

    /* SIEM event is emitted by scan_buffer() — no duplicate emit here */

    return err;
}

akav_error_t Engine::scan_directory(const char* path, const akav_scan_options_t* opts,
                                    akav_scan_callback_t callback, void* user_data)
{
    if (!is_initialized())
        return AKAV_ERROR_NOT_INIT;
    if (!path || !callback)
        return AKAV_ERROR_INVALID;

    /* Build search pattern: path\* */
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return AKAV_ERROR_IO;

    do
    {
        /* Skip . and .. */
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", path, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            /* Recurse into subdirectory */
            scan_directory(full_path, opts, callback, user_data);
        }
        else
        {
            akav_scan_result_t result;
            akav_error_t err = scan_file(full_path, opts, &result);
            if (err == AKAV_OK)
            {
                callback(full_path, &result, user_data);
            }
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return AKAV_OK;
}

akav_error_t Engine::cache_clear()
{
    if (cache_)
        cache_->clear();
    return AKAV_OK;
}

akav_error_t Engine::cache_stats(uint64_t* hits, uint64_t* misses, uint64_t* entries)
{
    if (!hits || !misses || !entries)
        return AKAV_ERROR_INVALID;
    if (cache_) {
        cache_->stats(hits, misses, entries);
    } else {
        *hits = 0;
        *misses = 0;
        *entries = 0;
    }
    return AKAV_OK;
}

akav_error_t Engine::whitelist_add_hash(const uint8_t sha256[32])
{
    if (!sha256)
        return AKAV_ERROR_INVALID;
    if (whitelist_)
        whitelist_->add_hash(sha256);
    return AKAV_OK;
}

akav_error_t Engine::whitelist_add_path(const char* path_prefix)
{
    if (!path_prefix)
        return AKAV_ERROR_INVALID;
    if (whitelist_)
        whitelist_->add_path(path_prefix);
    return AKAV_OK;
}

akav_error_t Engine::whitelist_add_signer(const char* signer_name)
{
    if (!signer_name)
        return AKAV_ERROR_INVALID;
    if (whitelist_)
        whitelist_->add_signer(signer_name);
    return AKAV_OK;
}

akav_error_t Engine::whitelist_clear()
{
    if (whitelist_)
        whitelist_->clear();
    return AKAV_OK;
}

const char* Engine::db_version() const
{
    return db_version_str_.c_str();
}

akav_error_t Engine::set_siem_callback(akav_siem_callback_t callback, void* user_data)
{
    if (!siem_)
        return AKAV_ERROR_NOT_INIT;
    siem_->set_callback(callback, user_data);
    return AKAV_OK;
}

akav_error_t Engine::siem_start_http_shipper(const char* siem_url, const char* api_key)
{
    if (!siem_)
        return AKAV_ERROR_NOT_INIT;
    if (!siem_url || !api_key)
        return AKAV_ERROR_INVALID;
    return siem_->start_http(siem_url, api_key) ? AKAV_OK : AKAV_ERROR_IO;
}

akav_error_t Engine::siem_stop_http_shipper()
{
    if (!siem_)
        return AKAV_ERROR_NOT_INIT;
    siem_->stop_http();
    return AKAV_OK;
}

akav_error_t Engine::siem_start_jsonl(const char* path)
{
    if (!siem_)
        return AKAV_ERROR_NOT_INIT;
    return siem_->start_jsonl(path) ? AKAV_OK : AKAV_ERROR_IO;
}

akav_error_t Engine::siem_stop_jsonl()
{
    if (!siem_)
        return AKAV_ERROR_NOT_INIT;
    siem_->stop_jsonl();
    return AKAV_OK;
}

} /* namespace akav */
