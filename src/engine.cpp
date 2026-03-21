#include "engine_internal.h"
#include "file_type.h"
#include "parsers/safe_reader.h"
#include "parsers/zip.h"
#include "parsers/gzip.h"
#include "parsers/tar.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>
#include <cstdio>
#include <chrono>

namespace akav
{

Engine::Engine()
{
    akav_scanner_init(&scanner_);
}

Engine::~Engine()
{
    akav_scanner_destroy(&scanner_);
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
    (void)name; /* Used for display in later phases */
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

    /* Run signature scan pipeline (Bloom → MD5 → SHA256 → CRC32 → Aho-Corasick) */
    if (scanner_loaded_)
    {
        akav_scanner_scan_buffer(&scanner_, buf, len, result);
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

    /* Read file into memory */
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

    /* Check max filesize if specified */
    akav_scan_options_t defaults;
    akav_scan_options_default(&defaults);
    if (!opts)
        opts = &defaults;

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

    /* Extract filename for display */
    const char* filename = strrchr(path, '\\');
    if (!filename)
        filename = strrchr(path, '/');
    filename = filename ? filename + 1 : path;

    akav_error_t err = scan_buffer(buf, buf_size, filename, opts, result);
    free(buf);
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
    /* TODO: Phase 5 */
    return AKAV_OK;
}

akav_error_t Engine::cache_stats(uint64_t* hits, uint64_t* misses, uint64_t* entries)
{
    if (!hits || !misses || !entries)
        return AKAV_ERROR_INVALID;
    *hits = 0;
    *misses = 0;
    *entries = 0;
    return AKAV_OK;
}

akav_error_t Engine::whitelist_add_hash(const uint8_t[32])
{
    /* TODO: Phase 5 */
    return AKAV_OK;
}

akav_error_t Engine::whitelist_add_path(const char*)
{
    /* TODO: Phase 5 */
    return AKAV_OK;
}

akav_error_t Engine::whitelist_add_signer(const char*)
{
    /* TODO: Phase 5 */
    return AKAV_OK;
}

akav_error_t Engine::whitelist_clear()
{
    /* TODO: Phase 5 */
    return AKAV_OK;
}

const char* Engine::db_version() const
{
    return db_version_str_.c_str();
}

akav_error_t Engine::set_siem_callback(akav_siem_callback_t, void*)
{
    /* TODO: Phase 5 */
    return AKAV_OK;
}

akav_error_t Engine::siem_start_http_shipper(const char*, const char*)
{
    /* TODO: Phase 5 */
    return AKAV_OK;
}

akav_error_t Engine::siem_stop_http_shipper()
{
    /* TODO: Phase 5 */
    return AKAV_OK;
}

} /* namespace akav */
