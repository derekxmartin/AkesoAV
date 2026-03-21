#include "engine_internal.h"
#include "file_type.h"
#include "parsers/safe_reader.h"

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

    auto end = std::chrono::steady_clock::now();
    result->scan_time_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

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
