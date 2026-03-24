/* jsonl_writer.cpp -- NDJSON local log writer with 100 MB rotation.
 *
 * Implements the local JSONL log per S3.7.6:
 *   - One JSON object per line (NDJSON)
 *   - UTF-8, no BOM
 *   - 100 MB rotation: akesoav.jsonl -> akesoav.1.jsonl ... akesoav.5.jsonl
 *   - Thread-safe via CRITICAL_SECTION
 */

#include "jsonl_writer.h"
#include "siem/event_serialize.h"

#include <cstdio>
#include <cstring>
#include <direct.h>
#include <sys/stat.h>
#include <io.h>
#include <fcntl.h>

namespace akav {

/* ---- Helpers --------------------------------------------------------- */

static std::string default_jsonl_path()
{
    char buf[MAX_PATH];
    DWORD len = GetEnvironmentVariableA("ProgramData", buf, sizeof(buf));
    if (len == 0 || len >= sizeof(buf))
        return "C:\\ProgramData\\Akeso\\Logs\\akesoav.jsonl";

    std::string path(buf, len);
    path += "\\Akeso\\Logs\\akesoav.jsonl";
    return path;
}

static std::string parent_dir(const std::string& path)
{
    auto pos = path.find_last_of("\\/");
    if (pos == std::string::npos) return ".";
    return path.substr(0, pos);
}

static void ensure_directory(const std::string& dir)
{
    /* Create all components. Simple recursive approach. */
    for (size_t i = 0; i < dir.size(); ++i) {
        if (dir[i] == '\\' || dir[i] == '/') {
            std::string sub = dir.substr(0, i);
            if (!sub.empty() && sub.back() != ':')
                _mkdir(sub.c_str());
        }
    }
    _mkdir(dir.c_str());
}

/* Build the rotated filename:
 *   base.jsonl -> base.1.jsonl, base.2.jsonl, ... */
static std::string rotated_name(const std::string& base, int index)
{
    /* Find ".jsonl" suffix */
    auto dot = base.rfind(".jsonl");
    if (dot == std::string::npos)
        return base + "." + std::to_string(index);

    return base.substr(0, dot) + "." + std::to_string(index) + ".jsonl";
}

/* ---- JsonlWriter implementation -------------------------------------- */

JsonlWriter::JsonlWriter()
    : fp_(nullptr)
    , current_size_(0)
    , initialized_(false)
{
    memset(&cs_, 0, sizeof(cs_));
}

JsonlWriter::~JsonlWriter()
{
    shutdown();
}

bool JsonlWriter::init(const char* path)
{
    if (initialized_)
        return true;

    InitializeCriticalSection(&cs_);

    path_ = path ? path : default_jsonl_path();

    /* Ensure parent directory exists */
    ensure_directory(parent_dir(path_));

    if (!open_file()) {
        DeleteCriticalSection(&cs_);
        return false;
    }

    initialized_ = true;
    return true;
}

void JsonlWriter::shutdown()
{
    if (!initialized_)
        return;

    EnterCriticalSection(&cs_);
    if (fp_) {
        fflush(fp_);
        fclose(fp_);
        fp_ = nullptr;
    }
    LeaveCriticalSection(&cs_);

    DeleteCriticalSection(&cs_);
    initialized_ = false;
}

bool JsonlWriter::open_file()
{
    if (fp_) {
        fclose(fp_);
        fp_ = nullptr;
    }

    /* Open in append mode with FILE_SHARE_READ so SIEM log can be read
     * by other processes (test scripts, log viewers) while service runs. */
    HANDLE hFile = CreateFileA(path_.c_str(),
        FILE_APPEND_DATA | FILE_GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[jsonl_writer] Cannot open '%s' (err=%lu)\n",
                path_.c_str(), GetLastError());
        return false;
    }
    int fd = _open_osfhandle((intptr_t)hFile, _O_APPEND | _O_WRONLY);
    if (fd == -1) {
        CloseHandle(hFile);
        fprintf(stderr, "[jsonl_writer] Cannot create fd for '%s'\n", path_.c_str());
        return false;
    }
    fp_ = _fdopen(fd, "ab");
    if (!fp_) {
        _close(fd);
        fprintf(stderr, "[jsonl_writer] Cannot fdopen '%s'\n", path_.c_str());
        return false;
    }

    /* Determine current size */
    struct _stat64 st;
    if (_stat64(path_.c_str(), &st) == 0)
        current_size_ = (size_t)st.st_size;
    else
        current_size_ = 0;

    return true;
}

void JsonlWriter::rotate()
{
    /* Close current file */
    if (fp_) {
        fflush(fp_);
        fclose(fp_);
        fp_ = nullptr;
    }

    /* Shift existing rotated files: .5 -> delete, .4 -> .5, .3 -> .4, etc. */
    std::string oldest = rotated_name(path_, MAX_ROTATIONS);
    _unlink(oldest.c_str());

    for (int i = MAX_ROTATIONS - 1; i >= 1; --i) {
        std::string from = rotated_name(path_, i);
        std::string to   = rotated_name(path_, i + 1);
        rename(from.c_str(), to.c_str()); /* OK if source doesn't exist */
    }

    /* Current -> .1 */
    std::string first = rotated_name(path_, 1);
    rename(path_.c_str(), first.c_str());

    /* Reopen fresh file */
    open_file();
}

bool JsonlWriter::write_event(const akav_siem_event_t* event)
{
    if (!initialized_ || !event)
        return false;

    EnterCriticalSection(&cs_);

    /* Build the full NDJSON line:
     * {"event_id":"...","timestamp":"...","source_type":"...","event_type":"...",
     *  "agent_id":"...","payload":...}\n */
    char line[16384];
    int len = snprintf(line, sizeof(line),
        "{\"event_id\":\"%s\",\"timestamp\":\"%s\","
        "\"source_type\":\"%s\",\"event_type\":\"%s\","
        "\"agent_id\":\"%s\",\"payload\":%s}\n",
        event->event_id, event->timestamp,
        event->source_type, event->event_type,
        event->agent_id, event->payload_json);

    if (len <= 0 || (size_t)len >= sizeof(line)) {
        LeaveCriticalSection(&cs_);
        return false;
    }

    /* Rotate if needed */
    if (current_size_ + (size_t)len > MAX_FILE_SIZE)
        rotate();

    if (!fp_) {
        LeaveCriticalSection(&cs_);
        return false;
    }

    size_t written = fwrite(line, 1, (size_t)len, fp_);
    fflush(fp_);
    current_size_ += written;

    LeaveCriticalSection(&cs_);
    return written == (size_t)len;
}

void JsonlWriter::flush()
{
    if (!initialized_)
        return;

    EnterCriticalSection(&cs_);
    if (fp_)
        fflush(fp_);
    LeaveCriticalSection(&cs_);
}

} /* namespace akav */
