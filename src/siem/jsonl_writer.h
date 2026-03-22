/* jsonl_writer.h -- NDJSON local log writer with file rotation.
 *
 * Writes all SIEM events to a local JSONL file for offline analysis
 * and forensics (S3.7.6).
 *
 * Specs:
 *   Path:     %ProgramData%\Akeso\Logs\akesoav.jsonl
 *   Format:   NDJSON (one JSON object per line, UTF-8, no BOM)
 *   Rotation: 100 MB per file, rotate to .1.jsonl through .5.jsonl
 *   Thread:   All writes are serialized via CRITICAL_SECTION
 */

#ifndef AKAV_JSONL_WRITER_H
#define AKAV_JSONL_WRITER_H

#include "akesoav.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <string>

namespace akav {

class JsonlWriter {
public:
    static constexpr size_t MAX_FILE_SIZE = 100 * 1024 * 1024; /* 100 MB */
    static constexpr int    MAX_ROTATIONS = 5;

    JsonlWriter();
    ~JsonlWriter();

    JsonlWriter(const JsonlWriter&) = delete;
    JsonlWriter& operator=(const JsonlWriter&) = delete;

    /* Initialize with a custom path or nullptr for the default
     * %ProgramData%\Akeso\Logs\akesoav.jsonl. */
    bool init(const char* path = nullptr);
    void shutdown();

    /* Write a single SIEM event as one NDJSON line.
     * Thread-safe. Rotates if needed before writing. */
    bool write_event(const akav_siem_event_t* event);

    /* Force flush the file. */
    void flush();

    /* Get current file path. */
    const std::string& path() const { return path_; }

    /* Get approximate bytes written to current file. */
    size_t current_size() const { return current_size_; }

private:
    void rotate();
    bool open_file();

    std::string       path_;
    FILE*             fp_;
    size_t            current_size_;
    CRITICAL_SECTION  cs_;
    bool              initialized_;
};

} /* namespace akav */

#endif /* AKAV_JSONL_WRITER_H */
