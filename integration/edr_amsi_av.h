// edr_amsi_av.h -- AMSI integration for AkesoAV script content scanning.
//
// Provides the AmsiScanner class that hooks into the EDR agent's AMSI
// provider (akesoedr-amsi.dll) to scan script content via akav_scan_buffer().
//
// The AMSI provider calls AmsiScanner::scan() with the script buffer and
// appName from AmsiScanBuffer. If malicious content is detected, the
// provider returns AMSI_RESULT_DETECTED to block execution.
//
// Scan results are emitted as av:scan_result events with:
//   scan_type = "amsi"
//   scanner_id = "amsi_provider"
//   file_name = "amsi:<source>" (powershell, dotnet, vbscript, jscript, vba)
//
// Built-in pattern rules (replacing YARA for lightweight deployment):
//   - Invoke-Mimikatz
//   - Invoke-Expression + DownloadString chain
//   - [Reflection.Assembly]::Load patterns
//   - AmsiScanBuffer patching attempts
//   - amsiInitFailed variable set

#ifndef AKESOAV_EDR_AMSI_AV_H
#define AKESOAV_EDR_AMSI_AV_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

// Forward-declare opaque engine type
struct akav_engine;
typedef struct akav_engine akav_engine_t;

// AMSI result codes (from amsi.h)
enum AmsiResult {
    AMSI_RESULT_CLEAN          = 0,
    AMSI_RESULT_NOT_DETECTED   = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 0x4FFF,
    AMSI_RESULT_DETECTED       = 32768
};

// Script content pattern rule
struct AmsiPattern {
    std::string name;          // Detection name (e.g. "AMSI.Trojan.Mimikatz")
    std::string signature_id;  // Rule ID (e.g. "amsi-001")
    std::vector<std::string> patterns; // All patterns must match (AND logic)
    bool case_insensitive;
};

// AMSI scan result
struct AmsiScanResult {
    AmsiResult  result;
    bool        detected;
    std::string malware_name;
    std::string signature_id;
    std::string source;        // Derived AMSI source: powershell, dotnet, etc.
};

class AmsiScanner {
public:
    AmsiScanner();
    ~AmsiScanner();

    AmsiScanner(const AmsiScanner&) = delete;
    AmsiScanner& operator=(const AmsiScanner&) = delete;

    // Initialize with an AV engine handle (for scan_buffer calls).
    // If engine is nullptr, only built-in pattern rules are used.
    bool init(akav_engine_t* engine = nullptr);

    // Scan script content from AMSI.
    // buffer: raw script content from AmsiScanBuffer
    // length: buffer size in bytes
    // app_name: AMSI appName parameter (e.g. "PowerShell", "DotNet", etc.)
    // content_name: optional content name from AmsiScanBuffer
    AmsiScanResult scan(const uint8_t* buffer, size_t length,
                        const char* app_name,
                        const char* content_name = nullptr);

    // Get loaded pattern count.
    size_t pattern_count() const { return patterns_.size(); }

    // Get all loaded patterns.
    const std::vector<AmsiPattern>& patterns() const { return patterns_; }

    // Add a custom pattern rule.
    void add_pattern(const AmsiPattern& pattern);

private:
    akav_engine_t* engine_;
    std::vector<AmsiPattern> patterns_;
    bool initialized_;

    // Load built-in AMSI script detection patterns.
    void load_builtin_patterns();

    // Derive AMSI source from appName.
    static std::string derive_source(const char* app_name);

    // Check buffer against built-in patterns.
    bool match_patterns(const uint8_t* buffer, size_t length,
                        std::string& out_name, std::string& out_sig_id);

    // Case-insensitive substring search.
    static bool contains_ci(const uint8_t* buffer, size_t length,
                            const std::string& pattern);
};

#endif // AKESOAV_EDR_AMSI_AV_H
