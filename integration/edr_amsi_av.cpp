// edr_amsi_av.cpp -- AMSI integration for AkesoAV script content scanning.
//
// Scans script content received from the EDR agent's AMSI provider using:
//   1. Built-in pattern rules (lightweight alternative to YARA)
//   2. AV engine scan_buffer (if engine is available)
//
// Detection results are returned as AmsiScanResult. The EDR agent's AMSI
// provider maps this to AMSI_RESULT_DETECTED or AMSI_RESULT_NOT_DETECTED.

#include "edr_amsi_av.h"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <cctype>

// ---- Constructor / Destructor -------------------------------------------

AmsiScanner::AmsiScanner()
    : engine_(nullptr)
    , initialized_(false)
{
}

AmsiScanner::~AmsiScanner() = default;

// ---- Initialization -----------------------------------------------------

bool AmsiScanner::init(akav_engine_t* engine)
{
    engine_ = engine;
    load_builtin_patterns();
    initialized_ = true;
    return true;
}

// ---- Built-in AMSI patterns ---------------------------------------------

void AmsiScanner::load_builtin_patterns()
{
    patterns_.clear();

    // Rule 1: Invoke-Mimikatz
    patterns_.push_back({
        "AMSI.Trojan.InvokeMimikatz",
        "amsi-001",
        {"Invoke-Mimikatz"},
        true
    });

    // Rule 2: Invoke-Expression + DownloadString chain
    patterns_.push_back({
        "AMSI.Trojan.DownloadCradle",
        "amsi-002",
        {"Invoke-Expression", "DownloadString"},
        true
    });

    // Alternative download cradle: IEX + Net.WebClient
    patterns_.push_back({
        "AMSI.Trojan.DownloadCradle.WebClient",
        "amsi-003",
        {"IEX", "Net.WebClient"},
        true
    });

    // Rule 3: Reflection.Assembly Load (used for in-memory .NET loading)
    patterns_.push_back({
        "AMSI.Suspicious.ReflectionLoad",
        "amsi-004",
        {"Reflection.Assembly", "Load"},
        true
    });

    // Alternative: [System.Reflection.Assembly]::Load
    patterns_.push_back({
        "AMSI.Suspicious.ReflectionLoad.System",
        "amsi-005",
        {"System.Reflection.Assembly", "Load"},
        true
    });

    // Rule 4: AmsiScanBuffer patching (AMSI bypass)
    patterns_.push_back({
        "AMSI.Bypass.PatchAmsiScanBuffer",
        "amsi-006",
        {"AmsiScanBuffer", "VirtualProtect"},
        true
    });

    // Alternative AMSI bypass: reading amsi.dll base
    patterns_.push_back({
        "AMSI.Bypass.GetProcAmsi",
        "amsi-007",
        {"amsi.dll", "GetProcAddress"},
        true
    });

    // Rule 5: amsiInitFailed bypass
    patterns_.push_back({
        "AMSI.Bypass.InitFailed",
        "amsi-008",
        {"amsiInitFailed"},
        true
    });

    // Rule 6: PowerShell execution policy bypass + encoded command
    patterns_.push_back({
        "AMSI.Suspicious.EncodedCommand",
        "amsi-009",
        {"FromBase64String", "Invoke-Expression"},
        true
    });

    // Rule 7: Common post-exploitation: Invoke-PSInject, Invoke-Shellcode
    patterns_.push_back({
        "AMSI.Trojan.InvokePSInject",
        "amsi-010",
        {"Invoke-PSInject"},
        true
    });

    patterns_.push_back({
        "AMSI.Trojan.InvokeShellcode",
        "amsi-011",
        {"Invoke-Shellcode"},
        true
    });

    // Rule 8: WMI-based persistence
    patterns_.push_back({
        "AMSI.Suspicious.WMIPersistence",
        "amsi-012",
        {"EventSubscription", "CommandLineTemplate"},
        true
    });
}

// ---- Source derivation ---------------------------------------------------

std::string AmsiScanner::derive_source(const char* app_name)
{
    if (!app_name || !app_name[0])
        return "unknown";

    // Case-insensitive comparison
    std::string name(app_name);
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    if (name.find("powershell") != std::string::npos) return "powershell";
    if (name.find("dotnet") != std::string::npos ||
        name.find(".net") != std::string::npos)       return "dotnet";
    if (name.find("vbscript") != std::string::npos)   return "vbscript";
    if (name.find("jscript") != std::string::npos)    return "jscript";
    if (name.find("vba") != std::string::npos)        return "vba";
    if (name.find("wscript") != std::string::npos)    return "vbscript";
    if (name.find("cscript") != std::string::npos)    return "jscript";

    return "unknown";
}

// ---- Case-insensitive search --------------------------------------------

bool AmsiScanner::contains_ci(const uint8_t* buffer, size_t length,
                               const std::string& pattern)
{
    if (pattern.empty()) return true;
    if (length < pattern.size()) return false;

    // Build lowercased pattern
    std::string lower_pat(pattern.size(), '\0');
    std::transform(pattern.begin(), pattern.end(), lower_pat.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    // Search through buffer
    for (size_t i = 0; i <= length - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (std::tolower(buffer[i + j]) != (unsigned char)lower_pat[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }

    return false;
}

// ---- Pattern matching ---------------------------------------------------

bool AmsiScanner::match_patterns(const uint8_t* buffer, size_t length,
                                  std::string& out_name,
                                  std::string& out_sig_id)
{
    for (const auto& rule : patterns_) {
        bool all_match = true;

        for (const auto& pat : rule.patterns) {
            bool found;
            if (rule.case_insensitive) {
                found = contains_ci(buffer, length, pat);
            } else {
                // Case-sensitive search
                std::string haystack(reinterpret_cast<const char*>(buffer), length);
                found = haystack.find(pat) != std::string::npos;
            }

            if (!found) {
                all_match = false;
                break;
            }
        }

        if (all_match) {
            out_name = rule.name;
            out_sig_id = rule.signature_id;
            return true;
        }
    }

    return false;
}

// ---- Scan ---------------------------------------------------------------

AmsiScanResult AmsiScanner::scan(const uint8_t* buffer, size_t length,
                                  const char* app_name,
                                  const char* content_name)
{
    (void)content_name;

    AmsiScanResult result{};
    result.result = AMSI_RESULT_NOT_DETECTED;
    result.detected = false;
    result.source = derive_source(app_name);

    if (!initialized_ || !buffer || length == 0)
        return result;

    // 1. Check built-in pattern rules first (fast)
    std::string rule_name, rule_sig_id;
    if (match_patterns(buffer, length, rule_name, rule_sig_id)) {
        result.result = AMSI_RESULT_DETECTED;
        result.detected = true;
        result.malware_name = rule_name;
        result.signature_id = rule_sig_id;
        return result;
    }

    // 2. If AV engine is available, run full scan_buffer
    //    This catches anything in the signature database (e.g. EICAR)
    if (engine_) {
        // We use LoadLibrary/GetProcAddress in the real EDR shim,
        // but for testing we can call the engine directly if linked.
        // In production, the EDR's AMSI DLL uses the AVEngine shim
        // class from edr_shim.h to call akav_scan_buffer().
        //
        // For now, this path is a placeholder. The real integration
        // happens in the EDR agent's akesoedr-amsi.dll which uses
        // the AVEngine class from edr_shim.h.
    }

    return result;
}

// ---- Custom pattern management ------------------------------------------

void AmsiScanner::add_pattern(const AmsiPattern& pattern)
{
    patterns_.push_back(pattern);
}
