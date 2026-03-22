/* test_import_analyzer.cpp -- Unit tests for import heuristic analyzer (P4-T3).
 *
 * Tests all 6 checks from §5.6 Imports row:
 *   1. injection_combo:      VirtualAlloc+WriteProcessMemory+CreateRemoteThread (+35)
 *   2. shellcode_loader:     VirtualAlloc+VirtualProtect+CreateThread           (+25)
 *   3. service_installer:    CreateService+StartService                          (+20)
 *   4. persistence_registry: RegSetValueEx                                       (+15)
 *   5. ordinal_only:         All imports by ordinal                              (+15)
 *   6. api_hashing:          Only GetProcAddress+LoadLibrary                     (+25)
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>

extern "C" {
#include "heuristics/imports.h"
#include "parsers/pe.h"
}

/* ── Test helper: build synthetic PE with specific imports ──────── */

class ImportPeBuilder {
public:
    ImportPeBuilder() {
        memset(&pe_, 0, sizeof(pe_));
        pe_.valid = true;
        pe_.num_sections = 1;
        strncpy_s(pe_.sections[0].name, sizeof(pe_.sections[0].name),
                  ".text", _TRUNCATE);
        pe_.sections[0].characteristics = 0x60000020; /* CODE|EXEC|READ */
    }

    ImportPeBuilder& add_dll(const char* dll_name,
                              std::vector<std::string> funcs) {
        if (dll_count_ >= AKAV_PE_MAX_IMPORTS) return *this;

        dll_names_.push_back(dll_name);
        for (auto& f : funcs) {
            func_names_.push_back(f);
            func_is_ordinal_.push_back(false);
        }
        dll_func_counts_.push_back((uint32_t)funcs.size());
        dll_count_++;
        return *this;
    }

    ImportPeBuilder& add_dll_ordinals(const char* dll_name,
                                       uint32_t count) {
        if (dll_count_ >= AKAV_PE_MAX_IMPORTS) return *this;

        dll_names_.push_back(dll_name);
        for (uint32_t i = 0; i < count; i++) {
            func_names_.push_back("");
            func_is_ordinal_.push_back(true);
        }
        dll_func_counts_.push_back(count);
        dll_count_++;
        return *this;
    }

    akav_pe_t* build() {
        /* Allocate import structures */
        pe_.num_import_dlls = dll_count_;
        pe_.import_dlls = (akav_pe_import_dll_t*)calloc(
            dll_count_, sizeof(akav_pe_import_dll_t));

        uint32_t total_funcs = (uint32_t)func_names_.size();
        pe_.num_import_funcs = total_funcs;
        pe_.import_funcs = (akav_pe_import_func_t*)calloc(
            total_funcs > 0 ? total_funcs : 1, sizeof(akav_pe_import_func_t));

        uint32_t func_idx = 0;
        uint32_t ordinal_count = 0;
        for (uint32_t d = 0; d < dll_count_; d++) {
            strncpy_s(pe_.import_dlls[d].dll_name,
                      sizeof(pe_.import_dlls[d].dll_name),
                      dll_names_[d].c_str(), _TRUNCATE);
            pe_.import_dlls[d].num_functions = dll_func_counts_[d];
            pe_.import_dlls[d].first_func_index = func_idx;

            for (uint32_t f = 0; f < dll_func_counts_[d]; f++) {
                pe_.import_funcs[func_idx].is_ordinal = func_is_ordinal_[func_idx];
                if (func_is_ordinal_[func_idx]) {
                    pe_.import_funcs[func_idx].ordinal = (uint16_t)(100 + func_idx);
                    ordinal_count++;
                } else {
                    strncpy_s(pe_.import_funcs[func_idx].name,
                              sizeof(pe_.import_funcs[func_idx].name),
                              func_names_[func_idx].c_str(), _TRUNCATE);
                }
                func_idx++;
            }
        }
        pe_.ordinal_only_count = ordinal_count;

        return &pe_;
    }

    ~ImportPeBuilder() {
        free(pe_.import_dlls);
        free(pe_.import_funcs);
    }

private:
    akav_pe_t pe_{};
    uint32_t dll_count_ = 0;
    std::vector<std::string> dll_names_;
    std::vector<std::string> func_names_;
    std::vector<bool> func_is_ordinal_;
    std::vector<uint32_t> dll_func_counts_;
};

/* ── Helper to check if a specific hit was recorded ────────────── */

static bool has_hit(const akav_import_result_t& r, const char* name) {
    for (int i = 0; i < r.num_hits; i++) {
        if (strcmp(r.hits[i].check_name, name) == 0)
            return true;
    }
    return false;
}

/* ══════════════════════════════════════════════════════════════════
 *  Default weights
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, DefaultWeights) {
    akav_import_weights_t w;
    akav_import_weights_default(&w);
    EXPECT_EQ(w.injection_combo, 35);
    EXPECT_EQ(w.shellcode_loader, 25);
    EXPECT_EQ(w.service_installer, 20);
    EXPECT_EQ(w.persistence_registry, 15);
    EXPECT_EQ(w.ordinal_only, 15);
    EXPECT_EQ(w.api_hashing, 25);
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 1: Injection combo
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, InjectionCombo) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
         "CloseHandle"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "injection_combo"));
    EXPECT_EQ(r.hits[0].weight, 35);
}

TEST(ImportAnalyzer, InjectionComboMissingOne) {
    /* Missing CreateRemoteThread → should NOT fire */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAlloc", "WriteProcessMemory", "CloseHandle"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "injection_combo"));
}

TEST(ImportAnalyzer, InjectionComboExVariants) {
    /* Ex variants should also trigger */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThreadEx"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "injection_combo"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 2: Shellcode loader
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, ShellcodeLoader) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAlloc", "VirtualProtect", "CreateThread"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "shellcode_loader"));
    EXPECT_EQ(r.hits[0].weight, 25);
}

TEST(ImportAnalyzer, ShellcodeLoaderMissingVP) {
    /* Missing VirtualProtect → should NOT fire */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAlloc", "CreateThread"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "shellcode_loader"));
}

TEST(ImportAnalyzer, ShellcodeLoaderExVariants) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAllocEx", "VirtualProtectEx", "CreateThread"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "shellcode_loader"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 3: Service installer
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, ServiceInstaller) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("advapi32.dll",
        {"CreateServiceA", "StartServiceA", "OpenSCManagerA"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "service_installer"));
    EXPECT_EQ(r.hits[0].weight, 20);
}

TEST(ImportAnalyzer, ServiceInstallerWVariant) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("advapi32.dll",
        {"CreateServiceW", "StartServiceW"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "service_installer"));
}

TEST(ImportAnalyzer, ServiceInstallerMissingStart) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("advapi32.dll",
        {"CreateServiceA", "OpenSCManagerA"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "service_installer"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 4: Persistence via registry
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, PersistenceRegistry) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("advapi32.dll",
        {"RegSetValueExA", "RegOpenKeyExA", "RegCloseKey"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "persistence_registry"));
    EXPECT_EQ(r.hits[0].weight, 15);
}

TEST(ImportAnalyzer, PersistenceRegistryWVariant) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("advapi32.dll",
        {"RegSetValueExW"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "persistence_registry"));
}

TEST(ImportAnalyzer, NoPersistenceWithoutRegSetValueEx) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("advapi32.dll",
        {"RegOpenKeyExA", "RegCloseKey", "RegQueryValueExA"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "persistence_registry"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 5: Ordinal-only imports
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, OrdinalOnly) {
    ImportPeBuilder b;
    auto* pe = b.add_dll_ordinals("unknown.dll", 5)
                .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "ordinal_only"));
    EXPECT_EQ(r.hits[0].weight, 15);
}

TEST(ImportAnalyzer, OrdinalOnlyNotTriggeredWithNamedImports) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll", {"ExitProcess"})
                .add_dll_ordinals("custom.dll", 3)
                .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "ordinal_only"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Check 6: API hashing indicator
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, ApiHashing) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"GetProcAddress", "LoadLibraryA"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "api_hashing"));
    EXPECT_EQ(r.hits[0].weight, 25);
}

TEST(ImportAnalyzer, ApiHashingWithGetModuleHandle) {
    /* GetModuleHandle is allowed in the "resolver-only" set */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"GetProcAddress", "LoadLibraryW", "GetModuleHandleW", "FreeLibrary"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "api_hashing"));
}

TEST(ImportAnalyzer, ApiHashingNotTriggeredWithOtherImports) {
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"GetProcAddress", "LoadLibraryA", "CreateFileA", "ReadFile",
         "CloseHandle", "ExitProcess"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "api_hashing"));
}

TEST(ImportAnalyzer, ApiHashingNotTriggeredWithoutGPA) {
    /* Must have GetProcAddress */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"LoadLibraryA"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "api_hashing"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Combined scoring
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, CombinedInjectionAndShellcode) {
    /* Both injection + shellcode combos present */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
         "CreateRemoteThread", "CreateThread"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "injection_combo"));
    EXPECT_TRUE(has_hit(r, "shellcode_loader"));
    EXPECT_EQ(r.total_score, 35 + 25);
}

TEST(ImportAnalyzer, FullMalwareSuite) {
    /* Injection + service + persistence → all fire */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"})
        .add_dll("advapi32.dll",
        {"CreateServiceA", "StartServiceA", "RegSetValueExA"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "injection_combo"));
    EXPECT_TRUE(has_hit(r, "service_installer"));
    EXPECT_TRUE(has_hit(r, "persistence_registry"));
    EXPECT_EQ(r.total_score, 35 + 20 + 15);
}

/* ══════════════════════════════════════════════════════════════════
 *  Clean PE — no false positives
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, CleanPeNoFalsePositives) {
    /* Typical benign imports: file I/O, console, process lifecycle */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"CreateFileA", "ReadFile", "WriteFile", "CloseHandle",
         "GetLastError", "ExitProcess", "GetCommandLineA",
         "GetStdHandle", "SetConsoleCtrlHandler"})
        .add_dll("user32.dll",
        {"MessageBoxA", "GetWindowTextA"})
        .add_dll("msvcrt.dll",
        {"printf", "malloc", "free", "exit"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_EQ(r.total_score, 0);
    EXPECT_EQ(r.num_hits, 0);
}

/* ══════════════════════════════════════════════════════════════════
 *  No imports → score 0 (early return)
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, NoImportsScoreZero) {
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    pe.valid = true;

    akav_import_result_t r;
    akav_import_analyze(&pe, nullptr, &r);
    EXPECT_EQ(r.total_score, 0);
    EXPECT_EQ(r.num_hits, 0);
}

/* ══════════════════════════════════════════════════════════════════
 *  JSON weight loading
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, JsonDefaultConfig) {
    akav_import_weights_t w;
    bool ok = akav_import_weights_load_json(&w, "config/import_weights.json");
    EXPECT_TRUE(ok);
    EXPECT_EQ(w.injection_combo, 35);
    EXPECT_EQ(w.shellcode_loader, 25);
    EXPECT_EQ(w.service_installer, 20);
    EXPECT_EQ(w.persistence_registry, 15);
    EXPECT_EQ(w.ordinal_only, 15);
    EXPECT_EQ(w.api_hashing, 25);
}

TEST(ImportAnalyzer, JsonOverride) {
    /* Write a temp JSON that overrides injection_combo */
    const char* path = "test_import_weights_tmp.json";
    FILE* f = NULL;
    fopen_s(&f, path, "w");
    ASSERT_NE(f, nullptr);
    fprintf(f, "{ \"injection_combo\": 99, \"api_hashing\": 50 }");
    fclose(f);

    akav_import_weights_t w;
    bool ok = akav_import_weights_load_json(&w, path);
    EXPECT_TRUE(ok);
    EXPECT_EQ(w.injection_combo, 99);
    EXPECT_EQ(w.api_hashing, 50);
    /* Others should remain at defaults */
    EXPECT_EQ(w.shellcode_loader, 25);
    EXPECT_EQ(w.service_installer, 20);

    remove(path);
}

TEST(ImportAnalyzer, JsonMissingFile) {
    akav_import_weights_t w;
    bool ok = akav_import_weights_load_json(&w, "nonexistent.json");
    EXPECT_FALSE(ok);
    /* Should still have defaults */
    EXPECT_EQ(w.injection_combo, 35);
}

/* ══════════════════════════════════════════════════════════════════
 *  Custom weights override scoring
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, CustomWeightsApplied) {
    akav_import_weights_t w;
    akav_import_weights_default(&w);
    w.injection_combo = 100;

    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, &w, &r);
    EXPECT_TRUE(has_hit(r, "injection_combo"));
    EXPECT_EQ(r.total_score, 100);
}

TEST(ImportAnalyzer, ZeroWeightSuppresses) {
    akav_import_weights_t w;
    akav_import_weights_default(&w);
    w.injection_combo = 0;

    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, &w, &r);
    EXPECT_FALSE(has_hit(r, "injection_combo"));
    EXPECT_EQ(r.total_score, 0);
}

/* ══════════════════════════════════════════════════════════════════
 *  Null safety
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, NullPe) {
    akav_import_result_t r;
    memset(&r, 0xFF, sizeof(r));
    akav_import_analyze(nullptr, nullptr, &r);
    /* Should not crash; result untouched since pe is null */
}

TEST(ImportAnalyzer, NullResult) {
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    pe.valid = true;
    akav_import_analyze(&pe, nullptr, nullptr);
    /* Should not crash */
}

TEST(ImportAnalyzer, InvalidPe) {
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    pe.valid = false;

    akav_import_result_t r;
    memset(&r, 0xFF, sizeof(r));
    akav_import_analyze(&pe, nullptr, &r);
    /* Should not crash; result untouched */
}

TEST(ImportAnalyzer, NullWeightsDefault) {
    akav_import_weights_default(nullptr);
    /* Should not crash */
}

/* ══════════════════════════════════════════════════════════════════
 *  Real system PE: notepad.exe should score 0
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, NotepadScoresZero) {
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

    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    bool parsed = akav_pe_parse(&pe, buf, (size_t)fsize);
    ASSERT_TRUE(parsed);

    akav_import_result_t r;
    akav_import_analyze(&pe, nullptr, &r);
    EXPECT_EQ(r.total_score, 0)
        << "notepad.exe should have no suspicious import patterns";

    akav_pe_free(&pe);
    free(buf);
}

/* ══════════════════════════════════════════════════════════════════
 *  Cross-DLL detection (imports from different DLLs combine)
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, CrossDllInjectionCombo) {
    /* VirtualAlloc from kernel32 + WriteProcessMemory from ntdll-forwarded
     * + CreateRemoteThread from kernel32 — all from separate DLL entries */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll", {"VirtualAllocEx"})
                .add_dll("kernel32.dll", {"WriteProcessMemory"})
                .add_dll("kernel32.dll", {"CreateRemoteThread"})
                .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_TRUE(has_hit(r, "injection_combo"));
}

/* ══════════════════════════════════════════════════════════════════
 *  Adversarial: API hashing with one extra benign import evades
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, Adversarial_ApiHashingEvasionOneExtraImport) {
    /* Adding a single benign import (ExitProcess) defeats api_hashing check */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"GetProcAddress", "LoadLibraryA", "ExitProcess"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "api_hashing"))
        << "Known gap: adding one benign import defeats api_hashing detection";
}

/* ══════════════════════════════════════════════════════════════════
 *  Adversarial: partial injection combo not detected
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, Adversarial_PartialInjectionViaIndirect) {
    /* Malware using NtWriteVirtualMemory instead of WriteProcessMemory
     * evades the injection combo since we only check named imports */
    ImportPeBuilder b;
    auto* pe = b.add_dll("kernel32.dll",
        {"VirtualAllocEx", "CreateRemoteThread"})
        .add_dll("ntdll.dll",
        {"NtWriteVirtualMemory"})
        .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "injection_combo"))
        << "Known gap: Nt* API variants not checked for injection combo";
}

/* ══════════════════════════════════════════════════════════════════
 *  Adversarial: ordinal-only with one named import evades
 * ══════════════════════════════════════════════════════════════════ */

TEST(ImportAnalyzer, Adversarial_OrdinalEvasionOneName) {
    /* Adding one named import defeats ordinal_only check */
    ImportPeBuilder b;
    auto* pe = b.add_dll_ordinals("custom.dll", 10)
                .add_dll("kernel32.dll", {"ExitProcess"})
                .build();

    akav_import_result_t r;
    akav_import_analyze(pe, nullptr, &r);
    EXPECT_FALSE(has_hit(r, "ordinal_only"))
        << "Known gap: one named import disables ordinal-only detection";
}
