cmake_minimum_required(VERSION 3.20)
project(AkesoAV VERSION 0.1.0 LANGUAGES C CXX)

# ── Standards ──
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Options ──
option(AKAV_BUILD_TESTS "Build unit tests" ON)
option(AKAV_BUILD_FUZZ "Build fuzz targets (requires clang-cl)" OFF)

# Fuzz builds: libFuzzer runtime is /MT, so force static CRT everywhere
if(AKAV_BUILD_FUZZ)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded" CACHE STRING "" FORCE)
endif()

# ── Compiler warnings (applied per-target to avoid affecting fetched deps) ──
if(MSVC)
    set(AKAV_WARNING_FLAGS /W4 /WX)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(AKAV_WARNING_FLAGS -Wall -Wextra -Werror)
endif()

# ── zlib (for ZIP decompression) ──
include(FetchContent)
FetchContent_Declare(
    zlib
    GIT_REPOSITORY https://github.com/madler/zlib.git
    GIT_TAG        v1.3.1
)
set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zlib)

# ── SQLite (for quarantine index) ──
FetchContent_Declare(
    sqlite3
    URL https://www.sqlite.org/2024/sqlite-amalgamation-3460000.zip
    DOWNLOAD_NO_EXTRACT FALSE
)
FetchContent_MakeAvailable(sqlite3)

# Build sqlite3 as a static library from the amalgamation
add_library(sqlite3_lib STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3_lib PUBLIC ${sqlite3_SOURCE_DIR})
# Suppress warnings from third-party code
if(MSVC)
    target_compile_options(sqlite3_lib PRIVATE /W0)
endif()

# ── YARA (for rule matching) ──
include(${CMAKE_SOURCE_DIR}/cmake/BuildYara.cmake)

# ── Windows libraries ──
set(AKAV_WIN_LIBS bcrypt.lib crypt32.lib wintrust.lib winhttp.lib)

# ── Core engine sources (static lib shared by DLL and tests) ──
set(AKAV_ENGINE_SOURCES
    src/api.c
    src/engine.cpp
    src/engine_shims.cpp
    src/file_type.cpp
    src/parsers/safe_reader.cpp
    src/parsers/pe.cpp
    src/parsers/elf.cpp
    src/parsers/pdf.cpp
    src/parsers/ole2.cpp
    src/parsers/ooxml.cpp
    src/signatures/bloom.cpp
    src/signatures/hash_matcher.cpp
    src/signatures/crc_matcher.cpp
    src/signatures/aho_corasick.cpp
    src/signatures/fuzzy_hash.cpp
    src/database/sigdb.cpp
    src/scanner.cpp
    src/parsers/zip.cpp
    src/parsers/gzip.cpp
    src/parsers/tar.cpp
    src/heuristics/static_analyzer.cpp
    src/heuristics/entropy.cpp
    src/heuristics/imports.cpp
    src/heuristics/strings.cpp
    src/heuristics/ml_classifier.cpp
    src/heuristics/dynamic_scorer.cpp
    src/unpacker/upx.cpp
    src/unpacker/generic.cpp
    src/plugin/plugin_loader.cpp
    src/protection/self_protect.cpp
    src/protection/watchdog.cpp
    src/signatures/yara_scanner.cpp
    src/signatures/graph_sig.cpp
    src/emulator/x86_decode.cpp
    src/emulator/x86_emu.cpp
    src/emulator/winapi_stubs.cpp
    src/emulator/pe_loader.cpp
    src/scan_cache.cpp
    src/whitelist.cpp
    src/quarantine/quarantine.cpp
    src/siem/event_serialize.cpp
    src/siem/jsonl_writer.cpp
    src/siem/siem_shipper.cpp
    src/service/cron_parser.cpp
    src/service/scheduler.cpp
    src/update/update_client.cpp
)

add_library(akesoav_core OBJECT ${AKAV_ENGINE_SOURCES})
target_include_directories(akesoav_core
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
)
target_compile_options(akesoav_core PRIVATE ${AKAV_WARNING_FLAGS})
target_compile_definitions(akesoav_core PUBLIC AKAV_BUILD_DLL)
target_link_libraries(akesoav_core PUBLIC ${AKAV_WIN_LIBS} zlibstatic sqlite3_lib yara_lib)
target_include_directories(akesoav_core
    PUBLIC  $<BUILD_INTERFACE:${zlib_BINARY_DIR}>
    PUBLIC  $<BUILD_INTERFACE:${zlib_SOURCE_DIR}>
)

# ── akesoav.dll (core engine DLL) ──
add_library(akesoav SHARED src/dll_main.cpp)
target_link_libraries(akesoav PRIVATE akesoav_core)
target_compile_options(akesoav PRIVATE ${AKAV_WARNING_FLAGS})
set_target_properties(akesoav PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

# ── akavscan.exe (CLI scanner) ──
add_executable(akavscan src/cli/akavscan.c)
target_link_libraries(akavscan PRIVATE akesoav_core)
target_compile_options(akavscan PRIVATE ${AKAV_WARNING_FLAGS})

# ── create_test_db.exe (test .akavdb generator utility) ──
add_executable(create_test_db scripts/create_test_db.cpp)
target_link_libraries(create_test_db PRIVATE akesoav_core)

# ── update_test.exe (update client integration test tool) ──
add_executable(update_test tools/update_test.cpp)
target_link_libraries(update_test PRIVATE akesoav_core)

add_executable(sig_helper tools/sig_helper.cpp)
target_link_libraries(sig_helper PRIVATE akesoav_core)

# ── akesoav-service.exe (Windows service + named pipe) ──
add_executable(akesoav-service src/service/akesoav_service.cpp)
target_link_libraries(akesoav-service PRIVATE akesoav_core)
target_compile_options(akesoav-service PRIVATE ${AKAV_WARNING_FLAGS})

# ── akesoav-watchdog.exe (service health monitor) ──
add_executable(akesoav-watchdog src/protection/watchdog_main.cpp)
target_link_libraries(akesoav-watchdog PRIVATE akesoav_core)
target_compile_options(akesoav-watchdog PRIVATE ${AKAV_WARNING_FLAGS})

# ── EDR integration shim (static lib, runtime-loads akesoav.dll) ──
add_library(akesoav_edr_shim STATIC
    integration/edr_shim.cpp
    integration/edr_shim.h
)
target_include_directories(akesoav_edr_shim
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/integration>
)
target_compile_options(akesoav_edr_shim PRIVATE ${AKAV_WARNING_FLAGS})

# ── AMSI content scanner (static lib for EDR AMSI provider) ──
add_library(akesoav_amsi_scanner STATIC
    integration/edr_amsi_av.cpp
    integration/edr_amsi_av.h
)
target_include_directories(akesoav_amsi_scanner
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/integration>
)
target_compile_options(akesoav_amsi_scanner PRIVATE ${AKAV_WARNING_FLAGS})

# ── Rule evaluator (for EDR YAML detection rules) ──
add_library(akesoav_rule_evaluator STATIC
    rules/rule_evaluator.cpp
    rules/rule_evaluator.h
)
target_include_directories(akesoav_rule_evaluator
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/rules>
)
target_compile_options(akesoav_rule_evaluator PRIVATE ${AKAV_WARNING_FLAGS})

# ── Tests ──
if(AKAV_BUILD_TESTS AND NOT AKAV_BUILD_FUZZ)
    enable_testing()

    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(akesoav_tests
        tests/unit/test_safe_reader.cpp
        tests/unit/test_file_type.cpp
        tests/unit/test_eicar.cpp
        tests/unit/test_engine_lifecycle.cpp
        tests/unit/test_bloom.cpp
        tests/unit/test_hash_matcher.cpp
        tests/unit/test_crc_matcher.cpp
        tests/unit/test_aho_corasick.cpp
        tests/unit/test_sigdb.cpp
        tests/unit/test_scan_pipeline.cpp
        tests/unit/test_pe.cpp
        tests/unit/test_zip.cpp
        tests/unit/test_gzip_tar.cpp
        tests/unit/test_static_analyzer.cpp
        tests/unit/test_entropy_analyzer.cpp
        tests/unit/test_import_analyzer.cpp
        tests/unit/test_string_analyzer.cpp
        tests/unit/test_heuristic_pipeline.cpp
        tests/unit/test_scan_cache.cpp
        tests/unit/test_whitelist.cpp
        tests/unit/test_quarantine.cpp
        tests/unit/test_siem.cpp
        tests/unit/test_scheduler.cpp
        tests/unit/test_fuzzy_hash.cpp
        tests/unit/test_upx.cpp
        tests/unit/test_plugin_loader.cpp
        tests/unit/test_elf.cpp
        tests/unit/test_pdf.cpp
        tests/unit/test_ole2.cpp
        tests/unit/test_x86_decode.cpp
        tests/unit/test_x86_emu.cpp
        tests/unit/test_pe_loader.cpp
        tests/unit/test_generic_unpacker.cpp
        tests/unit/test_yara_scanner.cpp
        tests/unit/test_graph_sig.cpp
        tests/unit/test_ml_classifier.cpp
        tests/unit/test_dynamic_scorer.cpp
        tests/unit/test_self_protect.cpp
        tests/unit/test_update_client.cpp
        tests/unit/test_watchdog.cpp
        tests/unit/test_ooxml.cpp
        tests/hardening/test_parser_resilience.cpp
    )

    target_link_libraries(akesoav_tests PRIVATE
        akesoav_core
        GTest::gtest_main
    )
    target_compile_options(akesoav_tests PRIVATE ${AKAV_WARNING_FLAGS})

    include(GoogleTest)
    gtest_discover_tests(akesoav_tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

    # ── Test plugin DLLs (for plugin loader tests) ──
    add_library(test_plugin_scanner SHARED tests/plugins/test_plugin_scanner.cpp)
    target_include_directories(test_plugin_scanner PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    target_compile_options(test_plugin_scanner PRIVATE ${AKAV_WARNING_FLAGS})

    add_library(test_plugin_bad_version SHARED tests/plugins/test_plugin_bad_version.cpp)
    target_include_directories(test_plugin_bad_version PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    target_compile_options(test_plugin_bad_version PRIVATE ${AKAV_WARNING_FLAGS})

    # Ensure test plugin DLLs are built before running tests
    add_dependencies(akesoav_tests test_plugin_scanner test_plugin_bad_version)

    # ── Service integration tests (separate exe, spawns akesoav-service) ──
    add_executable(akesoav_service_tests
        tests/unit/test_service.cpp
    )
    target_link_libraries(akesoav_service_tests PRIVATE
        GTest::gtest_main
    )
    target_compile_options(akesoav_service_tests PRIVATE ${AKAV_WARNING_FLAGS})
    add_dependencies(akesoav_service_tests akesoav-service)

    gtest_discover_tests(akesoav_service_tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

    # ── EDR rules tests ──
    add_executable(akesoav_edr_rules_tests
        tests/unit/test_edr_rules.cpp
    )
    target_link_libraries(akesoav_edr_rules_tests PRIVATE
        akesoav_rule_evaluator
        GTest::gtest_main
    )
    target_compile_options(akesoav_edr_rules_tests PRIVATE ${AKAV_WARNING_FLAGS})

    gtest_discover_tests(akesoav_edr_rules_tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

    # ── EDR shim integration tests ──
    add_executable(akesoav_edr_shim_tests
        tests/unit/test_edr_shim.cpp
    )
    target_link_libraries(akesoav_edr_shim_tests PRIVATE
        akesoav_edr_shim
        GTest::gtest_main
    )
    target_compile_options(akesoav_edr_shim_tests PRIVATE ${AKAV_WARNING_FLAGS})
    # Depends on akesoav.dll being built (for DLL-present tests)
    add_dependencies(akesoav_edr_shim_tests akesoav)

    gtest_discover_tests(akesoav_edr_shim_tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

    # ── AMSI scanner tests ──
    add_executable(akesoav_amsi_tests
        tests/unit/test_amsi.cpp
    )
    target_link_libraries(akesoav_amsi_tests PRIVATE
        akesoav_amsi_scanner
        GTest::gtest_main
    )
    target_compile_options(akesoav_amsi_tests PRIVATE ${AKAV_WARNING_FLAGS})

    gtest_discover_tests(akesoav_amsi_tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
endif()

# ── Fuzz targets (clang-cl + libFuzzer) ──
if(AKAV_BUILD_FUZZ)
    # Compile everything with fuzzer + ASan instrumentation
    add_compile_options(-fsanitize=fuzzer,address)

    # Find clang runtime library directory for libFuzzer + ASan link libs.
    # clang-cl doesn't auto-link these when CMake invokes lld-link directly.
    execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} /clang:--print-resource-dir
        OUTPUT_VARIABLE CLANG_RESOURCE_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(CLANG_RT_DIR "${CLANG_RESOURCE_DIR}/lib/windows")

    set(AKAV_FUZZ_LINK_LIBS
        "${CLANG_RT_DIR}/clang_rt.fuzzer-x86_64.lib"
        "${CLANG_RT_DIR}/clang_rt.asan_dynamic-x86_64.lib"
        "${CLANG_RT_DIR}/clang_rt.asan_dynamic_runtime_thunk-x86_64.lib"
    )

    # Copy ASan runtime DLL next to fuzz executables so they can run
    file(COPY "${CLANG_RT_DIR}/clang_rt.asan_dynamic-x86_64.dll"
         DESTINATION "${CMAKE_BINARY_DIR}")

    # Macro to add a fuzz target with the correct link libraries
    macro(akav_add_fuzz_target name source)
        add_executable(${name} ${source})
        target_link_libraries(${name} PRIVATE akesoav_core ${AKAV_FUZZ_LINK_LIBS})
    endmacro()

    akav_add_fuzz_target(fuzz_scan_buffer tests/fuzz/fuzz_scan_buffer.cpp)
    akav_add_fuzz_target(fuzz_pe          tests/fuzz/fuzz_pe.cpp)
    akav_add_fuzz_target(fuzz_zip         tests/fuzz/fuzz_zip.cpp)
    akav_add_fuzz_target(fuzz_gzip        tests/fuzz/fuzz_gzip.cpp)
    akav_add_fuzz_target(fuzz_elf         tests/fuzz/fuzz_elf.cpp)
    akav_add_fuzz_target(fuzz_pdf         tests/fuzz/fuzz_pdf.cpp)
    akav_add_fuzz_target(fuzz_ole2        tests/fuzz/fuzz_ole2.cpp)
    akav_add_fuzz_target(fuzz_x86_decode  tests/fuzz/fuzz_x86_decode.cpp)
    akav_add_fuzz_target(fuzz_x86_emu     tests/fuzz/fuzz_x86_emu.cpp)
endif()
