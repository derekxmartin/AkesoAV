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

# ── Windows libraries ──
set(AKAV_WIN_LIBS bcrypt.lib crypt32.lib wintrust.lib)

# ── Core engine sources (static lib shared by DLL and tests) ──
set(AKAV_ENGINE_SOURCES
    src/api.c
    src/engine.cpp
    src/engine_shims.cpp
    src/file_type.cpp
    src/parsers/safe_reader.cpp
    src/parsers/pe.cpp
    src/signatures/bloom.cpp
    src/signatures/hash_matcher.cpp
    src/signatures/crc_matcher.cpp
    src/signatures/aho_corasick.cpp
    src/database/sigdb.cpp
    src/scanner.cpp
    src/parsers/zip.cpp
    src/parsers/gzip.cpp
    src/parsers/tar.cpp
)

add_library(akesoav_core OBJECT ${AKAV_ENGINE_SOURCES})
target_include_directories(akesoav_core
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
)
target_compile_options(akesoav_core PRIVATE ${AKAV_WARNING_FLAGS})
target_compile_definitions(akesoav_core PUBLIC AKAV_BUILD_DLL)
target_link_libraries(akesoav_core PUBLIC ${AKAV_WIN_LIBS} zlibstatic)
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
endif()
