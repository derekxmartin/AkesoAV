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

# ── Compiler warnings ──
if(MSVC)
    add_compile_options(/W4 /WX)
    if(NOT AKAV_BUILD_FUZZ)
        # /analyze can be enabled per-target or globally; enable globally for CI
        # add_compile_options(/analyze)
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -Werror)
endif()

# ── Windows libraries ──
set(AKAV_WIN_LIBS bcrypt.lib crypt32.lib wintrust.lib)

# ── Core engine sources (static lib shared by DLL and tests) ──
set(AKAV_ENGINE_SOURCES
    src/api.c
    src/engine.cpp
    src/engine_shims.cpp
    src/file_type.cpp
    src/parsers/safe_reader.cpp
    src/signatures/bloom.cpp
    src/signatures/hash_matcher.cpp
    src/signatures/crc_matcher.cpp
    src/signatures/aho_corasick.cpp
    src/database/sigdb.cpp
)

add_library(akesoav_core STATIC ${AKAV_ENGINE_SOURCES})
target_include_directories(akesoav_core
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
)
target_compile_definitions(akesoav_core PUBLIC AKAV_BUILD_DLL)
target_link_libraries(akesoav_core PUBLIC ${AKAV_WIN_LIBS})

# ── akesoav.dll (core engine DLL) ──
add_library(akesoav SHARED src/dll_main.cpp)
target_link_libraries(akesoav PRIVATE akesoav_core)
set_target_properties(akesoav PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS OFF)

# ── akavscan.exe (CLI scanner) ──
add_executable(akavscan src/cli/akavscan.c)
target_link_libraries(akavscan PRIVATE akesoav_core)

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
    )

    target_link_libraries(akesoav_tests PRIVATE
        akesoav_core
        GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(akesoav_tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
endif()

# ── Fuzz targets (clang-cl + libFuzzer) ──
if(AKAV_BUILD_FUZZ)
    add_compile_options(-fsanitize=fuzzer,address)
    add_link_options(-fsanitize=fuzzer,address)

    add_executable(fuzz_scan_buffer tests/fuzz/fuzz_scan_buffer.cpp)
    target_link_libraries(fuzz_scan_buffer PRIVATE akesoav_core)
endif()
