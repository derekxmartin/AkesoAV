#include <gtest/gtest.h>
#include "akesoav.h"
#include <cstring>

TEST(EngineLifecycle, CreateInitDestroy)
{
    akav_engine_t* engine = nullptr;
    ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);
    ASSERT_NE(engine, nullptr);
    ASSERT_EQ(akav_engine_init(engine, nullptr), AKAV_OK);
    ASSERT_EQ(akav_engine_destroy(engine), AKAV_OK);
}

TEST(EngineLifecycle, CreateNullPtr)
{
    EXPECT_EQ(akav_engine_create(nullptr), AKAV_ERROR_INVALID);
}

TEST(EngineLifecycle, InitNullEngine)
{
    EXPECT_EQ(akav_engine_init(nullptr, nullptr), AKAV_ERROR_INVALID);
}

TEST(EngineLifecycle, DestroyNullEngine)
{
    EXPECT_EQ(akav_engine_destroy(nullptr), AKAV_ERROR_INVALID);
}

TEST(EngineLifecycle, ScanBeforeInit)
{
    akav_engine_t* engine = nullptr;
    ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);

    /* Engine created but not initialized — scan should fail */
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    const uint8_t data[] = {0x01};
    EXPECT_EQ(akav_scan_buffer(engine, data, 1, "test", &opts, &result),
              AKAV_ERROR_NOT_INIT);

    akav_engine_destroy(engine);
}

TEST(EngineLifecycle, VersionString)
{
    const char* ver = akav_engine_version();
    ASSERT_NE(ver, nullptr);
    EXPECT_STRNE(ver, "");
}

TEST(EngineLifecycle, StrerrorAllCodes)
{
    EXPECT_STRNE(akav_strerror(AKAV_OK), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_INVALID), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_NOMEM), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_IO), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_DB), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_TIMEOUT), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_SIGNATURE), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_NOT_INIT), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_BOMB), "");
    EXPECT_STRNE(akav_strerror(AKAV_ERROR_SCAN), "");
}

TEST(EngineLifecycle, DefaultOptions)
{
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    EXPECT_EQ(opts.scan_archives, 1);
    EXPECT_EQ(opts.scan_packed, 1);
    EXPECT_EQ(opts.use_heuristics, 1);
    EXPECT_EQ(opts.heuristic_level, AKAV_HEUR_MEDIUM);
    EXPECT_EQ(opts.max_filesize, 0);
    EXPECT_EQ(opts.max_scan_depth, 10);
    EXPECT_EQ(opts.timeout_ms, 30000);
    EXPECT_EQ(opts.use_cache, 1);
    EXPECT_EQ(opts.use_whitelist, 1);
}

TEST(EngineLifecycle, CacheStatsInitial)
{
    akav_engine_t* engine = nullptr;
    ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);
    ASSERT_EQ(akav_engine_init(engine, nullptr), AKAV_OK);

    uint64_t hits, misses, entries;
    ASSERT_EQ(akav_cache_stats(engine, &hits, &misses, &entries), AKAV_OK);
    EXPECT_EQ(hits, 0u);
    EXPECT_EQ(misses, 0u);
    EXPECT_EQ(entries, 0u);

    akav_engine_destroy(engine);
}
