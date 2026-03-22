/* test_scan_cache.cpp -- Unit tests for scan result cache (P5-T1).
 *
 * Tests §5.3 Scan Cache requirements:
 *   - Key: (path, last_modified, file_size)
 *   - SRWLOCK reader-writer (thread safety)
 *   - LRU eviction at capacity
 *   - Invalidation on file change (timestamp/size change → miss)
 *   - Clear on signature reload
 *   - Stats: hit/miss/entries counters
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <thread>
#include <vector>
#include <atomic>

#include "scan_cache.h"
#include "engine_internal.h"

/* ── Helper: build a fake scan result ──────────────────────────── */

static akav_scan_result_t make_result(int found, const char* name,
                                       double heur_score = 0.0) {
    akav_scan_result_t r;
    memset(&r, 0, sizeof(r));
    r.found = found;
    if (name)
        strncpy_s(r.malware_name, sizeof(r.malware_name), name, _TRUNCATE);
    r.heuristic_score = heur_score;
    r.total_size = 1024;
    r.scanned_size = 1024;
    return r;
}

/* ══════════════════════════════════════════════════════════════════
 *  Basic lookup/insert
 * ══════════════════════════════════════════════════════════════════ */

TEST(ScanCache, InsertAndLookup) {
    akav::ScanCache cache(1000);
    auto result = make_result(1, "EICAR-Test-File");

    cache.insert("C:\\test\\eicar.com", 100, 68, result);

    akav_scan_result_t out;
    bool hit = cache.lookup("C:\\test\\eicar.com", 100, 68, &out);
    EXPECT_TRUE(hit);
    EXPECT_EQ(out.found, 1);
    EXPECT_STREQ(out.malware_name, "EICAR-Test-File");
    EXPECT_EQ(out.cached, 1) << "Cached result should have cached=1";
}

TEST(ScanCache, MissOnNonExistent) {
    akav::ScanCache cache(1000);

    akav_scan_result_t out;
    bool hit = cache.lookup("C:\\nonexistent.exe", 100, 1024, &out);
    EXPECT_FALSE(hit);
}

TEST(ScanCache, CleanFileHitAfterRescan) {
    akav::ScanCache cache(1000);
    auto result = make_result(0, nullptr);

    cache.insert("C:\\clean.exe", 200, 4096, result);

    /* Re-scan with same path+timestamp+size → cache hit */
    akav_scan_result_t out;
    bool hit = cache.lookup("C:\\clean.exe", 200, 4096, &out);
    EXPECT_TRUE(hit);
    EXPECT_EQ(out.found, 0);
    EXPECT_EQ(out.cached, 1);
}

/* ══════════════════════════════════════════════════════════════════
 *  Invalidation on file change
 * ══════════════════════════════════════════════════════════════════ */

TEST(ScanCache, InvalidateOnTimestampChange) {
    akav::ScanCache cache(1000);
    auto result = make_result(0, nullptr);

    cache.insert("C:\\file.exe", 100, 4096, result);

    /* Timestamp changed → miss */
    akav_scan_result_t out;
    bool hit = cache.lookup("C:\\file.exe", 200, 4096, &out);
    EXPECT_FALSE(hit) << "Changed timestamp should invalidate cache";
}

TEST(ScanCache, InvalidateOnSizeChange) {
    akav::ScanCache cache(1000);
    auto result = make_result(0, nullptr);

    cache.insert("C:\\file.exe", 100, 4096, result);

    /* Size changed → miss */
    akav_scan_result_t out;
    bool hit = cache.lookup("C:\\file.exe", 100, 8192, &out);
    EXPECT_FALSE(hit) << "Changed file size should invalidate cache";
}

/* ══════════════════════════════════════════════════════════════════
 *  Clear
 * ══════════════════════════════════════════════════════════════════ */

TEST(ScanCache, ClearRemovesAllEntries) {
    akav::ScanCache cache(1000);
    auto result = make_result(0, nullptr);

    cache.insert("C:\\a.exe", 100, 1024, result);
    cache.insert("C:\\b.exe", 200, 2048, result);
    cache.insert("C:\\c.exe", 300, 4096, result);

    EXPECT_EQ(cache.entry_count(), 3u);

    cache.clear();

    EXPECT_EQ(cache.entry_count(), 0u);

    /* All entries should be gone */
    akav_scan_result_t out;
    EXPECT_FALSE(cache.lookup("C:\\a.exe", 100, 1024, &out));
    EXPECT_FALSE(cache.lookup("C:\\b.exe", 200, 2048, &out));
    EXPECT_FALSE(cache.lookup("C:\\c.exe", 300, 4096, &out));
}

TEST(ScanCache, ClearResetsStats) {
    akav::ScanCache cache(1000);
    auto result = make_result(0, nullptr);
    cache.insert("C:\\a.exe", 100, 1024, result);

    akav_scan_result_t out;
    cache.lookup("C:\\a.exe", 100, 1024, &out); /* hit */
    cache.lookup("C:\\b.exe", 200, 2048, &out); /* miss */

    cache.clear();

    uint64_t hits, misses, entries;
    cache.stats(&hits, &misses, &entries);
    EXPECT_EQ(hits, 0u);
    EXPECT_EQ(misses, 0u);
    EXPECT_EQ(entries, 0u);
}

/* ══════════════════════════════════════════════════════════════════
 *  LRU eviction
 * ══════════════════════════════════════════════════════════════════ */

TEST(ScanCache, LruEvictionAtCapacity) {
    akav::ScanCache cache(3); /* capacity = 3 */
    auto r0 = make_result(0, nullptr);

    cache.insert("C:\\1.exe", 100, 100, r0);
    cache.insert("C:\\2.exe", 100, 200, r0);
    cache.insert("C:\\3.exe", 100, 300, r0);
    EXPECT_EQ(cache.entry_count(), 3u);

    /* Insert a 4th — should evict the LRU (1.exe, inserted first) */
    cache.insert("C:\\4.exe", 100, 400, r0);
    EXPECT_EQ(cache.entry_count(), 3u);

    /* 1.exe should be evicted */
    akav_scan_result_t out;
    EXPECT_FALSE(cache.lookup("C:\\1.exe", 100, 100, &out))
        << "LRU entry should be evicted";

    /* 2, 3, 4 should still be present */
    EXPECT_TRUE(cache.lookup("C:\\2.exe", 100, 200, &out));
    EXPECT_TRUE(cache.lookup("C:\\3.exe", 100, 300, &out));
    EXPECT_TRUE(cache.lookup("C:\\4.exe", 100, 400, &out));
}

TEST(ScanCache, LruPromotionOnAccess) {
    akav::ScanCache cache(3);
    auto r0 = make_result(0, nullptr);

    cache.insert("C:\\1.exe", 100, 100, r0);
    cache.insert("C:\\2.exe", 100, 200, r0);
    cache.insert("C:\\3.exe", 100, 300, r0);

    /* Access 1.exe to promote it (no longer LRU) */
    akav_scan_result_t out;
    cache.lookup("C:\\1.exe", 100, 100, &out);

    /* Insert 4th — should evict 2.exe (now LRU) instead of 1.exe */
    cache.insert("C:\\4.exe", 100, 400, r0);

    EXPECT_TRUE(cache.lookup("C:\\1.exe", 100, 100, &out))
        << "Recently accessed entry should NOT be evicted";
    EXPECT_FALSE(cache.lookup("C:\\2.exe", 100, 200, &out))
        << "Least recently accessed entry should be evicted";
}

TEST(ScanCache, SetMaxEntriesEvictsExcess) {
    akav::ScanCache cache(10);
    auto r0 = make_result(0, nullptr);

    for (int i = 0; i < 10; i++) {
        char path[64];
        snprintf(path, sizeof(path), "C:\\%d.exe", i);
        cache.insert(path, 100, (int64_t)(i * 100 + 100), r0);
    }
    EXPECT_EQ(cache.entry_count(), 10u);

    /* Reduce capacity to 5 — should evict 5 LRU entries */
    cache.set_max_entries(5);
    EXPECT_EQ(cache.entry_count(), 5u);
}

/* ══════════════════════════════════════════════════════════════════
 *  Stats
 * ══════════════════════════════════════════════════════════════════ */

TEST(ScanCache, StatsCorrect) {
    akav::ScanCache cache(1000);
    auto result = make_result(1, "TestMalware");

    cache.insert("C:\\a.exe", 100, 1024, result);

    akav_scan_result_t out;
    cache.lookup("C:\\a.exe", 100, 1024, &out); /* hit */
    cache.lookup("C:\\a.exe", 100, 1024, &out); /* hit */
    cache.lookup("C:\\b.exe", 200, 2048, &out); /* miss */

    uint64_t hits, misses, entries;
    cache.stats(&hits, &misses, &entries);
    EXPECT_EQ(hits, 2u);
    EXPECT_EQ(misses, 1u);
    EXPECT_EQ(entries, 1u);
}

/* ══════════════════════════════════════════════════════════════════
 *  Update existing entry
 * ══════════════════════════════════════════════════════════════════ */

TEST(ScanCache, UpdateExistingEntry) {
    akav::ScanCache cache(1000);
    auto r1 = make_result(0, nullptr);
    cache.insert("C:\\file.exe", 100, 4096, r1);

    /* Update with new result */
    auto r2 = make_result(1, "NewDetection");
    cache.insert("C:\\file.exe", 100, 4096, r2);

    akav_scan_result_t out;
    bool hit = cache.lookup("C:\\file.exe", 100, 4096, &out);
    EXPECT_TRUE(hit);
    EXPECT_EQ(out.found, 1);
    EXPECT_STREQ(out.malware_name, "NewDetection");

    /* Entry count should still be 1 (updated, not duplicated) */
    EXPECT_EQ(cache.entry_count(), 1u);
}

/* ══════════════════════════════════════════════════════════════════
 *  Thread safety (two threads, no race)
 * ══════════════════════════════════════════════════════════════════ */

TEST(ScanCache, ConcurrentReadWrite) {
    akav::ScanCache cache(10000);
    std::atomic<bool> done{false};
    std::atomic<int> hit_count{0};
    std::atomic<int> miss_count{0};

    /* Writer thread: continuously insert entries */
    std::thread writer([&]() {
        for (int i = 0; i < 5000; i++) {
            char path[64];
            snprintf(path, sizeof(path), "C:\\%d.exe", i);
            auto r = make_result(i % 2, i % 2 ? "Malware" : nullptr);
            cache.insert(path, 100, (int64_t)(i * 100), r);
        }
        done = true;
    });

    /* Reader thread: continuously lookup entries */
    std::thread reader([&]() {
        akav_scan_result_t out;
        int local_hits = 0, local_misses = 0;
        while (!done.load() || local_hits + local_misses < 5000) {
            char path[64];
            int idx = (local_hits + local_misses) % 5000;
            snprintf(path, sizeof(path), "C:\\%d.exe", idx);
            if (cache.lookup(path, 100, (int64_t)(idx * 100), &out))
                local_hits++;
            else
                local_misses++;
            if (local_hits + local_misses >= 10000) break;
        }
        hit_count = local_hits;
        miss_count = local_misses;
    });

    writer.join();
    reader.join();

    /* No crashes, and stats should be consistent */
    uint64_t stats_hits, stats_misses, stats_entries;
    cache.stats(&stats_hits, &stats_misses, &stats_entries);
    EXPECT_GT(stats_entries, 0u);
    /* Just verify no crash and reasonable stats */
    EXPECT_GE(hit_count.load() + miss_count.load(), 1);
}

TEST(ScanCache, ConcurrentMultipleReaders) {
    akav::ScanCache cache(1000);

    /* Pre-populate */
    for (int i = 0; i < 100; i++) {
        char path[64];
        snprintf(path, sizeof(path), "C:\\%d.exe", i);
        auto r = make_result(0, nullptr);
        cache.insert(path, 100, (int64_t)(i * 100), r);
    }

    /* Launch 4 reader threads */
    std::atomic<int> total_hits{0};
    auto reader_fn = [&]() {
        int hits = 0;
        akav_scan_result_t out;
        for (int i = 0; i < 100; i++) {
            char path[64];
            snprintf(path, sizeof(path), "C:\\%d.exe", i);
            if (cache.lookup(path, 100, (int64_t)(i * 100), &out))
                hits++;
        }
        total_hits += hits;
    };

    std::vector<std::thread> threads;
    for (int t = 0; t < 4; t++)
        threads.emplace_back(reader_fn);
    for (auto& t : threads)
        t.join();

    /* All 4 readers should hit all 100 entries */
    EXPECT_EQ(total_hits.load(), 400);
}

/* ══════════════════════════════════════════════════════════════════
 *  Engine integration: cache hit on unchanged re-scan
 * ══════════════════════════════════════════════════════════════════ */

TEST(ScanCacheEngine, CacheHitOnRescan) {
    akav::Engine engine;
    ASSERT_EQ(engine.init(nullptr), AKAV_OK);

    /* Write a temp file */
    const char* path = "test_cache_tmp.bin";
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    ASSERT_NE(f, nullptr);
    const char* content = "This is clean test content for caching.";
    fwrite(content, 1, strlen(content), f);
    fclose(f);

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_cache = 1;

    /* First scan — should be a cache miss */
    akav_scan_result_t r1;
    ASSERT_EQ(engine.scan_file(path, &opts, &r1), AKAV_OK);
    EXPECT_EQ(r1.cached, 0);

    /* Second scan (unchanged file) — should be a cache hit */
    akav_scan_result_t r2;
    ASSERT_EQ(engine.scan_file(path, &opts, &r2), AKAV_OK);
    EXPECT_EQ(r2.cached, 1) << "Re-scan of unchanged file should be cached";
    EXPECT_EQ(r2.found, r1.found);

    /* Stats should show 1 hit, 1 miss */
    uint64_t hits, misses, entries;
    engine.cache_stats(&hits, &misses, &entries);
    EXPECT_EQ(hits, 1u);
    EXPECT_EQ(misses, 1u);
    EXPECT_EQ(entries, 1u);

    remove(path);
}

TEST(ScanCacheEngine, ModifiedFileCacheMiss) {
    akav::Engine engine;
    ASSERT_EQ(engine.init(nullptr), AKAV_OK);

    const char* path = "test_cache_mod_tmp.bin";
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_cache = 1;

    /* Write and scan first version */
    {
        FILE* f = nullptr;
        fopen_s(&f, path, "wb");
        ASSERT_NE(f, nullptr);
        const char* content = "Version 1 content";
        fwrite(content, 1, strlen(content), f);
        fclose(f);
    }

    akav_scan_result_t r1;
    ASSERT_EQ(engine.scan_file(path, &opts, &r1), AKAV_OK);
    EXPECT_EQ(r1.cached, 0);

    /* Small delay to ensure timestamp changes */
    Sleep(50);

    /* Modify file (different size) */
    {
        FILE* f = nullptr;
        fopen_s(&f, path, "wb");
        ASSERT_NE(f, nullptr);
        const char* content = "Version 2 content with more data here";
        fwrite(content, 1, strlen(content), f);
        fclose(f);
    }

    /* Re-scan — should be a miss (file changed) */
    akav_scan_result_t r2;
    ASSERT_EQ(engine.scan_file(path, &opts, &r2), AKAV_OK);
    EXPECT_EQ(r2.cached, 0) << "Modified file should not be served from cache";

    remove(path);
}

TEST(ScanCacheEngine, ClearOnSigReload) {
    akav::Engine engine;
    ASSERT_EQ(engine.init(nullptr), AKAV_OK);

    const char* path = "test_cache_reload_tmp.bin";
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_cache = 1;

    /* Write and scan */
    {
        FILE* f = nullptr;
        fopen_s(&f, path, "wb");
        ASSERT_NE(f, nullptr);
        const char* content = "Test content for reload";
        fwrite(content, 1, strlen(content), f);
        fclose(f);
    }

    akav_scan_result_t r1;
    ASSERT_EQ(engine.scan_file(path, &opts, &r1), AKAV_OK);
    EXPECT_EQ(r1.cached, 0);

    /* Verify it's cached */
    akav_scan_result_t r2;
    ASSERT_EQ(engine.scan_file(path, &opts, &r2), AKAV_OK);
    EXPECT_EQ(r2.cached, 1);

    /* Clear cache (simulating sig reload) */
    engine.cache_clear();

    /* Re-scan — should be a miss now */
    akav_scan_result_t r3;
    ASSERT_EQ(engine.scan_file(path, &opts, &r3), AKAV_OK);
    EXPECT_EQ(r3.cached, 0) << "Cache should be cleared after sig reload";

    remove(path);
}

TEST(ScanCacheEngine, CacheDisabledByOption) {
    akav::Engine engine;
    ASSERT_EQ(engine.init(nullptr), AKAV_OK);

    const char* path = "test_cache_disabled_tmp.bin";
    {
        FILE* f = nullptr;
        fopen_s(&f, path, "wb");
        ASSERT_NE(f, nullptr);
        const char* content = "Content";
        fwrite(content, 1, strlen(content), f);
        fclose(f);
    }

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_cache = 0;

    akav_scan_result_t r1;
    ASSERT_EQ(engine.scan_file(path, &opts, &r1), AKAV_OK);

    /* Second scan with cache disabled — should NOT be cached */
    akav_scan_result_t r2;
    ASSERT_EQ(engine.scan_file(path, &opts, &r2), AKAV_OK);
    EXPECT_EQ(r2.cached, 0) << "Cache disabled — should not hit";

    /* Stats should show 0 entries */
    uint64_t hits, misses, entries;
    engine.cache_stats(&hits, &misses, &entries);
    EXPECT_EQ(entries, 0u);

    remove(path);
}
