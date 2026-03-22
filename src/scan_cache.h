#ifndef AKAV_SCAN_CACHE_H
#define AKAV_SCAN_CACHE_H

/* scan_cache.h -- Thread-safe scan result cache with LRU eviction.
 *
 * Key:   (file_path, last_modified_timestamp, file_size)
 * Value: akav_scan_result_t (full cached result)
 *
 * Thread safety: SRWLOCK reader-writer pattern.
 *   - Lookups acquire shared (read) lock
 *   - Inserts/evictions acquire exclusive (write) lock
 *
 * Invalidation:
 *   - Automatic: changed timestamp or size → cache miss
 *   - Explicit:  akav_scan_cache_clear() on sig reload
 *   - Capacity:  LRU eviction at max_entries (default 50,000)
 */

#ifdef __cplusplus

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "akesoav.h"
#include <string>
#include <unordered_map>
#include <list>
#include <cstdint>

namespace akav {

struct CacheKey {
    std::string path;
    int64_t     last_modified;  /* FILETIME as 64-bit int */
    int64_t     file_size;

    bool operator==(const CacheKey& o) const {
        return path == o.path &&
               last_modified == o.last_modified &&
               file_size == o.file_size;
    }
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& k) const {
        /* FNV-1a inspired combine */
        size_t h = std::hash<std::string>{}(k.path);
        h ^= std::hash<int64_t>{}(k.last_modified) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<int64_t>{}(k.file_size) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct CacheEntry {
    akav_scan_result_t result;
};

class ScanCache {
public:
    explicit ScanCache(uint32_t max_entries = 50000);
    ~ScanCache();

    ScanCache(const ScanCache&) = delete;
    ScanCache& operator=(const ScanCache&) = delete;

    /**
     * Look up a cached result.
     * Returns true if found (and copies result to *out).
     * Thread-safe (shared lock).
     */
    bool lookup(const std::string& path, int64_t last_modified,
                int64_t file_size, akav_scan_result_t* out);

    /**
     * Insert or update a cached result.
     * Thread-safe (exclusive lock). Evicts LRU if at capacity.
     */
    void insert(const std::string& path, int64_t last_modified,
                int64_t file_size, const akav_scan_result_t& result);

    /**
     * Clear all cached entries. Called on signature reload.
     * Thread-safe (exclusive lock).
     */
    void clear();

    /**
     * Get cache statistics.
     * Thread-safe (shared lock).
     */
    void stats(uint64_t* hits, uint64_t* misses, uint64_t* entries) const;

    /**
     * Get current entry count (for testing).
     */
    uint32_t entry_count() const;

    /**
     * Set max capacity (for testing).
     */
    void set_max_entries(uint32_t max_entries);

private:
    void evict_lru_locked();

    /* LRU list: front = most recently used, back = least recently used */
    using LruList = std::list<CacheKey>;
    using MapType = std::unordered_map<CacheKey, std::pair<CacheEntry, LruList::iterator>,
                                        CacheKeyHash>;

    MapType   map_;
    LruList   lru_;
    uint32_t  max_entries_;

    mutable SRWLOCK lock_;

    /* Stats (updated under write lock for inserts, read lock for lookups) */
    mutable uint64_t hits_{0};
    mutable uint64_t misses_{0};
};

} /* namespace akav */

#endif /* __cplusplus */

#endif /* AKAV_SCAN_CACHE_H */
