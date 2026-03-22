/* scan_cache.cpp -- Thread-safe scan result cache with LRU eviction.
 *
 * Implements §5.3 Scan Cache:
 *   - Key: (path, last_modified, file_size)
 *   - Value: akav_scan_result_t
 *   - SRWLOCK reader-writer
 *   - LRU eviction at configurable capacity (default 50,000)
 */

#include "scan_cache.h"
#include <cstring>

namespace akav {

ScanCache::ScanCache(uint32_t max_entries)
    : max_entries_(max_entries)
{
    InitializeSRWLock(&lock_);
}

ScanCache::~ScanCache()
{
    /* SRWLOCK does not need explicit destruction on Windows */
}

bool ScanCache::lookup(const std::string& path, int64_t last_modified,
                        int64_t file_size, akav_scan_result_t* out)
{
    CacheKey key{path, last_modified, file_size};

    AcquireSRWLockShared(&lock_);

    auto it = map_.find(key);
    if (it == map_.end()) {
        misses_++;
        ReleaseSRWLockShared(&lock_);
        return false;
    }

    /* Found — copy result */
    if (out) {
        memcpy(out, &it->second.first.result, sizeof(akav_scan_result_t));
        out->cached = 1;
    }
    hits_++;

    ReleaseSRWLockShared(&lock_);

    /* Promote to front of LRU (requires exclusive lock).
     * We do this outside the shared lock to avoid lock upgrade.
     * This is a best-effort LRU — slight reordering races are acceptable. */
    AcquireSRWLockExclusive(&lock_);
    auto it2 = map_.find(key);
    if (it2 != map_.end()) {
        lru_.erase(it2->second.second);
        lru_.push_front(key);
        it2->second.second = lru_.begin();
    }
    ReleaseSRWLockExclusive(&lock_);

    return true;
}

void ScanCache::insert(const std::string& path, int64_t last_modified,
                        int64_t file_size, const akav_scan_result_t& result)
{
    CacheKey key{path, last_modified, file_size};

    AcquireSRWLockExclusive(&lock_);

    /* Update existing entry if present */
    auto it = map_.find(key);
    if (it != map_.end()) {
        memcpy(&it->second.first.result, &result, sizeof(akav_scan_result_t));
        /* Move to front of LRU */
        lru_.erase(it->second.second);
        lru_.push_front(key);
        it->second.second = lru_.begin();
        ReleaseSRWLockExclusive(&lock_);
        return;
    }

    /* Evict if at capacity */
    while (map_.size() >= max_entries_ && !lru_.empty()) {
        evict_lru_locked();
    }

    /* Insert new entry */
    lru_.push_front(key);
    CacheEntry entry;
    memcpy(&entry.result, &result, sizeof(akav_scan_result_t));
    map_[key] = {entry, lru_.begin()};

    ReleaseSRWLockExclusive(&lock_);
}

void ScanCache::clear()
{
    AcquireSRWLockExclusive(&lock_);
    map_.clear();
    lru_.clear();
    hits_ = 0;
    misses_ = 0;
    ReleaseSRWLockExclusive(&lock_);
}

void ScanCache::stats(uint64_t* hits, uint64_t* misses, uint64_t* entries) const
{
    AcquireSRWLockShared(&lock_);
    if (hits)    *hits = hits_;
    if (misses)  *misses = misses_;
    if (entries) *entries = (uint64_t)map_.size();
    ReleaseSRWLockShared(&lock_);
}

uint32_t ScanCache::entry_count() const
{
    AcquireSRWLockShared(&lock_);
    uint32_t count = (uint32_t)map_.size();
    ReleaseSRWLockShared(&lock_);
    return count;
}

void ScanCache::set_max_entries(uint32_t max_entries)
{
    AcquireSRWLockExclusive(&lock_);
    max_entries_ = max_entries;
    /* Evict excess entries */
    while (map_.size() > max_entries_ && !lru_.empty()) {
        evict_lru_locked();
    }
    ReleaseSRWLockExclusive(&lock_);
}

void ScanCache::evict_lru_locked()
{
    /* Remove the least recently used entry (back of LRU list) */
    if (lru_.empty()) return;
    auto& oldest_key = lru_.back();
    map_.erase(oldest_key);
    lru_.pop_back();
}

} /* namespace akav */
