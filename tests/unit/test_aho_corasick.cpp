#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>
#include <set>

extern "C" {
#include "signatures/aho_corasick.h"
}

/* ── Helpers ──────────────────────────────────────────────────────── */

struct MatchCollector {
    std::vector<akav_ac_match_t> matches;
};

static bool collect_match(const akav_ac_match_t* match, void* user_data)
{
    auto* collector = static_cast<MatchCollector*>(user_data);
    collector->matches.push_back(*match);
    return true; /* continue */
}

static bool stop_after_first(const akav_ac_match_t* match, void* user_data)
{
    auto* collector = static_cast<MatchCollector*>(user_data);
    collector->matches.push_back(*match);
    return false; /* stop */
}

/* ── Fixture ──────────────────────────────────────────────────────── */

class AhoCorasickTest : public ::testing::Test {
protected:
    akav_ac_t* ac = nullptr;

    void SetUp() override
    {
        ac = akav_ac_create();
        ASSERT_NE(ac, nullptr);
    }

    void TearDown() override
    {
        akav_ac_destroy(ac);
    }

    void add(const char* pattern, uint32_t id)
    {
        ASSERT_TRUE(akav_ac_add_pattern(
            ac, reinterpret_cast<const uint8_t*>(pattern),
            static_cast<uint32_t>(strlen(pattern)), id));
    }

    void add_bytes(const uint8_t* pattern, uint32_t len, uint32_t id)
    {
        ASSERT_TRUE(akav_ac_add_pattern(ac, pattern, len, id));
    }
};

/* ── Basic tests ──────────────────────────────────────────────────── */

TEST_F(AhoCorasickTest, CreateDestroy)
{
    EXPECT_EQ(akav_ac_pattern_count(ac), 0u);
}

TEST_F(AhoCorasickTest, SinglePattern)
{
    add("hello", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "say hello world";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, sizeof(input) - 1,
                                     collect_match, &mc);
    EXPECT_EQ(count, 1u);
    ASSERT_EQ(mc.matches.size(), 1u);
    EXPECT_EQ(mc.matches[0].pattern_id, 1u);
    EXPECT_EQ(mc.matches[0].offset, 8u); /* end of "hello" at index 8 */
    EXPECT_EQ(mc.matches[0].pattern_len, 5u);
}

TEST_F(AhoCorasickTest, MultiplePatterns)
{
    add("he", 1);
    add("she", 2);
    add("his", 3);
    add("hers", 4);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "ushers";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, sizeof(input) - 1,
                                     collect_match, &mc);

    /* Expected: "she" at 1-3, "he" at 2-3, "hers" at 2-5 */
    EXPECT_GE(count, 3u);

    std::set<uint32_t> ids;
    for (auto& m : mc.matches) ids.insert(m.pattern_id);
    EXPECT_TRUE(ids.count(1)); /* "he" */
    EXPECT_TRUE(ids.count(2)); /* "she" */
    EXPECT_TRUE(ids.count(4)); /* "hers" */
}

TEST_F(AhoCorasickTest, OverlappingPatterns)
{
    add("abc", 1);
    add("bc", 2);
    add("c", 3);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "abc";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, 3, collect_match, &mc);
    EXPECT_EQ(count, 3u); /* all three overlap at the end */
}

TEST_F(AhoCorasickTest, NoMatch)
{
    add("xyz", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "hello world";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, sizeof(input) - 1,
                                     collect_match, &mc);
    EXPECT_EQ(count, 0u);
    EXPECT_TRUE(mc.matches.empty());
}

/* ── Null bytes in patterns ───────────────────────────────────────── */

TEST_F(AhoCorasickTest, NullBytesInPattern)
{
    const uint8_t pattern[] = {0x00, 0x41, 0x00, 0x42};
    add_bytes(pattern, 4, 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = {0xFF, 0x00, 0x41, 0x00, 0x42, 0xFF};
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, sizeof(input),
                                     collect_match, &mc);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(mc.matches[0].pattern_id, 1u);
}

TEST_F(AhoCorasickTest, AllNullPattern)
{
    const uint8_t pattern[] = {0x00, 0x00, 0x00};
    add_bytes(pattern, 3, 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = {0x00, 0x00, 0x00, 0x00};
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, sizeof(input),
                                     collect_match, &mc);
    EXPECT_GE(count, 2u); /* matches at offset 2 and 3 */
}

/* ── Empty/null input handling ────────────────────────────────────── */

TEST_F(AhoCorasickTest, EmptyInput)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    uint32_t count = akav_ac_search(ac, (const uint8_t*)"", 0,
                                     collect_match, nullptr);
    EXPECT_EQ(count, 0u);
}

TEST_F(AhoCorasickTest, NullInput)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    uint32_t count = akav_ac_search(ac, nullptr, 100, collect_match, nullptr);
    EXPECT_EQ(count, 0u);
}

TEST_F(AhoCorasickTest, SearchBeforeFinalize)
{
    add("test", 1);
    /* Don't finalize */
    uint32_t count = akav_ac_search(ac, (const uint8_t*)"test", 4,
                                     collect_match, nullptr);
    EXPECT_EQ(count, 0u);
}

/* ── Callback control ─────────────────────────────────────────────── */

TEST_F(AhoCorasickTest, StopAfterFirstMatch)
{
    add("a", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "aaaa";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, 4, stop_after_first, &mc);

    /* Callback stopped after first, but count reflects how many were
       found up to that point */
    EXPECT_EQ(mc.matches.size(), 1u);
    EXPECT_GE(count, 1u);
}

TEST_F(AhoCorasickTest, NullCallback)
{
    add("abc", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "xabcxabcx";
    uint32_t count = akav_ac_search(ac, input, sizeof(input) - 1,
                                     nullptr, nullptr);
    EXPECT_EQ(count, 2u);
}

/* ── Serialization round-trip ─────────────────────────────────────── */

TEST_F(AhoCorasickTest, SerializeDeserialize)
{
    add("foo", 10);
    add("bar", 20);
    add("foobar", 30);
    ASSERT_TRUE(akav_ac_finalize(ac));

    /* Serialize */
    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    ASSERT_GT(needed, 0u);

    std::vector<uint8_t> buf(needed);
    size_t written = akav_ac_serialize(ac, buf.data(), buf.size());
    ASSERT_EQ(written, needed);

    /* Deserialize */
    akav_ac_t* ac2 = akav_ac_deserialize(buf.data(), buf.size());
    ASSERT_NE(ac2, nullptr);
    EXPECT_EQ(akav_ac_pattern_count(ac2), 3u);

    /* Verify search produces same results */
    const uint8_t input[] = "xfoobarx";
    MatchCollector mc1, mc2;
    akav_ac_search(ac, input, sizeof(input) - 1, collect_match, &mc1);
    akav_ac_search(ac2, input, sizeof(input) - 1, collect_match, &mc2);

    EXPECT_EQ(mc1.matches.size(), mc2.matches.size());

    std::set<uint32_t> ids1, ids2;
    for (auto& m : mc1.matches) ids1.insert(m.pattern_id);
    for (auto& m : mc2.matches) ids2.insert(m.pattern_id);
    EXPECT_EQ(ids1, ids2);

    akav_ac_destroy(ac2);
}

TEST_F(AhoCorasickTest, DeserializeInvalid)
{
    EXPECT_EQ(akav_ac_deserialize(nullptr, 0), nullptr);

    uint8_t garbage[32] = {};
    EXPECT_EQ(akav_ac_deserialize(garbage, sizeof(garbage)), nullptr);

    /* Too small buffer */
    uint8_t tiny[4] = {};
    EXPECT_EQ(akav_ac_deserialize(tiny, sizeof(tiny)), nullptr);
}

TEST_F(AhoCorasickTest, SerializeBeforeFinalize)
{
    add("test", 1);
    size_t s = akav_ac_serialize(ac, nullptr, 0);
    EXPECT_EQ(s, 0u); /* can't serialize unfinalized */
}

/* ── Scale: 1K patterns vs 10MB ───────────────────────────────────── */

TEST_F(AhoCorasickTest, OneThousandPatternsVsTenMB)
{
    const uint32_t N = 1000;
    for (uint32_t i = 0; i < N; i++) {
        std::string pat = "pattern_" + std::to_string(i) + "_end";
        ASSERT_TRUE(akav_ac_add_pattern(
            ac, reinterpret_cast<const uint8_t*>(pat.data()),
            static_cast<uint32_t>(pat.size()), i));
    }
    ASSERT_TRUE(akav_ac_finalize(ac));
    EXPECT_EQ(akav_ac_pattern_count(ac), N);

    /* Build 10MB input with a few patterns embedded */
    const size_t INPUT_SIZE = 10 * 1024 * 1024;
    std::vector<uint8_t> input(INPUT_SIZE, 'X');

    /* Plant some matches */
    const char* p0 = "pattern_0_end";
    const char* p500 = "pattern_500_end";
    const char* p999 = "pattern_999_end";
    memcpy(input.data() + 1000, p0, strlen(p0));
    memcpy(input.data() + INPUT_SIZE / 2, p500, strlen(p500));
    memcpy(input.data() + INPUT_SIZE - 100, p999, strlen(p999));

    auto start = std::chrono::high_resolution_clock::now();
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input.data(), input.size(),
                                     collect_match, &mc);
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    EXPECT_EQ(count, 3u);
    EXPECT_LT(ms, 500) << "1K patterns vs 10MB took " << ms << "ms (limit: 500ms)";
}

/* ── Thread safety: two threads scanning simultaneously ───────────── */

TEST_F(AhoCorasickTest, ConcurrentSearch)
{
    add("needle", 1);
    add("haystack", 2);
    ASSERT_TRUE(akav_ac_finalize(ac));

    /* Two different inputs */
    const std::string input1(10000, 'a');
    const std::string input2 = "find the needle in the haystack here";

    std::atomic<uint32_t> count1{0}, count2{0};

    auto worker = [&](const std::string& input, std::atomic<uint32_t>& out) {
        for (int iter = 0; iter < 100; iter++) {
            uint32_t c = akav_ac_search(ac,
                reinterpret_cast<const uint8_t*>(input.data()),
                input.size(), nullptr, nullptr);
            out.store(c, std::memory_order_relaxed);
        }
    };

    std::thread t1(worker, std::cref(input1), std::ref(count1));
    std::thread t2(worker, std::cref(input2), std::ref(count2));

    t1.join();
    t2.join();

    EXPECT_EQ(count1.load(), 0u); /* no patterns in all-'a' input */
    EXPECT_EQ(count2.load(), 2u); /* "needle" + "haystack" */
}

/* ── Edge cases ───────────────────────────────────────────────────── */

TEST_F(AhoCorasickTest, SingleBytePattern)
{
    const uint8_t pat = 0xFF;
    add_bytes(&pat, 1, 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = {0x00, 0xFF, 0x00, 0xFF, 0xFF};
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, sizeof(input),
                                     collect_match, &mc);
    EXPECT_EQ(count, 3u);
}

TEST_F(AhoCorasickTest, DuplicatePatterns)
{
    add("dup", 1);
    add("dup", 2);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "dup";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, 3, collect_match, &mc);
    /* Second add overwrites the pattern_index on the same trie leaf,
       so we get 1 match with id=2 */
    EXPECT_GE(count, 1u);
}

TEST_F(AhoCorasickTest, PrefixSuffixOverlap)
{
    /* "abab" contains overlapping instances of "ab" */
    add("ab", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "abab";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, 4, collect_match, &mc);
    EXPECT_EQ(count, 2u);
}

TEST_F(AhoCorasickTest, PatternLongerThanInput)
{
    add("verylongpattern", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "short";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, 5, collect_match, &mc);
    EXPECT_EQ(count, 0u);
}

TEST_F(AhoCorasickTest, AddPatternAfterFinalize)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    EXPECT_FALSE(akav_ac_add_pattern(
        ac, (const uint8_t*)"new", 3, 2));
}

TEST_F(AhoCorasickTest, FinalizeNull)
{
    EXPECT_FALSE(akav_ac_finalize(nullptr));
}

TEST_F(AhoCorasickTest, DoubleFinalize)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));
    EXPECT_FALSE(akav_ac_finalize(ac)); /* already finalized */
}

TEST_F(AhoCorasickTest, DestroyNull)
{
    akav_ac_destroy(nullptr); /* must not crash */
}

TEST_F(AhoCorasickTest, AddEmptyPattern)
{
    EXPECT_FALSE(akav_ac_add_pattern(ac, (const uint8_t*)"", 0, 1));
}

/* ── Adversarial deserialization ──────────────────────────────────── */

TEST_F(AhoCorasickTest, DeserializeBadMagic)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    /* Corrupt magic */
    buf[0] = 0xFF;
    EXPECT_EQ(akav_ac_deserialize(buf.data(), buf.size()), nullptr);
}

TEST_F(AhoCorasickTest, DeserializeTruncated)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    /* Truncate */
    EXPECT_EQ(akav_ac_deserialize(buf.data(), needed / 2), nullptr);
}

TEST_F(AhoCorasickTest, DeserializeHugeNodeCount)
{
    /* Craft a header claiming billions of nodes */
    uint8_t buf[17] = {};
    uint32_t magic = 0x43414B41;
    uint32_t version = 1;
    uint32_t node_count = 0xFFFFFFFF;
    uint32_t pattern_count = 0;
    memcpy(buf, &magic, 4);
    memcpy(buf + 4, &version, 4);
    memcpy(buf + 8, &node_count, 4);
    memcpy(buf + 12, &pattern_count, 4);
    buf[16] = 1;

    EXPECT_EQ(akav_ac_deserialize(buf, sizeof(buf)), nullptr);
}

/* ── Adversarial: deserialization attacks ──────────────────────────── */

TEST_F(AhoCorasickTest, DeserializeCorruptedFailureLinks)
{
    /* Serialize a valid automaton, then corrupt failure link fields
       to point out of bounds. Deserialize must clamp them safely. */
    add("abc", 1);
    add("bc", 2);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    /* Each serialized node is 1040 bytes. The failure field is at
       offset 1024 within each node. Corrupt node 1's failure link. */
    size_t node1_offset = 17 + 1 * 1040; /* header + 1 node */
    size_t failure_offset = node1_offset + 1024;
    int32_t bad_failure = 99999;
    memcpy(buf.data() + failure_offset, &bad_failure, 4);

    /* Should succeed (deserialize clamps out-of-bounds refs to root) */
    akav_ac_t* ac2 = akav_ac_deserialize(buf.data(), buf.size());
    ASSERT_NE(ac2, nullptr);

    /* Must not crash during search */
    const uint8_t input[] = "xabcx";
    uint32_t count = akav_ac_search(ac2, input, sizeof(input) - 1,
                                     nullptr, nullptr);
    (void)count; /* result may differ from original — that's fine */

    akav_ac_destroy(ac2);
}

TEST_F(AhoCorasickTest, DeserializeCorruptedOutputLinks)
{
    add("he", 1);
    add("she", 2);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    /* Corrupt output_link of node 2 (offset 1028 within each node) */
    size_t node2_offset = 17 + 2 * 1040;
    size_t output_link_offset = node2_offset + 1028;
    int32_t bad_output = 999999;
    memcpy(buf.data() + output_link_offset, &bad_output, 4);

    akav_ac_t* ac2 = akav_ac_deserialize(buf.data(), buf.size());
    ASSERT_NE(ac2, nullptr);

    const uint8_t input[] = "ushers";
    uint32_t count = akav_ac_search(ac2, input, sizeof(input) - 1,
                                     nullptr, nullptr);
    (void)count;

    akav_ac_destroy(ac2);
}

TEST_F(AhoCorasickTest, DeserializeCorruptedChildren)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    /* Corrupt a child pointer in root node's children array.
       Child for byte 't' (0x74) is at offset 0x74 * 4 = 464 within node 0 */
    size_t root_child_offset = 17 + 0x74 * 4;
    int32_t bad_child = 50000;
    memcpy(buf.data() + root_child_offset, &bad_child, 4);

    akav_ac_t* ac2 = akav_ac_deserialize(buf.data(), buf.size());
    ASSERT_NE(ac2, nullptr);

    /* Search with corrupted child — must not crash */
    const uint8_t input[] = "test";
    uint32_t count = akav_ac_search(ac2, input, 4, nullptr, nullptr);
    (void)count;

    akav_ac_destroy(ac2);
}

TEST_F(AhoCorasickTest, DeserializeCorruptedPatternIndex)
{
    add("abc", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    /* Corrupt pattern_index of last trie node to point past pattern array */
    /* Find the node for 'c' — it's the last node added.
       pattern_index is at offset 1032 within each node. */
    uint32_t node_count_raw;
    memcpy(&node_count_raw, buf.data() + 8, 4);
    size_t last_node_offset = 17 + ((size_t)node_count_raw - 1) * 1040;
    size_t pidx_offset = last_node_offset + 1032;
    int32_t bad_pidx = 99999;
    memcpy(buf.data() + pidx_offset, &bad_pidx, 4);

    akav_ac_t* ac2 = akav_ac_deserialize(buf.data(), buf.size());
    ASSERT_NE(ac2, nullptr);

    /* Search — clamped pattern_index should prevent OOB access */
    const uint8_t input[] = "abc";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac2, input, 3, collect_match, &mc);
    /* With clamped index, the match for "abc" won't fire, so 0 matches */
    EXPECT_EQ(count, 0u);

    akav_ac_destroy(ac2);
}

TEST_F(AhoCorasickTest, DeserializeUnsupportedVersion)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    /* Set version to 99 */
    uint32_t bad_version = 99;
    memcpy(buf.data() + 4, &bad_version, 4);

    EXPECT_EQ(akav_ac_deserialize(buf.data(), buf.size()), nullptr);
}

TEST_F(AhoCorasickTest, DeserializeZeroNodeCountNonzeroPatterns)
{
    uint8_t buf[17] = {};
    uint32_t magic = 0x43414B41;
    uint32_t version = 1;
    uint32_t node_count = 0;
    uint32_t pattern_count = 100;
    memcpy(buf, &magic, 4);
    memcpy(buf + 4, &version, 4);
    memcpy(buf + 8, &node_count, 4);
    memcpy(buf + 12, &pattern_count, 4);
    buf[16] = 1;

    EXPECT_EQ(akav_ac_deserialize(buf, sizeof(buf)), nullptr);
}

TEST_F(AhoCorasickTest, DeserializeFinalizedFlagZero)
{
    add("test", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    /* Clear finalized flag */
    buf[16] = 0;

    EXPECT_EQ(akav_ac_deserialize(buf.data(), buf.size()), nullptr);
}

TEST_F(AhoCorasickTest, DeserializeRandomBitFlips)
{
    add("hello", 1);
    add("world", 2);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> good(needed);
    akav_ac_serialize(ac, good.data(), good.size());

    /* Flip one bit at various positions throughout the buffer.
       Must never crash — either rejects or produces a usable automaton. */
    for (size_t pos = 0; pos < needed; pos += needed / 20) {
        auto bad = good;
        bad[pos] ^= 0x40;

        akav_ac_t* ac2 = akav_ac_deserialize(bad.data(), bad.size());
        if (ac2) {
            const uint8_t input[] = "hello world";
            (void)akav_ac_search(ac2, input, sizeof(input) - 1,
                                  nullptr, nullptr);
            akav_ac_destroy(ac2);
        }
        /* Either NULL or safe — test passes if no crash */
    }
}

TEST_F(AhoCorasickTest, DeserializeHugePatternCount)
{
    uint8_t buf[17] = {};
    uint32_t magic = 0x43414B41;
    uint32_t version = 1;
    uint32_t node_count = 1;
    uint32_t pattern_count = 0xFFFFFFFF;
    memcpy(buf, &magic, 4);
    memcpy(buf + 4, &version, 4);
    memcpy(buf + 8, &node_count, 4);
    memcpy(buf + 12, &pattern_count, 4);
    buf[16] = 1;

    EXPECT_EQ(akav_ac_deserialize(buf, sizeof(buf)), nullptr);
}

/* ── Adversarial: algorithmic abuse ───────────────────────────────── */

TEST_F(AhoCorasickTest, All256SingleBytePatterns)
{
    /* Force maximum branching at root — every byte value has a child */
    for (int i = 0; i < 256; i++) {
        uint8_t byte = static_cast<uint8_t>(i);
        ASSERT_TRUE(akav_ac_add_pattern(ac, &byte, 1, static_cast<uint32_t>(i)));
    }
    ASSERT_TRUE(akav_ac_finalize(ac));
    EXPECT_EQ(akav_ac_pattern_count(ac), 256u);

    /* Every byte in input should match */
    std::vector<uint8_t> input(1000);
    for (size_t i = 0; i < input.size(); i++)
        input[i] = static_cast<uint8_t>(i & 0xFF);

    uint32_t count = akav_ac_search(ac, input.data(), input.size(),
                                     nullptr, nullptr);
    EXPECT_EQ(count, 1000u);
}

TEST_F(AhoCorasickTest, DeepPrefixChain)
{
    /* "a", "aa", "aaa", ... up to length 500.
       Creates a deep trie with heavy failure link chaining. */
    for (int len = 1; len <= 500; len++) {
        std::string pat(static_cast<size_t>(len), 'a');
        ASSERT_TRUE(akav_ac_add_pattern(
            ac, reinterpret_cast<const uint8_t*>(pat.data()),
            static_cast<uint32_t>(pat.size()),
            static_cast<uint32_t>(len)));
    }
    ASSERT_TRUE(akav_ac_finalize(ac));

    /* Input of 1000 'a's — every position triggers multiple matches */
    std::string input(1000, 'a');
    MatchCollector mc;
    uint32_t count = akav_ac_search(
        ac, reinterpret_cast<const uint8_t*>(input.data()),
        input.size(), collect_match, &mc);

    /* At position i (0-indexed, where offset = end of match):
       patterns of length 1..min(i+1, 500) all match.
       Total = sum_{i=0}^{999} min(i+1, 500) */
    uint32_t expected = 0;
    for (int i = 0; i < 1000; i++) {
        expected += static_cast<uint32_t>((i + 1) < 500 ? (i + 1) : 500);
    }
    EXPECT_EQ(count, expected);
}

TEST_F(AhoCorasickTest, AllPrefixesOfEachOther)
{
    /* Patterns: "abcde", "abcd", "abc", "ab", "a"
       All are prefixes of the longest — maximizes output link traversal */
    add("a", 1);
    add("ab", 2);
    add("abc", 3);
    add("abcd", 4);
    add("abcde", 5);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const uint8_t input[] = "abcde";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input, 5, collect_match, &mc);

    /* "a" at 0, "ab" at 1, "abc" at 2, "abcd" at 3, "abcde" at 4 */
    EXPECT_EQ(count, 5u);

    std::set<uint32_t> ids;
    for (auto& m : mc.matches) ids.insert(m.pattern_id);
    for (uint32_t id = 1; id <= 5; id++) {
        EXPECT_TRUE(ids.count(id)) << "Missing pattern_id " << id;
    }
}

TEST_F(AhoCorasickTest, MaxMatchDensitySingleByte)
{
    /* Single-byte pattern 'X' against all-'X' input.
       Every byte position matches — worst case for callback throughput. */
    const uint8_t pat = 'X';
    add_bytes(&pat, 1, 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    const size_t N = 100000;
    std::vector<uint8_t> input(N, 'X');

    auto start = std::chrono::high_resolution_clock::now();
    uint32_t count = akav_ac_search(ac, input.data(), input.size(),
                                     nullptr, nullptr);
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    EXPECT_EQ(count, static_cast<uint32_t>(N));
    EXPECT_LT(ms, 100) << "100K max-density matches took " << ms << "ms";
}

TEST_F(AhoCorasickTest, VeryLongSinglePattern)
{
    /* 64KB pattern — deep trie with zero branching */
    std::vector<uint8_t> long_pat(65536);
    for (size_t i = 0; i < long_pat.size(); i++)
        long_pat[i] = static_cast<uint8_t>(i & 0xFF);

    ASSERT_TRUE(akav_ac_add_pattern(
        ac, long_pat.data(), static_cast<uint32_t>(long_pat.size()), 1));
    ASSERT_TRUE(akav_ac_finalize(ac));

    /* Embed the pattern in a larger buffer */
    std::vector<uint8_t> input(long_pat.size() + 200, 0);
    memcpy(input.data() + 100, long_pat.data(), long_pat.size());

    MatchCollector mc;
    uint32_t count = akav_ac_search(ac, input.data(), input.size(),
                                     collect_match, &mc);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(mc.matches[0].pattern_id, 1u);
    EXPECT_EQ(mc.matches[0].pattern_len, 65536u);
}

TEST_F(AhoCorasickTest, ManyPatternsSharedPrefixes)
{
    /* 500 patterns all starting with "AAAAAAAAAA" (10 A's) then diverging.
       Maximizes node reuse in the trie for the shared prefix. */
    const std::string prefix(10, 'A');
    for (int i = 0; i < 500; i++) {
        std::string pat = prefix + std::to_string(i);
        ASSERT_TRUE(akav_ac_add_pattern(
            ac, reinterpret_cast<const uint8_t*>(pat.data()),
            static_cast<uint32_t>(pat.size()),
            static_cast<uint32_t>(i)));
    }
    ASSERT_TRUE(akav_ac_finalize(ac));

    /* Search for a specific embedded pattern */
    std::string input = "xxxxx" + prefix + "42" + "xxxxx";
    MatchCollector mc;
    uint32_t count = akav_ac_search(
        ac, reinterpret_cast<const uint8_t*>(input.data()),
        input.size(), collect_match, &mc);

    EXPECT_GE(count, 1u);
    bool found_42 = false;
    for (auto& m : mc.matches) {
        if (m.pattern_id == 42) found_42 = true;
    }
    EXPECT_TRUE(found_42);
}

/* ── Adversarial: state machine integrity after deserialization ──── */

TEST_F(AhoCorasickTest, DeserializedSearchMatchesOriginal)
{
    /* Build a non-trivial automaton, serialize, deserialize, and verify
       that search results are byte-identical to the original. */
    add("he", 1);
    add("she", 2);
    add("his", 3);
    add("hers", 4);
    add("her", 5);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    akav_ac_t* ac2 = akav_ac_deserialize(buf.data(), buf.size());
    ASSERT_NE(ac2, nullptr);

    /* Test against multiple inputs */
    const char* inputs[] = {
        "ushers", "she sells", "his hers her",
        "abcdefgh", "", "hehehehe", "shhhh"
    };

    for (const char* inp : inputs) {
        size_t len = strlen(inp);
        if (len == 0) continue;

        MatchCollector mc1, mc2;
        uint32_t c1 = akav_ac_search(
            ac, reinterpret_cast<const uint8_t*>(inp), len,
            collect_match, &mc1);
        uint32_t c2 = akav_ac_search(
            ac2, reinterpret_cast<const uint8_t*>(inp), len,
            collect_match, &mc2);

        EXPECT_EQ(c1, c2) << "Count mismatch for input: " << inp;
        ASSERT_EQ(mc1.matches.size(), mc2.matches.size())
            << "Match count mismatch for input: " << inp;

        for (size_t i = 0; i < mc1.matches.size(); i++) {
            EXPECT_EQ(mc1.matches[i].pattern_id, mc2.matches[i].pattern_id)
                << "Pattern ID mismatch at match " << i
                << " for input: " << inp;
            EXPECT_EQ(mc1.matches[i].offset, mc2.matches[i].offset)
                << "Offset mismatch at match " << i
                << " for input: " << inp;
        }
    }

    akav_ac_destroy(ac2);
}

TEST_F(AhoCorasickTest, DeserializedGotoOptimizationIntact)
{
    /* After deserialization, root transitions for missing bytes should
       loop back to root (goto optimization). Verify by searching for
       a pattern preceded by bytes not in any pattern. */
    add("xyz", 1);
    ASSERT_TRUE(akav_ac_finalize(ac));

    size_t needed = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_ac_serialize(ac, buf.data(), buf.size());

    akav_ac_t* ac2 = akav_ac_deserialize(buf.data(), buf.size());
    ASSERT_NE(ac2, nullptr);

    /* Input with lots of non-pattern bytes before the match */
    const uint8_t input[] = "aaabbbcccdddeee___xyz___";
    MatchCollector mc;
    uint32_t count = akav_ac_search(ac2, input, sizeof(input) - 1,
                                     collect_match, &mc);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(mc.matches[0].pattern_id, 1u);

    akav_ac_destroy(ac2);
}
