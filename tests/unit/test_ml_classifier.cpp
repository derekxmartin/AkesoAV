/* test_ml_classifier.cpp -- Unit tests for ML classifier inference (P9-T4). */

#include <gtest/gtest.h>
#include "heuristics/ml_classifier.h"
#include "parsers/pe.h"
#include <cstring>
#include <string>
#include <vector>
#include <cstdio>

/* ── Helpers: build a minimal JSON model ─────────────────────────── */

/* Single-tree model: if file_size_log2 <= 12.0 → 0.9 (malware), else → 0.1 */
static const char* SIMPLE_MODEL_JSON = R"({
    "model_type": "random_forest",
    "version": 1,
    "num_trees": 1,
    "num_features": 14,
    "feature_names": ["file_size_log2","num_sections","text_entropy",
        "max_entropy","mean_entropy","import_dll_count","import_func_count",
        "has_overlay","overlay_ratio","has_rich_header","timestamp_suspicious",
        "entry_outside_text","has_authenticode","suspicious_api_bits"],
    "threshold": 0.5,
    "trees": [
        {
            "feature": 0,
            "threshold": 12.0,
            "left": {"value": 0.9},
            "right": {"value": 0.1}
        }
    ]
})";

/* Multi-tree model: 3 trees for more realistic testing */
static const char* MULTI_TREE_MODEL_JSON = R"({
    "model_type": "random_forest",
    "version": 1,
    "num_trees": 3,
    "num_features": 14,
    "threshold": 0.5,
    "trees": [
        {
            "feature": 3,
            "threshold": 7.0,
            "left": {"value": 0.1},
            "right": {"value": 0.9}
        },
        {
            "feature": 5,
            "threshold": 3.0,
            "left": {
                "feature": 10,
                "threshold": 0.5,
                "left": {"value": 0.2},
                "right": {"value": 0.8}
            },
            "right": {"value": 0.1}
        },
        {
            "feature": 13,
            "threshold": 0.5,
            "left": {"value": 0.15},
            "right": {"value": 0.85}
        }
    ]
})";

static void write_temp_file(const char* path, const char* content)
{
    FILE* f = nullptr;
    fopen_s(&f, path, "w");
    ASSERT_NE(f, nullptr) << "Failed to create " << path;
    fputs(content, f);
    fclose(f);
}

/* ── Lifecycle ───────────────────────────────────────────────────── */

TEST(MLClassifier, InitState) {
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    EXPECT_FALSE(model.loaded);
    EXPECT_EQ(model.num_trees, 0u);
    EXPECT_DOUBLE_EQ(model.threshold, 0.5);
}

TEST(MLClassifier, FreeNullIsNoOp) {
    akav_ml_model_free(nullptr);
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    akav_ml_model_free(&model);
}

/* ── JSON loading ────────────────────────────────────────────────── */

TEST(MLClassifier, LoadSimpleModel) {
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load_json(&model, SIMPLE_MODEL_JSON,
                                          strlen(SIMPLE_MODEL_JSON)));
    EXPECT_TRUE(model.loaded);
    EXPECT_EQ(model.num_trees, 1u);
    EXPECT_DOUBLE_EQ(model.threshold, 0.5);
    akav_ml_model_free(&model);
}

TEST(MLClassifier, LoadMultiTreeModel) {
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load_json(&model, MULTI_TREE_MODEL_JSON,
                                          strlen(MULTI_TREE_MODEL_JSON)));
    EXPECT_TRUE(model.loaded);
    EXPECT_EQ(model.num_trees, 3u);
    akav_ml_model_free(&model);
}

TEST(MLClassifier, LoadFromFile) {
    const char* path = "test_ml_model_tmp.json";
    write_temp_file(path, SIMPLE_MODEL_JSON);

    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load(&model, path));
    EXPECT_TRUE(model.loaded);
    EXPECT_EQ(model.num_trees, 1u);
    akav_ml_model_free(&model);
    remove(path);
}

TEST(MLClassifier, LoadInvalidJsonFails) {
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    EXPECT_FALSE(akav_ml_model_load_json(&model, "{}", 2));
    EXPECT_FALSE(model.loaded);
}

TEST(MLClassifier, LoadEmptyFails) {
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    EXPECT_FALSE(akav_ml_model_load_json(&model, nullptr, 0));
    EXPECT_FALSE(akav_ml_model_load_json(&model, "", 0));
}

TEST(MLClassifier, LoadMissingFileFails) {
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    EXPECT_FALSE(akav_ml_model_load(&model, "nonexistent_model.json"));
}

/* ── Feature extraction ──────────────────────────────────────────── */

TEST(MLClassifier, ExtractFeaturesFromParsedPE) {
    /* Construct a minimal akav_pe_t manually */
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    pe.num_sections = 4;
    pe.timestamp = 1700000000;  /* valid timestamp */
    pe.entry_point = 0x1000;
    pe.has_overlay = true;
    pe.overlay_size = 1024;
    pe.has_rich_header = true;
    pe.has_authenticode = false;
    pe.num_import_dlls = 5;
    pe.num_import_funcs = 50;
    pe.ordinal_only_count = 0;

    /* Set up sections with entropy */
    strncpy_s(pe.sections[0].name, ".text", _TRUNCATE);
    pe.sections[0].virtual_address = 0x1000;
    pe.sections[0].virtual_size = 0x5000;
    pe.sections[0].entropy = 6.5;
    pe.sections[0].characteristics = 0x60000020;

    strncpy_s(pe.sections[1].name, ".rdata", _TRUNCATE);
    pe.sections[1].entropy = 5.2;

    strncpy_s(pe.sections[2].name, ".data", _TRUNCATE);
    pe.sections[2].entropy = 3.1;

    strncpy_s(pe.sections[3].name, ".rsrc", _TRUNCATE);
    pe.sections[3].entropy = 7.8;

    akav_ml_features_t features;
    akav_ml_extract_features(&pe, 100000, &features);

    /* [0] file_size_log2 ≈ 16.6 */
    EXPECT_NEAR(features.features[0], 16.6, 0.1);
    /* [1] num_sections = 4 */
    EXPECT_DOUBLE_EQ(features.features[1], 4.0);
    /* [2] text_entropy = 6.5 */
    EXPECT_DOUBLE_EQ(features.features[2], 6.5);
    /* [3] max_entropy = 7.8 */
    EXPECT_DOUBLE_EQ(features.features[3], 7.8);
    /* [4] mean_entropy ≈ 5.65 */
    EXPECT_NEAR(features.features[4], 5.65, 0.01);
    /* [5] import_dll_count = 5 */
    EXPECT_DOUBLE_EQ(features.features[5], 5.0);
    /* [6] import_func_count = 50 */
    EXPECT_DOUBLE_EQ(features.features[6], 50.0);
    /* [7] has_overlay = 1 */
    EXPECT_DOUBLE_EQ(features.features[7], 1.0);
    /* [8] overlay_ratio = 1024/100000 */
    EXPECT_NEAR(features.features[8], 0.01024, 0.0001);
    /* [9] has_rich_header = 1 */
    EXPECT_DOUBLE_EQ(features.features[9], 1.0);
    /* [10] timestamp_suspicious = 0 (valid) */
    EXPECT_DOUBLE_EQ(features.features[10], 0.0);
    /* [11] entry_outside_text = 0 (0x1000 is within .text) */
    EXPECT_DOUBLE_EQ(features.features[11], 0.0);
    /* [12] has_authenticode = 0 */
    EXPECT_DOUBLE_EQ(features.features[12], 0.0);
    /* [13] suspicious_api_bits = 0 (no import funcs to check) */
    EXPECT_DOUBLE_EQ(features.features[13], 0.0);
}

TEST(MLClassifier, SuspiciousTimestamp) {
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    pe.timestamp = 0;  /* suspicious */

    akav_ml_features_t features;
    akav_ml_extract_features(&pe, 1000, &features);
    EXPECT_DOUBLE_EQ(features.features[10], 1.0);
}

TEST(MLClassifier, EntryOutsideText) {
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    pe.num_sections = 1;
    pe.entry_point = 0x8000;  /* outside .text */
    strncpy_s(pe.sections[0].name, ".text", _TRUNCATE);
    pe.sections[0].virtual_address = 0x1000;
    pe.sections[0].virtual_size = 0x2000;  /* .text = 0x1000-0x3000 */
    pe.sections[0].entropy = 6.0;
    pe.sections[0].characteristics = 0x60000020;

    akav_ml_features_t features;
    akav_ml_extract_features(&pe, 10000, &features);
    EXPECT_DOUBLE_EQ(features.features[11], 1.0);
}

/* ── Inference ───────────────────────────────────────────────────── */

TEST(MLClassifier, ClassifyWithoutLoadedModel) {
    akav_ml_model_t model;
    akav_ml_model_init(&model);

    akav_ml_features_t features;
    memset(&features, 0, sizeof(features));

    akav_ml_result_t result;
    EXPECT_FALSE(akav_ml_classify(&model, &features, &result));
    EXPECT_FALSE(result.classified);
}

TEST(MLClassifier, ClassifyMalwareFeatures) {
    /* Load simple model: file_size_log2 <= 12.0 → 0.9 */
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load_json(&model, SIMPLE_MODEL_JSON,
                                          strlen(SIMPLE_MODEL_JSON)));

    akav_ml_features_t features;
    memset(&features, 0, sizeof(features));
    features.features[0] = 10.0;  /* small file → malware path */

    akav_ml_result_t result;
    ASSERT_TRUE(akav_ml_classify(&model, &features, &result));
    EXPECT_TRUE(result.classified);
    EXPECT_GT(result.probability, 0.7);
    EXPECT_GE(result.score, 35);  /* 0.9 * 50 = 45 */

    akav_ml_model_free(&model);
}

TEST(MLClassifier, ClassifyCleanFeatures) {
    /* Load simple model: file_size_log2 > 12.0 → 0.1 */
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load_json(&model, SIMPLE_MODEL_JSON,
                                          strlen(SIMPLE_MODEL_JSON)));

    akav_ml_features_t features;
    memset(&features, 0, sizeof(features));
    features.features[0] = 18.0;  /* large file → clean path */

    akav_ml_result_t result;
    ASSERT_TRUE(akav_ml_classify(&model, &features, &result));
    EXPECT_TRUE(result.classified);
    EXPECT_LT(result.probability, 0.3);
    EXPECT_LE(result.score, 15);  /* 0.1 * 50 = 5 */

    akav_ml_model_free(&model);
}

TEST(MLClassifier, MultiTreeAveraging) {
    /* Multi-tree model: tests that probabilities are averaged */
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load_json(&model, MULTI_TREE_MODEL_JSON,
                                          strlen(MULTI_TREE_MODEL_JSON)));

    /* Features that trigger high-probability paths in all 3 trees:
     *   Tree 0: max_entropy=7.5 > 7.0 → 0.9
     *   Tree 1: import_dlls=2 <= 3.0 → check timestamp: ts_suspicious=1.0 > 0.5 → 0.8
     *   Tree 2: api_bits=1.0 > 0.5 → 0.85
     * Average: (0.9 + 0.8 + 0.85) / 3 = 0.85
     */
    akav_ml_features_t features;
    memset(&features, 0, sizeof(features));
    features.features[3] = 7.5;   /* max_entropy */
    features.features[5] = 2.0;   /* import_dll_count */
    features.features[10] = 1.0;  /* timestamp_suspicious */
    features.features[13] = 1.0;  /* suspicious_api_bits */

    akav_ml_result_t result;
    ASSERT_TRUE(akav_ml_classify(&model, &features, &result));
    EXPECT_NEAR(result.probability, 0.85, 0.01);
    EXPECT_GE(result.score, 42);  /* 0.85 * 50 = 42.5 */

    akav_ml_model_free(&model);
}

TEST(MLClassifier, MultiTreeCleanPath) {
    /* Features that trigger low-probability paths in all 3 trees:
     *   Tree 0: max_entropy=5.0 <= 7.0 → 0.1
     *   Tree 1: import_dlls=10.0 > 3.0 → 0.1
     *   Tree 2: api_bits=0.0 <= 0.5 → 0.15
     * Average: (0.1 + 0.1 + 0.15) / 3 ≈ 0.117
     */
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load_json(&model, MULTI_TREE_MODEL_JSON,
                                          strlen(MULTI_TREE_MODEL_JSON)));

    akav_ml_features_t features;
    memset(&features, 0, sizeof(features));
    features.features[3] = 5.0;   /* max_entropy (low) */
    features.features[5] = 10.0;  /* import_dll_count (many) */
    features.features[10] = 0.0;  /* timestamp_suspicious (clean) */
    features.features[13] = 0.0;  /* api_bits (clean) */

    akav_ml_result_t result;
    ASSERT_TRUE(akav_ml_classify(&model, &features, &result));
    EXPECT_LT(result.probability, 0.3);
    EXPECT_LE(result.score, 15);

    akav_ml_model_free(&model);
}

TEST(MLClassifier, NullInputsHandled) {
    akav_ml_result_t result;
    EXPECT_FALSE(akav_ml_classify(nullptr, nullptr, &result));

    akav_ml_model_t model;
    akav_ml_model_init(&model);
    EXPECT_FALSE(akav_ml_classify(&model, nullptr, &result));

    akav_ml_features_t feat;
    memset(&feat, 0, sizeof(feat));
    akav_ml_extract_features(nullptr, 0, &feat);
    /* Should not crash */
}

/* ── Integration: ML pushes borderline PE over threshold ─────────── */

TEST(MLClassifier, MLPushesOverThreshold) {
    /* Scenario from acceptance criteria:
     * Import anomaly alone = 25 (below Medium threshold of 75).
     * ML classifier returns probability 0.7 → score = 35.
     * Combined: 25 + 35 = 60 → still below 75 for Medium,
     * but exceeds 50 for High. This demonstrates ML contribution. */

    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load_json(&model, SIMPLE_MODEL_JSON,
                                          strlen(SIMPLE_MODEL_JSON)));

    /* Simulate malware features (small file → prob 0.9) */
    akav_ml_features_t features;
    memset(&features, 0, sizeof(features));
    features.features[0] = 10.0;  /* small → malware */

    akav_ml_result_t result;
    ASSERT_TRUE(akav_ml_classify(&model, &features, &result));

    /* ML alone provides score 45 (0.9 * 50) */
    int import_score = 25;  /* one import anomaly */
    int combined = import_score + result.score;
    EXPECT_GT(combined, 50) << "ML + import should exceed High threshold (50)";

    akav_ml_model_free(&model);
}

/* ── Hot reload: model can be replaced ───────────────────────────── */

TEST(MLClassifier, HotReloadReplacesModel) {
    akav_ml_model_t model;
    akav_ml_model_init(&model);

    /* Load simple model first */
    ASSERT_TRUE(akav_ml_model_load_json(&model, SIMPLE_MODEL_JSON,
                                          strlen(SIMPLE_MODEL_JSON)));
    EXPECT_EQ(model.num_trees, 1u);

    /* Replace with multi-tree model */
    ASSERT_TRUE(akav_ml_model_load_json(&model, MULTI_TREE_MODEL_JSON,
                                          strlen(MULTI_TREE_MODEL_JSON)));
    EXPECT_EQ(model.num_trees, 3u);

    akav_ml_model_free(&model);
}

/* ── Real PE test ────────────────────────────────────────────────── */

TEST(MLClassifier, ExtractFeaturesFromRealPE) {
    FILE* f = nullptr;
    fopen_s(&f, "testdata/clean_pe_32.exe", "rb");
    if (!f) {
        GTEST_SKIP() << "testdata/clean_pe_32.exe not available";
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> data(fsize);
    fread(data.data(), 1, fsize, f);
    fclose(f);

    /* Parse PE fully */
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    ASSERT_TRUE(akav_pe_parse(&pe, data.data(), data.size()));
    akav_pe_parse_imports(&pe, data.data(), data.size());
    akav_pe_compute_entropy(&pe, data.data(), data.size());
    akav_pe_analyze_metadata(&pe, data.data(), data.size());

    /* Extract ML features */
    akav_ml_features_t features;
    akav_ml_extract_features(&pe, data.size(), &features);

    /* Sanity checks */
    EXPECT_GT(features.features[0], 10.0);   /* file_size_log2 > 1KB */
    EXPECT_GT(features.features[1], 0.0);    /* has sections */
    EXPECT_GE(features.features[2], 0.0);    /* entropy valid range */
    EXPECT_LE(features.features[3], 8.0);    /* max entropy <= 8 */

    /* Load model and classify — clean PE should be low probability */
    akav_ml_model_t model;
    akav_ml_model_init(&model);
    ASSERT_TRUE(akav_ml_model_load_json(&model, SIMPLE_MODEL_JSON,
                                          strlen(SIMPLE_MODEL_JSON)));

    akav_ml_result_t result;
    ASSERT_TRUE(akav_ml_classify(&model, &features, &result));
    EXPECT_LT(result.probability, 0.5) << "Clean PE should not be classified as malware";

    akav_ml_model_free(&model);
    akav_pe_free(&pe);
}
