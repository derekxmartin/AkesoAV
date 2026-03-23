/* ml_classifier.h -- ML classifier inference for PE malware detection (P9-T4).
 *
 * Loads a Random Forest model exported as JSON (from tools/ml/train_classifier.py),
 * extracts a 14-feature vector from parsed PE data, walks decision trees, and
 * returns a probability [0.0, 1.0]. Score contribution: probability * 50.
 */

#ifndef AKAV_HEURISTIC_ML_CLASSIFIER_H
#define AKAV_HEURISTIC_ML_CLASSIFIER_H

#include "parsers/pe.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────── */

#define AKAV_ML_NUM_FEATURES    14
#define AKAV_ML_MAX_TREES       200
#define AKAV_ML_MAX_NODES       65536  /* per tree */
#define AKAV_ML_SCORE_WEIGHT    50     /* probability * weight = heuristic score */

/* ── Decision tree node ───────────────────────────────────────── */

typedef struct akav_ml_node {
    int      feature;     /* feature index, or -1 for leaf */
    double   threshold;   /* split threshold (internal node) */
    double   value;       /* probability (leaf node) */
    int      left;        /* index of left child, -1 if leaf */
    int      right;       /* index of right child, -1 if leaf */
} akav_ml_node_t;

/* ── Decision tree ────────────────────────────────────────────── */

typedef struct {
    akav_ml_node_t* nodes;
    uint32_t        num_nodes;
} akav_ml_tree_t;

/* ── Random Forest model ──────────────────────────────────────── */

typedef struct {
    akav_ml_tree_t  trees[AKAV_ML_MAX_TREES];
    uint32_t        num_trees;
    uint32_t        num_features;
    double          threshold;   /* classification threshold (default 0.5) */
    bool            loaded;
} akav_ml_model_t;

/* ── Feature vector ───────────────────────────────────────────── */

typedef struct {
    double features[AKAV_ML_NUM_FEATURES];
    /*  [0]  file_size_log2
     *  [1]  num_sections
     *  [2]  text_entropy
     *  [3]  max_entropy
     *  [4]  mean_entropy
     *  [5]  import_dll_count
     *  [6]  import_func_count
     *  [7]  has_overlay
     *  [8]  overlay_ratio
     *  [9]  has_rich_header
     *  [10] timestamp_suspicious
     *  [11] entry_outside_text
     *  [12] has_authenticode
     *  [13] suspicious_api_bits
     */
} akav_ml_features_t;

/* ── ML classification result ─────────────────────────────────── */

typedef struct {
    double probability;   /* malware probability [0.0, 1.0] */
    int    score;         /* probability * AKAV_ML_SCORE_WEIGHT */
    bool   classified;    /* true if model was loaded and inference ran */
} akav_ml_result_t;

/* ── API ──────────────────────────────────────────────────────── */

/**
 * Initialize the model to empty state.
 */
void akav_ml_model_init(akav_ml_model_t* model);

/**
 * Load a Random Forest model from a JSON file (exported by train_classifier.py).
 * Returns true on success.
 */
bool akav_ml_model_load(akav_ml_model_t* model, const char* json_path);

/**
 * Load a Random Forest model from a JSON string in memory.
 * Returns true on success.
 */
bool akav_ml_model_load_json(akav_ml_model_t* model,
                               const char* json_str, size_t json_len);

/**
 * Free all memory allocated by a loaded model.
 */
void akav_ml_model_free(akav_ml_model_t* model);

/**
 * Extract a 14-feature vector from a parsed PE structure.
 * Requires pe to have been parsed with imports, entropy, and metadata.
 *
 * file_size is the total file size in bytes.
 */
void akav_ml_extract_features(const akav_pe_t* pe,
                                size_t file_size,
                                akav_ml_features_t* features);

/**
 * Run inference: evaluate the feature vector against all trees and
 * return the average probability.
 *
 * Returns false if model is not loaded.
 */
bool akav_ml_classify(const akav_ml_model_t* model,
                        const akav_ml_features_t* features,
                        akav_ml_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_HEURISTIC_ML_CLASSIFIER_H */
