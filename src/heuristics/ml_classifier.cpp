/* ml_classifier.cpp -- ML classifier inference for PE malware detection (P9-T4).
 *
 * Loads a Random Forest model from JSON, extracts PE features, walks
 * decision trees, and returns malware probability [0.0, 1.0].
 */

#include "heuristics/ml_classifier.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

/* ── Minimal JSON parser (no dependencies) ───────────────────────── */

/* We parse the model JSON with a simple recursive descent parser.
 * The model format is well-defined so we don't need a general JSON library. */

typedef struct {
    const char* str;
    size_t      pos;
    size_t      len;
} json_ctx_t;

static void skip_ws(json_ctx_t* ctx)
{
    while (ctx->pos < ctx->len) {
        char c = ctx->str[ctx->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            ctx->pos++;
        else
            break;
    }
}

static bool match_char(json_ctx_t* ctx, char c)
{
    skip_ws(ctx);
    if (ctx->pos < ctx->len && ctx->str[ctx->pos] == c) {
        ctx->pos++;
        return true;
    }
    return false;
}

static bool parse_number(json_ctx_t* ctx, double* out)
{
    skip_ws(ctx);
    if (ctx->pos >= ctx->len) return false;

    char buf[64];
    int bi = 0;
    bool has_dot = false;

    if (ctx->str[ctx->pos] == '-') buf[bi++] = ctx->str[ctx->pos++];

    while (ctx->pos < ctx->len && bi < 62) {
        char c = ctx->str[ctx->pos];
        if (c >= '0' && c <= '9') {
            buf[bi++] = c;
            ctx->pos++;
        } else if (c == '.' && !has_dot) {
            buf[bi++] = c;
            ctx->pos++;
            has_dot = true;
        } else if (c == 'e' || c == 'E') {
            buf[bi++] = c;
            ctx->pos++;
            if (ctx->pos < ctx->len && (ctx->str[ctx->pos] == '+' ||
                                          ctx->str[ctx->pos] == '-'))
                buf[bi++] = ctx->str[ctx->pos++];
        } else {
            break;
        }
    }

    if (bi == 0 || (bi == 1 && buf[0] == '-')) return false;
    buf[bi] = '\0';
    *out = atof(buf);
    return true;
}

static bool skip_string(json_ctx_t* ctx)
{
    skip_ws(ctx);
    if (!match_char(ctx, '"')) return false;
    while (ctx->pos < ctx->len && ctx->str[ctx->pos] != '"') {
        if (ctx->str[ctx->pos] == '\\') ctx->pos++;  /* skip escaped char */
        ctx->pos++;
    }
    ctx->pos++;  /* closing quote */
    return true;
}

static bool match_key(json_ctx_t* ctx, const char* key)
{
    skip_ws(ctx);
    if (ctx->pos >= ctx->len || ctx->str[ctx->pos] != '"') return false;

    size_t klen = strlen(key);
    if (ctx->pos + 1 + klen + 1 > ctx->len) return false;
    if (memcmp(ctx->str + ctx->pos + 1, key, klen) != 0) return false;
    if (ctx->str[ctx->pos + 1 + klen] != '"') return false;

    ctx->pos += klen + 2;  /* skip "key" */
    skip_ws(ctx);
    if (!match_char(ctx, ':')) return false;
    return true;
}

/* Forward declaration */
static int parse_tree_node(json_ctx_t* ctx, akav_ml_node_t* nodes,
                            int max_nodes, int* count);

static bool skip_value(json_ctx_t* ctx);

static bool skip_array(json_ctx_t* ctx)
{
    if (!match_char(ctx, '[')) return false;
    skip_ws(ctx);
    if (match_char(ctx, ']')) return true;
    do {
        if (!skip_value(ctx)) return false;
    } while (match_char(ctx, ','));
    return match_char(ctx, ']');
}

static bool skip_object(json_ctx_t* ctx)
{
    if (!match_char(ctx, '{')) return false;
    skip_ws(ctx);
    if (match_char(ctx, '}')) return true;
    do {
        if (!skip_string(ctx)) return false;
        skip_ws(ctx);
        if (!match_char(ctx, ':')) return false;
        if (!skip_value(ctx)) return false;
    } while (match_char(ctx, ','));
    return match_char(ctx, '}');
}

static bool skip_value(json_ctx_t* ctx)
{
    skip_ws(ctx);
    if (ctx->pos >= ctx->len) return false;
    char c = ctx->str[ctx->pos];
    if (c == '"') return skip_string(ctx);
    if (c == '[') return skip_array(ctx);
    if (c == '{') return skip_object(ctx);
    if (c == 't') { ctx->pos += 4; return true; }  /* true */
    if (c == 'f') { ctx->pos += 5; return true; }  /* false */
    if (c == 'n') { ctx->pos += 4; return true; }  /* null */
    double dummy;
    return parse_number(ctx, &dummy);
}

/* ── Parse a tree node recursively ───────────────────────────────── */

/* Node format:
 *   Internal: {"feature": idx, "threshold": val, "left": node, "right": node}
 *   Leaf:     {"value": probability}
 */
static int parse_tree_node(json_ctx_t* ctx, akav_ml_node_t* nodes,
                            int max_nodes, int* count)
{
    skip_ws(ctx);
    if (!match_char(ctx, '{')) return -1;
    if (*count >= max_nodes) return -1;

    int this_idx = (*count)++;
    nodes[this_idx].feature = -1;
    nodes[this_idx].threshold = 0.0;
    nodes[this_idx].value = 0.0;
    nodes[this_idx].left = -1;
    nodes[this_idx].right = -1;

    bool is_leaf = false;

    while (ctx->pos < ctx->len) {
        skip_ws(ctx);
        if (ctx->str[ctx->pos] == '}') { ctx->pos++; break; }

        /* Try known keys */
        size_t save = ctx->pos;

        if (match_key(ctx, "value")) {
            double val;
            if (!parse_number(ctx, &val)) return -1;
            nodes[this_idx].value = val;
            is_leaf = true;
        } else if (ctx->pos = save, match_key(ctx, "feature")) {
            double val;
            if (!parse_number(ctx, &val)) return -1;
            nodes[this_idx].feature = (int)val;
        } else if (ctx->pos = save, match_key(ctx, "threshold")) {
            double val;
            if (!parse_number(ctx, &val)) return -1;
            nodes[this_idx].threshold = val;
        } else if (ctx->pos = save, match_key(ctx, "left")) {
            int child = parse_tree_node(ctx, nodes, max_nodes, count);
            if (child < 0) return -1;
            nodes[this_idx].left = child;
        } else if (ctx->pos = save, match_key(ctx, "right")) {
            int child = parse_tree_node(ctx, nodes, max_nodes, count);
            if (child < 0) return -1;
            nodes[this_idx].right = child;
        } else {
            /* Unknown key — skip */
            ctx->pos = save;
            if (!skip_string(ctx)) return -1;
            skip_ws(ctx);
            if (!match_char(ctx, ':')) return -1;
            if (!skip_value(ctx)) return -1;
        }

        skip_ws(ctx);
        if (ctx->pos < ctx->len && ctx->str[ctx->pos] == ',')
            ctx->pos++;
    }

    if (is_leaf) {
        nodes[this_idx].feature = -1;
        nodes[this_idx].left = -1;
        nodes[this_idx].right = -1;
    }

    return this_idx;
}

/* ── Find the "trees" array in the top-level JSON object ─────────── */

static bool find_trees_array(json_ctx_t* ctx)
{
    skip_ws(ctx);
    if (!match_char(ctx, '{')) return false;

    while (ctx->pos < ctx->len && ctx->str[ctx->pos] != '}') {
        size_t save = ctx->pos;
        if (match_key(ctx, "trees")) {
            return true;  /* positioned right after "trees": */
        }
        /* Not "trees" — skip this key-value pair */
        ctx->pos = save;
        if (!skip_string(ctx)) return false;
        skip_ws(ctx);
        if (!match_char(ctx, ':')) return false;
        if (!skip_value(ctx)) return false;
        skip_ws(ctx);
        if (ctx->pos < ctx->len && ctx->str[ctx->pos] == ',')
            ctx->pos++;
    }
    return false;
}

/* Also parse num_trees, threshold, num_features from top-level */
static void parse_model_metadata(json_ctx_t* ctx, akav_ml_model_t* model)
{
    size_t save = ctx->pos;
    ctx->pos = 0;

    skip_ws(ctx);
    if (!match_char(ctx, '{')) { ctx->pos = save; return; }

    while (ctx->pos < ctx->len && ctx->str[ctx->pos] != '}') {
        size_t ksave = ctx->pos;

        if (match_key(ctx, "num_trees")) {
            double v; parse_number(ctx, &v);
            /* already set from parsing trees array */
        } else if (ctx->pos = ksave, match_key(ctx, "num_features")) {
            double v;
            if (parse_number(ctx, &v)) model->num_features = (uint32_t)v;
        } else if (ctx->pos = ksave, match_key(ctx, "threshold")) {
            double v;
            if (parse_number(ctx, &v)) model->threshold = v;
        } else {
            ctx->pos = ksave;
            if (!skip_string(ctx)) break;
            skip_ws(ctx);
            if (!match_char(ctx, ':')) break;
            if (!skip_value(ctx)) break;
        }
        skip_ws(ctx);
        if (ctx->pos < ctx->len && ctx->str[ctx->pos] == ',')
            ctx->pos++;
    }
    ctx->pos = save;
}

/* ── Public API ──────────────────────────────────────────────────── */

void akav_ml_model_init(akav_ml_model_t* model)
{
    if (!model) return;
    memset(model, 0, sizeof(*model));
    model->threshold = 0.5;
}

bool akav_ml_model_load_json(akav_ml_model_t* model,
                               const char* json_str, size_t json_len)
{
    if (!model || !json_str || json_len == 0)
        return false;

    akav_ml_model_free(model);
    akav_ml_model_init(model);

    json_ctx_t ctx = { json_str, 0, json_len };

    /* Parse metadata first */
    parse_model_metadata(&ctx, model);

    /* Find the "trees" array */
    ctx.pos = 0;
    if (!find_trees_array(&ctx))
        return false;

    /* Parse trees array */
    if (!match_char(&ctx, '['))
        return false;

    skip_ws(&ctx);
    if (ctx.pos < ctx.len && ctx.str[ctx.pos] == ']') {
        ctx.pos++;
        return false;  /* empty trees array */
    }

    uint32_t tree_idx = 0;
    do {
        if (tree_idx >= AKAV_ML_MAX_TREES) break;

        /* Allocate node buffer for this tree */
        akav_ml_node_t* nodes = (akav_ml_node_t*)calloc(
            AKAV_ML_MAX_NODES, sizeof(akav_ml_node_t));
        if (!nodes) break;

        int count = 0;
        int root = parse_tree_node(&ctx, nodes, AKAV_ML_MAX_NODES, &count);
        if (root < 0 || count == 0) {
            free(nodes);
            break;
        }

        /* Shrink allocation */
        akav_ml_node_t* shrunk = (akav_ml_node_t*)realloc(
            nodes, (size_t)count * sizeof(akav_ml_node_t));
        model->trees[tree_idx].nodes = shrunk ? shrunk : nodes;
        model->trees[tree_idx].num_nodes = (uint32_t)count;
        tree_idx++;
    } while (match_char(&ctx, ','));

    model->num_trees = tree_idx;
    model->loaded = (tree_idx > 0);
    return model->loaded;
}

bool akav_ml_model_load(akav_ml_model_t* model, const char* json_path)
{
    if (!model || !json_path) return false;

    FILE* f = NULL;
    if (fopen_s(&f, json_path, "rb") != 0 || !f)
        return false;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 100 * 1024 * 1024) {  /* 100MB max */
        fclose(f);
        return false;
    }

    char* buf = (char*)malloc((size_t)fsize);
    if (!buf) { fclose(f); return false; }

    size_t rd = fread(buf, 1, (size_t)fsize, f);
    fclose(f);

    bool ok = akav_ml_model_load_json(model, buf, rd);
    free(buf);
    return ok;
}

void akav_ml_model_free(akav_ml_model_t* model)
{
    if (!model) return;
    for (uint32_t i = 0; i < model->num_trees; i++) {
        free(model->trees[i].nodes);
    }
    memset(model, 0, sizeof(*model));
    model->threshold = 0.5;
}

/* ── Feature extraction ──────────────────────────────────────────── */

/* Suspicious API detection bits — mirrors train_classifier.py */

static uint32_t compute_api_bits(const akav_pe_t* pe)
{
    if (!pe->import_funcs || pe->num_import_funcs == 0)
        return 0;

    /* Collect normalized function names into bitmask checks */
    bool has_virtual_alloc = false;
    bool has_write_process_memory = false;
    bool has_create_remote_thread = false;
    bool has_virtual_protect = false;
    bool has_create_thread = false;
    bool has_create_service = false;
    bool has_start_service = false;
    bool has_reg_set_value = false;
    bool has_get_proc_address = false;
    bool has_load_library = false;

    for (uint32_t i = 0; i < pe->num_import_funcs; i++) {
        const char* name = pe->import_funcs[i].name;
        if (!name[0]) continue;

        /* Case-insensitive prefix match, ignoring trailing A/W */
        if (_strnicmp(name, "VirtualAlloc", 12) == 0) has_virtual_alloc = true;
        if (_strnicmp(name, "WriteProcessMemory", 18) == 0) has_write_process_memory = true;
        if (_strnicmp(name, "CreateRemoteThread", 18) == 0) has_create_remote_thread = true;
        if (_strnicmp(name, "VirtualProtect", 14) == 0) has_virtual_protect = true;
        if (_strnicmp(name, "CreateThread", 12) == 0 &&
            _strnicmp(name, "CreateRemoteThread", 18) != 0)
            has_create_thread = true;
        if (_strnicmp(name, "CreateService", 13) == 0) has_create_service = true;
        if (_strnicmp(name, "StartService", 12) == 0) has_start_service = true;
        if (_strnicmp(name, "RegSetValueEx", 13) == 0) has_reg_set_value = true;
        if (_strnicmp(name, "GetProcAddress", 14) == 0) has_get_proc_address = true;
        if (_strnicmp(name, "LoadLibrary", 11) == 0) has_load_library = true;
    }

    uint32_t bits = 0;

    /* Bit 0: injection combo */
    if (has_virtual_alloc && has_write_process_memory && has_create_remote_thread)
        bits |= 1;

    /* Bit 1: shellcode loader */
    if (has_virtual_alloc && has_virtual_protect && has_create_thread)
        bits |= 2;

    /* Bit 2: service installer */
    if (has_create_service && has_start_service)
        bits |= 4;

    /* Bit 3: registry persistence */
    if (has_reg_set_value)
        bits |= 8;

    /* Bit 4: ordinal-only imports */
    if (pe->ordinal_only_count == pe->num_import_funcs && pe->num_import_funcs > 0)
        bits |= 16;

    /* Bit 5: API hashing (only GetProcAddress + LoadLibrary, nothing else) */
    uint32_t named_count = pe->num_import_funcs - pe->ordinal_only_count;
    if (named_count > 0 && has_get_proc_address && has_load_library) {
        /* Check if ALL named imports are just GetProcAddress/LoadLibrary variants */
        bool all_apihash = true;
        for (uint32_t i = 0; i < pe->num_import_funcs && all_apihash; i++) {
            const char* n = pe->import_funcs[i].name;
            if (!n[0] || pe->import_funcs[i].is_ordinal) continue;
            if (_strnicmp(n, "GetProcAddress", 14) != 0 &&
                _strnicmp(n, "LoadLibrary", 11) != 0)
                all_apihash = false;
        }
        if (all_apihash)
            bits |= 32;
    }

    return bits;
}

void akav_ml_extract_features(const akav_pe_t* pe,
                                size_t file_size,
                                akav_ml_features_t* features)
{
    if (!pe || !features) return;
    memset(features, 0, sizeof(*features));

    /* [0] file_size_log2 */
    features->features[0] = file_size > 0 ? log2((double)file_size) : 0.0;

    /* [1] num_sections */
    features->features[1] = (double)pe->num_sections;

    /* [2] text_entropy, [3] max_entropy, [4] mean_entropy */
    double text_ent = 0.0;
    double max_ent = 0.0;
    double sum_ent = 0.0;
    int ent_count = 0;
    bool found_text = false;

    for (uint32_t i = 0; i < pe->num_sections; i++) {
        double e = pe->sections[i].entropy;
        if (e < 0.0) continue;  /* not computed */
        if (e > max_ent) max_ent = e;
        sum_ent += e;
        ent_count++;

        /* .text or first executable section */
        if (!found_text) {
            if (_strnicmp(pe->sections[i].name, ".text", 5) == 0) {
                text_ent = e;
                found_text = true;
            } else if (pe->sections[i].characteristics & 0x20000000u) {
                text_ent = e;
                found_text = true;
            }
        }
    }

    features->features[2] = text_ent;
    features->features[3] = max_ent;
    features->features[4] = ent_count > 0 ? sum_ent / ent_count : 0.0;

    /* [5] import_dll_count, [6] import_func_count */
    features->features[5] = (double)pe->num_import_dlls;
    features->features[6] = (double)pe->num_import_funcs;

    /* [7] has_overlay, [8] overlay_ratio */
    features->features[7] = pe->has_overlay ? 1.0 : 0.0;
    features->features[8] = (pe->has_overlay && file_size > 0)
        ? (double)pe->overlay_size / (double)file_size : 0.0;

    /* [9] has_rich_header */
    features->features[9] = pe->has_rich_header ? 1.0 : 0.0;

    /* [10] timestamp_suspicious: 0, <1990-01-01, or >2035-01-01 */
    uint32_t ts = pe->timestamp;
    features->features[10] = (ts == 0 || ts < 631152000u || ts > 2051222400u)
        ? 1.0 : 0.0;

    /* [11] entry_outside_text */
    double entry_outside = 0.0;
    for (uint32_t i = 0; i < pe->num_sections; i++) {
        if (_strnicmp(pe->sections[i].name, ".text", 5) == 0) {
            uint32_t sec_start = pe->sections[i].virtual_address;
            uint32_t sec_end = sec_start + pe->sections[i].virtual_size;
            if (pe->entry_point < sec_start || pe->entry_point >= sec_end)
                entry_outside = 1.0;
            break;
        }
    }
    features->features[11] = entry_outside;

    /* [12] has_authenticode */
    features->features[12] = pe->has_authenticode ? 1.0 : 0.0;

    /* [13] suspicious_api_bits */
    features->features[13] = (double)compute_api_bits(pe);
}

/* ── Inference ───────────────────────────────────────────────────── */

static double walk_tree(const akav_ml_tree_t* tree,
                          const double* features)
{
    if (!tree->nodes || tree->num_nodes == 0)
        return 0.0;

    int idx = 0;
    while (idx >= 0 && (uint32_t)idx < tree->num_nodes) {
        const akav_ml_node_t* node = &tree->nodes[idx];
        if (node->feature < 0) {
            /* Leaf node */
            return node->value;
        }
        if (node->feature >= AKAV_ML_NUM_FEATURES) {
            return 0.0;  /* invalid feature index */
        }
        if (features[node->feature] <= node->threshold)
            idx = node->left;
        else
            idx = node->right;
    }
    return 0.0;
}

bool akav_ml_classify(const akav_ml_model_t* model,
                        const akav_ml_features_t* features,
                        akav_ml_result_t* result)
{
    if (!result) return false;
    memset(result, 0, sizeof(*result));

    if (!model || !model->loaded || !features)
        return false;

    double sum = 0.0;
    for (uint32_t i = 0; i < model->num_trees; i++) {
        sum += walk_tree(&model->trees[i], features->features);
    }

    result->probability = model->num_trees > 0
        ? sum / (double)model->num_trees : 0.0;
    result->score = (int)(result->probability * AKAV_ML_SCORE_WEIGHT);
    result->classified = true;

    return true;
}
