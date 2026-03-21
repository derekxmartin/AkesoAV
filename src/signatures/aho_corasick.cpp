#include "aho_corasick.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ── Internal data structures ─────────────────────────────────────── */

/*
 * Each trie node has up to 256 children (one per byte value).
 * We use a flat array of nodes for cache locality.
 * Failure links and output chains are built during finalize.
 */

/* Pattern metadata stored alongside the automaton */
typedef struct {
    uint32_t pattern_id;
    uint32_t pattern_len;
} akav_ac_pattern_info_t;

/* Trie node */
typedef struct {
    int32_t  children[256];  /* child node index, -1 = none */
    int32_t  failure;        /* failure link node index */
    int32_t  output_link;    /* suffix link to next node with a pattern match */
    int32_t  pattern_index;  /* index into pattern_info array, -1 = none */
    uint32_t depth;          /* depth in trie (= prefix length) */
} akav_ac_node_t;

struct akav_ac {
    akav_ac_node_t*       nodes;
    uint32_t              node_count;
    uint32_t              node_capacity;
    akav_ac_pattern_info_t* patterns;
    uint32_t              pattern_count;
    uint32_t              pattern_capacity;
    bool                  finalized;
};

/* ── Node allocation ──────────────────────────────────────────────── */

static int32_t ac_alloc_node(akav_ac_t* ac)
{
    if (ac->node_count >= ac->node_capacity) {
        uint32_t new_cap = ac->node_capacity == 0 ? 256 : ac->node_capacity * 2;
        /* overflow check */
        if (new_cap < ac->node_capacity) return -1;

        akav_ac_node_t* new_nodes = (akav_ac_node_t*)realloc(
            ac->nodes, (size_t)new_cap * sizeof(akav_ac_node_t));
        if (!new_nodes) return -1;

        ac->nodes = new_nodes;
        ac->node_capacity = new_cap;
    }

    int32_t idx = (int32_t)ac->node_count++;
    akav_ac_node_t* node = &ac->nodes[idx];
    memset(node->children, 0xFF, sizeof(node->children)); /* -1 for all */
    node->failure = 0;
    node->output_link = -1;
    node->pattern_index = -1;
    node->depth = 0;

    return idx;
}

/* ── Create / Destroy ─────────────────────────────────────────────── */

akav_ac_t* akav_ac_create(void)
{
    akav_ac_t* ac = (akav_ac_t*)calloc(1, sizeof(akav_ac_t));
    if (!ac) return NULL;

    /* Allocate root node (index 0) */
    if (ac_alloc_node(ac) < 0) {
        free(ac);
        return NULL;
    }

    return ac;
}

void akav_ac_destroy(akav_ac_t* ac)
{
    if (ac) {
        free(ac->nodes);
        free(ac->patterns);
        free(ac);
    }
}

/* ── Add pattern ──────────────────────────────────────────────────── */

bool akav_ac_add_pattern(akav_ac_t* ac,
                          const uint8_t* pattern, uint32_t pattern_len,
                          uint32_t pattern_id)
{
    if (!ac || ac->finalized || !pattern || pattern_len == 0)
        return false;

    /* Walk/build trie */
    int32_t current = 0;
    for (uint32_t i = 0; i < pattern_len; i++) {
        uint8_t byte = pattern[i];
        if (ac->nodes[current].children[byte] < 0) {
            int32_t child = ac_alloc_node(ac);
            if (child < 0) return false;
            ac->nodes[child].depth = i + 1;
            ac->nodes[current].children[byte] = child;
        }
        current = ac->nodes[current].children[byte];
    }

    /* Store pattern info */
    if (ac->pattern_count >= ac->pattern_capacity) {
        uint32_t new_cap = ac->pattern_capacity == 0 ? 64 : ac->pattern_capacity * 2;
        if (new_cap < ac->pattern_capacity) return false;

        akav_ac_pattern_info_t* new_pats = (akav_ac_pattern_info_t*)realloc(
            ac->patterns, (size_t)new_cap * sizeof(akav_ac_pattern_info_t));
        if (!new_pats) return false;

        ac->patterns = new_pats;
        ac->pattern_capacity = new_cap;
    }

    uint32_t pidx = ac->pattern_count++;
    ac->patterns[pidx].pattern_id = pattern_id;
    ac->patterns[pidx].pattern_len = pattern_len;
    ac->nodes[current].pattern_index = (int32_t)pidx;

    return true;
}

/* ── Finalize (BFS to build failure + output links) ───────────────── */

bool akav_ac_finalize(akav_ac_t* ac)
{
    if (!ac || ac->finalized) return false;

    /* BFS queue — worst case all nodes */
    int32_t* queue = (int32_t*)malloc((size_t)ac->node_count * sizeof(int32_t));
    if (!queue) return false;

    uint32_t head = 0, tail = 0;

    /* Root's children: failure = root, enqueue */
    for (int c = 0; c < 256; c++) {
        int32_t child = ac->nodes[0].children[c];
        if (child > 0) {
            ac->nodes[child].failure = 0;
            queue[tail++] = child;
        } else {
            /* Point missing children of root back to root */
            ac->nodes[0].children[c] = 0;
        }
    }

    /* BFS */
    while (head < tail) {
        int32_t u = queue[head++];
        akav_ac_node_t* u_node = &ac->nodes[u];

        for (int c = 0; c < 256; c++) {
            int32_t v = u_node->children[c];
            if (v > 0) {
                /* Failure link: follow parent's failure link chain */
                int32_t f = u_node->failure;
                while (f > 0 && ac->nodes[f].children[c] <= 0) {
                    f = ac->nodes[f].failure;
                }
                int32_t fc = ac->nodes[f].children[c];
                ac->nodes[v].failure = (fc > 0 && fc != v) ? fc : 0;

                /* Output link: if failure node has a pattern, point to it;
                   otherwise inherit failure's output link */
                int32_t fail = ac->nodes[v].failure;
                if (ac->nodes[fail].pattern_index >= 0) {
                    ac->nodes[v].output_link = fail;
                } else {
                    ac->nodes[v].output_link = ac->nodes[fail].output_link;
                }

                queue[tail++] = v;
            } else {
                /* Fill missing transitions via failure links (goto optimization) */
                int32_t f = u_node->failure;
                u_node->children[c] = ac->nodes[f].children[c];
            }
        }
    }

    free(queue);
    ac->finalized = true;
    return true;
}

/* ── Search ───────────────────────────────────────────────────────── */

uint32_t akav_ac_search(const akav_ac_t* ac,
                         const uint8_t* data, size_t data_len,
                         akav_ac_match_cb callback, void* user_data)
{
    if (!ac || !ac->finalized || !data || data_len == 0)
        return 0;

    uint32_t match_count = 0;
    int32_t state = 0;  /* stack-allocated walk state */

    for (size_t i = 0; i < data_len; i++) {
        state = ac->nodes[state].children[data[i]];

        /* Report matches at current state */
        int32_t temp = state;
        while (temp > 0) {
            if (ac->nodes[temp].pattern_index >= 0) {
                match_count++;
                if (callback) {
                    const akav_ac_pattern_info_t* pi =
                        &ac->patterns[ac->nodes[temp].pattern_index];
                    akav_ac_match_t m;
                    m.pattern_id = pi->pattern_id;
                    m.offset = i;
                    m.pattern_len = pi->pattern_len;
                    if (!callback(&m, user_data))
                        return match_count;
                }
            }
            temp = ac->nodes[temp].output_link;
        }
    }

    return match_count;
}

/* ── Pattern count ────────────────────────────────────────────────── */

uint32_t akav_ac_pattern_count(const akav_ac_t* ac)
{
    return ac ? ac->pattern_count : 0;
}

/* ── Serialization ────────────────────────────────────────────────── */

/*
 * Format:
 *   [4] magic: "AKAC"
 *   [4] version: uint32_t (1)
 *   [4] node_count: uint32_t
 *   [4] pattern_count: uint32_t
 *   [1] finalized: uint8_t
 *   [N] nodes: node_count * sizeof(serialized_node)
 *   [M] patterns: pattern_count * sizeof(akav_ac_pattern_info_t)
 *
 * serialized_node (per node):
 *   [1024] children: 256 * int32_t
 *   [4]   failure: int32_t
 *   [4]   output_link: int32_t
 *   [4]   pattern_index: int32_t
 *   [4]   depth: uint32_t
 */

#define AKAV_AC_MAGIC       0x43414B41  /* "AKAC" */
#define AKAV_AC_VERSION     1
#define AKAV_AC_HEADER_SIZE 17  /* magic + version + node_count + pattern_count + finalized */
#define AKAV_AC_NODE_SERIAL_SIZE (256 * 4 + 4 + 4 + 4 + 4)  /* 1040 bytes */

size_t akav_ac_serialize(const akav_ac_t* ac, uint8_t* buf, size_t buf_size)
{
    if (!ac || !ac->finalized) return 0;

    size_t node_data = (size_t)ac->node_count * AKAV_AC_NODE_SERIAL_SIZE;
    size_t pat_data = (size_t)ac->pattern_count * sizeof(akav_ac_pattern_info_t);
    size_t required = AKAV_AC_HEADER_SIZE + node_data + pat_data;

    if (!buf || buf_size < required)
        return required;

    uint8_t* p = buf;

    /* Header */
    uint32_t magic = AKAV_AC_MAGIC;
    uint32_t version = AKAV_AC_VERSION;
    memcpy(p, &magic, 4); p += 4;
    memcpy(p, &version, 4); p += 4;
    memcpy(p, &ac->node_count, 4); p += 4;
    memcpy(p, &ac->pattern_count, 4); p += 4;
    *p++ = ac->finalized ? 1 : 0;

    /* Nodes */
    for (uint32_t i = 0; i < ac->node_count; i++) {
        const akav_ac_node_t* n = &ac->nodes[i];
        memcpy(p, n->children, 256 * 4); p += 256 * 4;
        memcpy(p, &n->failure, 4); p += 4;
        memcpy(p, &n->output_link, 4); p += 4;
        memcpy(p, &n->pattern_index, 4); p += 4;
        memcpy(p, &n->depth, 4); p += 4;
    }

    /* Patterns */
    if (ac->pattern_count > 0) {
        memcpy(p, ac->patterns, pat_data);
    }

    return required;
}

akav_ac_t* akav_ac_deserialize(const uint8_t* buf, size_t buf_size)
{
    if (!buf || buf_size < AKAV_AC_HEADER_SIZE)
        return NULL;

    const uint8_t* p = buf;

    uint32_t magic, version, node_count, pattern_count;
    uint8_t finalized;

    memcpy(&magic, p, 4); p += 4;
    memcpy(&version, p, 4); p += 4;
    memcpy(&node_count, p, 4); p += 4;
    memcpy(&pattern_count, p, 4); p += 4;
    finalized = *p++;

    if (magic != AKAV_AC_MAGIC || version != AKAV_AC_VERSION)
        return NULL;

    if (!finalized || node_count == 0)
        return NULL;

    /* Sanity caps to prevent huge allocations from crafted data */
    if (node_count > 16 * 1024 * 1024) /* ~16M nodes ≈ 16 GB, reject */
        return NULL;
    if (pattern_count > 4 * 1024 * 1024)
        return NULL;

    size_t node_data = (size_t)node_count * AKAV_AC_NODE_SERIAL_SIZE;
    size_t pat_data = (size_t)pattern_count * sizeof(akav_ac_pattern_info_t);
    if (buf_size < AKAV_AC_HEADER_SIZE + node_data + pat_data)
        return NULL;

    akav_ac_t* ac = (akav_ac_t*)calloc(1, sizeof(akav_ac_t));
    if (!ac) return NULL;

    ac->nodes = (akav_ac_node_t*)malloc((size_t)node_count * sizeof(akav_ac_node_t));
    if (!ac->nodes) {
        free(ac);
        return NULL;
    }

    /* Deserialize nodes */
    for (uint32_t i = 0; i < node_count; i++) {
        akav_ac_node_t* n = &ac->nodes[i];
        memcpy(n->children, p, 256 * 4); p += 256 * 4;
        memcpy(&n->failure, p, 4); p += 4;
        memcpy(&n->output_link, p, 4); p += 4;
        memcpy(&n->pattern_index, p, 4); p += 4;
        memcpy(&n->depth, p, 4); p += 4;

        /* Validate node references */
        if (n->failure < 0 || (uint32_t)n->failure >= node_count) n->failure = 0;
        if (n->output_link >= (int32_t)node_count) n->output_link = -1;
        if (n->pattern_index >= (int32_t)pattern_count) n->pattern_index = -1;
        for (int c = 0; c < 256; c++) {
            if (n->children[c] < 0 || (uint32_t)n->children[c] >= node_count)
                n->children[c] = 0;
        }
    }

    ac->node_count = node_count;
    ac->node_capacity = node_count;

    /* Deserialize patterns */
    if (pattern_count > 0) {
        ac->patterns = (akav_ac_pattern_info_t*)malloc(pat_data);
        if (!ac->patterns) {
            free(ac->nodes);
            free(ac);
            return NULL;
        }
        memcpy(ac->patterns, p, pat_data);
    }

    ac->pattern_count = pattern_count;
    ac->pattern_capacity = pattern_count;
    ac->finalized = true;

    return ac;
}
