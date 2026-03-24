/**
 * sig_helper — Compute fuzzy hashes and graph signatures for test tooling.
 *
 * Usage:
 *   sig_helper fuzzy <file>    Print ssdeep hash of file
 *   sig_helper graph <file>    Print graph sig block hashes as JSON
 *   sig_helper md5   <file>    Print MD5 hex of file
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../src/signatures/fuzzy_hash.h"
#include "../src/signatures/graph_sig.h"
#include "../src/signatures/hash_matcher.h"

static uint8_t* read_file(const char* path, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    uint8_t* buf = (uint8_t*)malloc((size_t)len);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)len, f);
    fclose(f);
    if (rd != (size_t)len) { free(buf); return NULL; }
    *out_len = (size_t)len;
    return buf;
}

static int cmd_fuzzy(const char* path)
{
    size_t len = 0;
    uint8_t* data = read_file(path, &len);
    if (!data) {
        fprintf(stderr, "Error: cannot read '%s'\n", path);
        return 1;
    }

    char hash[128] = {0};
    if (!akav_fuzzy_hash_compute(data, len, hash)) {
        fprintf(stderr, "Error: fuzzy hash computation failed\n");
        free(data);
        return 1;
    }
    free(data);
    printf("%s\n", hash);
    return 0;
}

static int cmd_graph(const char* path)
{
    size_t len = 0;
    uint8_t* data = read_file(path, &len);
    if (!data) {
        fprintf(stderr, "Error: cannot read '%s'\n", path);
        return 1;
    }

    akav_graph_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    if (!akav_graph_sig_build(data, len, &sig)) {
        fprintf(stderr, "Error: graph sig build failed (not a PE or no .text)\n");
        free(data);
        return 1;
    }
    free(data);

    printf("{\"block_hashes\":[");
    for (uint32_t i = 0; i < sig.num_blocks; i++) {
        if (i > 0) printf(",");
        printf("%u", sig.block_hashes[i]);
    }
    printf("],\"num_blocks\":%u,\"total_insns\":%u}\n",
           sig.num_blocks, sig.total_insns);

    akav_graph_sig_free(&sig);
    return 0;
}

static int cmd_md5(const char* path)
{
    size_t len = 0;
    uint8_t* data = read_file(path, &len);
    if (!data) {
        fprintf(stderr, "Error: cannot read '%s'\n", path);
        return 1;
    }

    uint8_t md5[16];
    if (!akav_hash_md5(data, len, md5)) {
        fprintf(stderr, "Error: MD5 computation failed\n");
        free(data);
        return 1;
    }
    free(data);

    for (int i = 0; i < 16; i++)
        printf("%02x", md5[i]);
    printf("\n");
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: sig_helper <fuzzy|graph|md5> <file>\n");
        return 1;
    }

    const char* cmd = argv[1];
    const char* path = argv[2];

    if (strcmp(cmd, "fuzzy") == 0) return cmd_fuzzy(path);
    if (strcmp(cmd, "graph") == 0) return cmd_graph(path);
    if (strcmp(cmd, "md5") == 0) return cmd_md5(path);

    fprintf(stderr, "Unknown command: %s\n", cmd);
    return 1;
}
