/* update_test.cpp -- Interactive CLI for testing the update client against
 * the test HTTPS server (scripts/test_update_server.py).
 *
 * Usage:
 *   update_test.exe --url https://localhost:8443/manifest.json
 *                   --pubkey <path_to_pubkey.bin>
 *                   [--cert-fp <hex_sha256_fingerprint>]
 *                   [--db <path_to_current.akavdb>]
 *
 * If --db is omitted, uses a temporary file.
 * If --cert-fp is omitted, cert pinning is skipped (useful for self-signed certs).
 *
 * Exit codes:
 *   0 = success (updated or already up-to-date)
 *   1 = error (verification failed, network error, etc.)
 *   2 = usage error
 */

#include "update/update_client.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

static void usage(const char* prog)
{
    fprintf(stderr,
        "Usage: %s --url <manifest_url> --pubkey <pubkey.bin>\n"
        "          [--cert-fp <hex_sha256>] [--db <path.akavdb>]\n"
        "\n"
        "Options:\n"
        "  --url       Manifest URL (e.g. https://localhost:8443/manifest.json)\n"
        "  --pubkey    Path to RSA public key blob file (BCRYPT_RSAPUBLIC_BLOB)\n"
        "  --cert-fp   Server cert SHA-256 fingerprint (64 hex chars, optional)\n"
        "  --db        Path to current .akavdb (default: update_test_temp.akavdb)\n"
        "  --current-version N  Current DB version (skip update if manifest <= N)\n"
        "  --no-verify Skip TLS certificate validation (for self-signed certs)\n"
        "\n"
        "Example with test server:\n"
        "  1. Start server:  python scripts/test_update_server.py\n"
        "  2. Copy the printed pubkey.bin path and cert fingerprint\n"
        "  3. Run:  update_test.exe --url https://localhost:8443/manifest.json\n"
        "               --pubkey C:\\...\\pubkey.bin --no-verify\n",
        prog);
}

static std::vector<uint8_t> read_file(const char* path)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return {}; }
    std::vector<uint8_t> data((size_t)sz);
    fread(data.data(), 1, data.size(), f);
    fclose(f);
    return data;
}

int main(int argc, char* argv[])
{
    const char* url = nullptr;
    const char* pubkey_path = nullptr;
    const char* cert_fp_hex = nullptr;
    const char* db_path = "update_test_temp.akavdb";
    uint32_t current_version = 0;
    bool no_verify = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
            url = argv[++i];
        } else if (strcmp(argv[i], "--pubkey") == 0 && i + 1 < argc) {
            pubkey_path = argv[++i];
        } else if (strcmp(argv[i], "--cert-fp") == 0 && i + 1 < argc) {
            cert_fp_hex = argv[++i];
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--current-version") == 0 && i + 1 < argc) {
            current_version = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-verify") == 0) {
            no_verify = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!url) {
        fprintf(stderr, "Error: --url is required\n");
        usage(argv[0]);
        return 2;
    }

    /* Load RSA public key */
    std::vector<uint8_t> pubkey;
    if (pubkey_path) {
        pubkey = read_file(pubkey_path);
        if (pubkey.empty()) {
            fprintf(stderr, "Error: cannot read public key file: %s\n", pubkey_path);
            return 2;
        }
        printf("[*] Loaded RSA public key: %zu bytes from %s\n",
               pubkey.size(), pubkey_path);
    } else {
        printf("[*] No --pubkey specified, RSA signature verification disabled\n");
    }

    /* Parse cert fingerprint */
    uint8_t cert_fp[32] = {0};
    bool have_cert_fp = false;
    if (cert_fp_hex) {
        if (strlen(cert_fp_hex) != 64) {
            fprintf(stderr, "Error: --cert-fp must be 64 hex characters\n");
            return 2;
        }
        if (akav_hex_decode(cert_fp_hex, 64, cert_fp, 32) != 32) {
            fprintf(stderr, "Error: invalid hex in --cert-fp\n");
            return 2;
        }
        have_cert_fp = true;
        printf("[*] Cert pinning enabled: %.16s...\n", cert_fp_hex);
    } else if (!no_verify) {
        printf("[*] No --cert-fp specified, cert pinning disabled\n");
    }

    printf("[*] DB path: %s\n", db_path);
    printf("[*] Manifest URL: %s\n", url);
    printf("\n");

    /* Step 1: Fetch manifest to show what's available */
    printf("=== Step 1: Fetching manifest ===\n");
    uint8_t* manifest_data = nullptr;
    size_t manifest_len = 0;
    char fetch_error[256] = {0};

    if (!akav_update_https_fetch(url,
                                  have_cert_fp ? cert_fp : nullptr,
                                  no_verify,
                                  &manifest_data, &manifest_len,
                                  fetch_error, sizeof(fetch_error))) {
        printf("[FAIL] Fetch failed: %s\n", fetch_error);

        if (no_verify && strstr(fetch_error, "SendRequest") != nullptr) {
            printf("\n[*] Retrying without TLS validation...\n");
            printf("    (Self-signed cert requires --no-verify which disables\n");
            printf("     Windows TLS validation. For the test server, you may\n");
            printf("     need to temporarily trust the cert or use HTTP.)\n");
        }
        return 1;
    }

    printf("[OK] Received %zu bytes\n", manifest_len);

    /* Step 2: Parse manifest */
    printf("\n=== Step 2: Parsing manifest ===\n");
    akav_update_manifest_t manifest;
    if (!akav_update_parse_manifest((const char*)manifest_data, manifest_len,
                                     &manifest)) {
        printf("[FAIL] Invalid manifest JSON\n");
        free(manifest_data);
        return 1;
    }

    printf("[OK] Manifest parsed:\n");
    printf("     Version:       %u\n", manifest.version);
    printf("     Published:     %s\n", manifest.published_at);
    printf("     Min engine:    %u\n", manifest.minimum_engine_version);
    printf("     Files:         %u\n", manifest.num_files);
    printf("     Has signature: %s\n", manifest.has_manifest_signature ? "yes" : "no");

    for (uint32_t i = 0; i < manifest.num_files; i++) {
        printf("     File[%u]: %s (%s, %llu bytes)\n", i,
               manifest.files[i].name, manifest.files[i].type,
               (unsigned long long)manifest.files[i].size);
    }

    /* Step 3: Verify manifest signature */
    if (!pubkey.empty() && manifest.has_manifest_signature) {
        printf("\n=== Step 3: Verifying manifest RSA signature ===\n");

        bool sig_ok = akav_update_rsa_verify(
            (const uint8_t*)manifest.raw_body, manifest.raw_body_len,
            manifest.manifest_signature, AKAV_UPDATE_RSA_SIG_LEN,
            pubkey.data(), pubkey.size());

        if (sig_ok) {
            printf("[OK] Manifest RSA signature VALID\n");
        } else {
            printf("[FAIL] Manifest RSA signature INVALID - tampered or wrong key\n");
            free(manifest_data);
            return 1;
        }
    } else {
        printf("\n=== Step 3: Skipping manifest signature verification ===\n");
    }

    /* Step 3.5: Version comparison */
    if (current_version > 0 && manifest.version <= current_version) {
        printf("\n=== Version Check ===\n");
        printf("[OK] No update needed (manifest v%u <= current v%u)\n",
               manifest.version, current_version);
        free(manifest_data);
        return 0;
    }

    /* Step 4: Download and verify each file */
    for (uint32_t i = 0; i < manifest.num_files; i++) {
        const akav_update_file_t* file = &manifest.files[i];
        printf("\n=== Step 4.%u: Downloading %s ===\n", i, file->name);

        uint8_t* file_data = nullptr;
        size_t file_len = 0;
        char dl_error[256] = {0};

        if (!akav_update_https_fetch(file->url,
                                      have_cert_fp ? cert_fp : nullptr,
                                      no_verify,
                                      &file_data, &file_len,
                                      dl_error, sizeof(dl_error))) {
            printf("[FAIL] Download failed: %s\n", dl_error);
            free(manifest_data);
            return 1;
        }
        printf("[OK] Downloaded %zu bytes\n", file_len);

        /* SHA-256 verify */
        printf("     Verifying SHA-256... ");
        uint8_t file_hash[32];
        akav_update_sha256_buffer(file_data, file_len, file_hash);
        if (memcmp(file_hash, file->sha256, 32) == 0) {
            printf("MATCH\n");
        } else {
            printf("MISMATCH -file is tampered!\n");
            free(file_data);
            free(manifest_data);
            return 1;
        }

        /* RSA verify */
        if (!pubkey.empty()) {
            printf("     Verifying RSA signature... ");
            bool file_sig_ok = akav_update_rsa_verify(
                file_data, file_len,
                file->rsa_signature, AKAV_UPDATE_RSA_SIG_LEN,
                pubkey.data(), pubkey.size());
            if (file_sig_ok) {
                printf("VALID\n");
            } else {
                printf("INVALID\n");
                free(file_data);
                free(manifest_data);
                return 1;
            }
        }

        /* Write to .new file */
        char new_path[260];
        snprintf(new_path, sizeof(new_path), "%s.new", db_path);
        FILE* f = nullptr;
        fopen_s(&f, new_path, "wb");
        if (f) {
            fwrite(file_data, 1, file_len, f);
            fclose(f);
            printf("[OK] Written to %s\n", new_path);
        }
        free(file_data);

        /* Atomic install */
        printf("     Atomic install... ");
        char install_error[256] = {0};
        if (akav_update_install_db(new_path, db_path,
                                    install_error, sizeof(install_error))) {
            printf("OK\n");
        } else {
            printf("FAILED: %s\n", install_error);
            free(manifest_data);
            return 1;
        }
    }

    free(manifest_data);

    printf("\n=== Result ===\n");
    printf("[OK] Update to version %u installed successfully at %s\n",
           manifest.version, db_path);

    /* Show .prev exists */
    char prev_path[260];
    snprintf(prev_path, sizeof(prev_path), "%s.prev", db_path);
    FILE* pf = nullptr;
    if (fopen_s(&pf, prev_path, "rb") == 0 && pf) {
        fseek(pf, 0, SEEK_END);
        printf("     Previous version backed up: %s (%ld bytes)\n",
               prev_path, ftell(pf));
        fclose(pf);
    }

    /* Test rollback */
    printf("\n=== Bonus: Testing rollback ===\n");
    char rb_error[256] = {0};
    if (akav_update_rollback(db_path, rb_error, sizeof(rb_error))) {
        printf("[OK] Rollback successful -%s restored from .prev\n", db_path);
    } else {
        printf("[INFO] Rollback skipped: %s\n", rb_error);
    }

    return 0;
}
