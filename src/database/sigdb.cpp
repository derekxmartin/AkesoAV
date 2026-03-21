#include "sigdb.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

/* ── Error helper ─────────────────────────────────────────────────── */

static void set_error(char* buf, size_t buf_size, const char* msg)
{
    if (buf && buf_size > 0) {
        size_t len = strlen(msg);
        if (len >= buf_size) len = buf_size - 1;
        memcpy(buf, msg, len);
        buf[len] = '\0';
    }
}

/* ── RSA-2048 signature verification via CNG ──────────────────────── */

static bool verify_rsa_signature(const uint8_t* data, size_t data_len,
                                  const uint8_t* signature, size_t sig_len,
                                  const uint8_t* pubkey_der, size_t pubkey_len)
{
    if (!pubkey_der || pubkey_len == 0)
        return true; /* skip verification if no key provided */

    BCRYPT_ALG_HANDLE sha256_alg = NULL;
    BCRYPT_ALG_HANDLE rsa_alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    bool result = false;

    /* Hash the data with SHA-256 */
    uint8_t hash[32];
    NTSTATUS status = BCryptOpenAlgorithmProvider(&sha256_alg,
        BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptHash(sha256_alg, NULL, 0,
                        (PUCHAR)data, (ULONG)data_len,
                        hash, sizeof(hash));
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Import RSA public key */
    status = BCryptOpenAlgorithmProvider(&rsa_alg,
        BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Try importing as BCRYPT_RSAPUBLIC_BLOB first (raw CNG format),
       then fall back to other formats if needed */
    status = BCryptImportKeyPair(rsa_alg, NULL,
        BCRYPT_RSAPUBLIC_BLOB, &key,
        (PUCHAR)pubkey_der, (ULONG)pubkey_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Verify signature using PKCS#1 v1.5 padding */
    BCRYPT_PKCS1_PADDING_INFO padding;
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    status = BCryptVerifySignature(key, &padding,
        hash, sizeof(hash),
        (PUCHAR)signature, (ULONG)sig_len,
        BCRYPT_PAD_PKCS1);

    result = BCRYPT_SUCCESS(status);

cleanup:
    if (key) BCryptDestroyKey(key);
    if (rsa_alg) BCryptCloseAlgorithmProvider(rsa_alg, 0);
    if (sha256_alg) BCryptCloseAlgorithmProvider(sha256_alg, 0);
    return result;
}

/* ── Validation of parsed database ────────────────────────────────── */

static bool validate_db(const akav_sigdb_t* /*db*/, const uint8_t* base, size_t file_size,
                         const uint8_t* rsa_pubkey, size_t rsa_pubkey_len,
                         char* error_buf, size_t error_buf_size)
{
    /* Check minimum size for header */
    if (file_size < AKAV_DB_HEADER_SIZE) {
        set_error(error_buf, error_buf_size, "File too small for header");
        return false;
    }

    const akav_db_header_t* hdr = (const akav_db_header_t*)base;

    /* Magic check */
    if (hdr->magic != AKAV_DB_MAGIC) {
        set_error(error_buf, error_buf_size, "Invalid magic (expected AKAV)");
        return false;
    }

    /* Version check */
    if (hdr->version != AKAV_DB_VERSION) {
        set_error(error_buf, error_buf_size, "Unsupported version");
        return false;
    }

    /* Section count sanity */
    if (hdr->section_count > 256) {
        set_error(error_buf, error_buf_size, "Section count exceeds maximum (256)");
        return false;
    }

    /* Check that section offset table fits */
    size_t table_end = (size_t)AKAV_DB_HEADER_SIZE +
                       (size_t)hdr->section_count * sizeof(akav_db_section_entry_t);
    if (table_end > file_size) {
        set_error(error_buf, error_buf_size, "Section offset table extends past file");
        return false;
    }

    /* Validate each section's offset + size fits within the file */
    const akav_db_section_entry_t* sections =
        (const akav_db_section_entry_t*)(base + AKAV_DB_HEADER_SIZE);

    for (uint32_t i = 0; i < hdr->section_count; i++) {
        uint64_t section_end = (uint64_t)sections[i].offset + sections[i].size;
        if (section_end > file_size) {
            set_error(error_buf, error_buf_size,
                      "Section data extends past file");
            return false;
        }
        /* Section must start after the header */
        if (sections[i].offset < AKAV_DB_HEADER_SIZE &&
            sections[i].size > 0) {
            set_error(error_buf, error_buf_size,
                      "Section overlaps header");
            return false;
        }
    }

    /* RSA signature verification */
    if (rsa_pubkey && rsa_pubkey_len > 0) {
        /* Build the signed data: header bytes 0x0000–0x0017 (24 bytes)
           + all section data */
        /* For simplicity, we verify header (pre-RSA-sig) + everything after header.
           The RSA sig covers bytes 0x0000-0x0017 + all section data. */
        size_t pre_sig_size = 0x18; /* magic + version + sig_count + created_at + section_count */

        /* We need to concatenate the pre-sig header with all section data.
           Section data starts after the header (0x0118). */
        size_t section_data_start = AKAV_DB_HEADER_SIZE +
            (size_t)hdr->section_count * sizeof(akav_db_section_entry_t);
        size_t section_data_len = file_size > section_data_start
                                      ? file_size - section_data_start : 0;

        /* Allocate buffer for signed payload */
        size_t signed_len = pre_sig_size + section_data_len;
        uint8_t* signed_data = (uint8_t*)malloc(signed_len);
        if (!signed_data) {
            set_error(error_buf, error_buf_size, "Allocation failed for RSA verify");
            return false;
        }

        __analysis_assume(signed_len >= pre_sig_size);
        memcpy(signed_data, base, pre_sig_size);
        if (section_data_len > 0) {
            memcpy(signed_data + pre_sig_size,
                   base + section_data_start, section_data_len);
        }

        bool sig_ok = verify_rsa_signature(
            signed_data, signed_len,
            hdr->rsa_signature, AKAV_DB_RSA_SIG_SIZE,
            rsa_pubkey, rsa_pubkey_len);

        free(signed_data);

        if (!sig_ok) {
            set_error(error_buf, error_buf_size,
                      "RSA signature verification failed");
            return false;
        }
    }

    return true;
}

/* ── Parse string table ───────────────────────────────────────────── */

static void find_string_table(akav_sigdb_t* db)
{
    db->string_table = NULL;
    db->string_table_size = 0;

    for (uint32_t i = 0; i < db->section_count; i++) {
        if (db->sections[i].section_type == AKAV_SECTION_STRING_TABLE) {
            uint32_t offset = db->sections[i].offset;
            uint32_t size = db->sections[i].size;
            if ((uint64_t)offset + size <= db->file_size) {
                db->string_table = (const char*)(db->base + offset);
                db->string_table_size = size;
            }
            break;
        }
    }
}

/* ── Open from memory-mapped file ─────────────────────────────────── */

bool akav_sigdb_open(akav_sigdb_t* db, const char* path,
                      const uint8_t* rsa_pubkey, size_t rsa_pubkey_len,
                      char* error_buf, size_t error_buf_size)
{
    if (!db || !path) {
        set_error(error_buf, error_buf_size, "Invalid arguments");
        return false;
    }

    memset(db, 0, sizeof(*db));

    /* Open file */
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        set_error(error_buf, error_buf_size, "Failed to open file");
        return false;
    }

    /* Get file size */
    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li) || li.QuadPart == 0) {
        CloseHandle(hFile);
        set_error(error_buf, error_buf_size, "Failed to get file size");
        return false;
    }

    size_t file_size = (size_t)li.QuadPart;

    /* Create read-only file mapping */
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY,
                                         0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        set_error(error_buf, error_buf_size, "Failed to create file mapping");
        return false;
    }

    /* Map view (read-only) */
    const uint8_t* base = (const uint8_t*)MapViewOfFile(
        hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        set_error(error_buf, error_buf_size, "Failed to map view of file");
        return false;
    }

    db->file_handle = hFile;
    db->mapping_handle = hMapping;
    db->base = base;
    db->file_size = file_size;

    /* Validate and parse */
    if (!validate_db(db, base, file_size,
                     rsa_pubkey, rsa_pubkey_len,
                     error_buf, error_buf_size)) {
        akav_sigdb_close(db);
        return false;
    }

    db->header = (const akav_db_header_t*)base;
    db->sections = (const akav_db_section_entry_t*)(base + AKAV_DB_HEADER_SIZE);
    db->section_count = db->header->section_count;
    db->total_signatures = db->header->signature_count;
    db->created_at = db->header->created_at;

    find_string_table(db);

    return true;
}

/* ── Open from memory buffer ──────────────────────────────────────── */

bool akav_sigdb_open_memory(akav_sigdb_t* db, const uint8_t* data, size_t size,
                             const uint8_t* rsa_pubkey, size_t rsa_pubkey_len,
                             char* error_buf, size_t error_buf_size)
{
    if (!db || !data || size == 0) {
        set_error(error_buf, error_buf_size, "Invalid arguments");
        return false;
    }

    memset(db, 0, sizeof(*db));

    db->base = data;
    db->file_size = size;
    /* file_handle and mapping_handle remain NULL (no file mapping) */

    if (!validate_db(db, data, size,
                     rsa_pubkey, rsa_pubkey_len,
                     error_buf, error_buf_size)) {
        memset(db, 0, sizeof(*db));
        return false;
    }

    db->header = (const akav_db_header_t*)data;
    db->sections = (const akav_db_section_entry_t*)(data + AKAV_DB_HEADER_SIZE);
    db->section_count = db->header->section_count;
    db->total_signatures = db->header->signature_count;
    db->created_at = db->header->created_at;

    find_string_table(db);

    return true;
}

/* ── Close ────────────────────────────────────────────────────────── */

void akav_sigdb_close(akav_sigdb_t* db)
{
    if (!db) return;

    if (db->mapping_handle) {
        if (db->base) {
            UnmapViewOfFile(db->base);
        }
        CloseHandle((HANDLE)db->mapping_handle);
    }

    if (db->file_handle) {
        CloseHandle((HANDLE)db->file_handle);
    }

    memset(db, 0, sizeof(*db));
}

/* ── Section lookup ───────────────────────────────────────────────── */

const akav_db_section_entry_t* akav_sigdb_find_section(
    const akav_sigdb_t* db, akav_section_type_t type)
{
    if (!db || !db->sections) return NULL;

    for (uint32_t i = 0; i < db->section_count; i++) {
        if (db->sections[i].section_type == (uint32_t)type) {
            return &db->sections[i];
        }
    }
    return NULL;
}

const uint8_t* akav_sigdb_section_data(const akav_sigdb_t* db,
                                        const akav_db_section_entry_t* section)
{
    if (!db || !db->base || !section) return NULL;

    uint64_t end = (uint64_t)section->offset + section->size;
    if (end > db->file_size) return NULL;

    return db->base + section->offset;
}

/* ── String table lookup ──────────────────────────────────────────── */

const char* akav_sigdb_lookup_string(const akav_sigdb_t* db,
                                      uint32_t name_index)
{
    if (!db || !db->string_table) return NULL;

    if (name_index >= db->string_table_size) return NULL;

    /* Ensure there's a null terminator before the end of the table */
    const char* str = db->string_table + name_index;
    size_t remaining = db->string_table_size - name_index;
    if (memchr(str, '\0', remaining) == NULL) return NULL;

    return str;
}
