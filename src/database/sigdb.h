#ifndef AKAV_SIGDB_H
#define AKAV_SIGDB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── .akavdb binary format constants (§3.4) ───────────────────────── */

#define AKAV_DB_MAGIC           0x56414B41  /* "AKAV" little-endian */
#define AKAV_DB_VERSION         1
#define AKAV_DB_HEADER_SIZE     0x0118      /* 280 bytes: fixed header */
#define AKAV_DB_RSA_SIG_SIZE    256         /* RSA-2048 signature */

/* Section types */
typedef enum {
    AKAV_SECTION_BLOOM       = 0,
    AKAV_SECTION_MD5         = 1,
    AKAV_SECTION_SHA256      = 2,
    AKAV_SECTION_CRC32       = 3,
    AKAV_SECTION_AHO_CORASICK = 4,
    AKAV_SECTION_FUZZY_HASH  = 5,
    AKAV_SECTION_GRAPH_SIG   = 6,
    AKAV_SECTION_YARA        = 7,
    AKAV_SECTION_WHITELIST   = 8,
    AKAV_SECTION_STRING_TABLE = 0xFF
} akav_section_type_t;

/* ── On-disk structures ───────────────────────────────────────────── */

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;             /* AKAV_DB_MAGIC */
    uint32_t version;           /* AKAV_DB_VERSION */
    uint32_t signature_count;   /* total sigs across all sections */
    int64_t  created_at;        /* Unix epoch seconds */
    uint32_t section_count;     /* number of section offset table entries */
    uint8_t  rsa_signature[AKAV_DB_RSA_SIG_SIZE]; /* RSA-2048 over header+sections */
} akav_db_header_t;

typedef struct {
    uint32_t section_type;      /* akav_section_type_t */
    uint32_t offset;            /* absolute byte offset from file start */
    uint32_t size;              /* section size in bytes */
    uint32_t entry_count;       /* number of signatures in section */
} akav_db_section_entry_t;

#pragma pack(pop)

/* ── Runtime database handle ──────────────────────────────────────── */

typedef struct {
    /* Memory-mapped file */
    void*    file_handle;       /* HANDLE from CreateFileA */
    void*    mapping_handle;    /* HANDLE from CreateFileMapping */
    const uint8_t* base;        /* MapViewOfFile base pointer */
    size_t   file_size;

    /* Parsed header */
    const akav_db_header_t*       header;
    const akav_db_section_entry_t* sections;  /* array of section_count entries */
    uint32_t section_count;

    /* String table (quick access) */
    const char* string_table;
    uint32_t    string_table_size;

    /* Signature stats */
    uint32_t total_signatures;
    int64_t  created_at;
} akav_sigdb_t;

/**
 * Open and memory-map a .akavdb file (read-only).
 * Validates magic, version, section offsets, and optionally RSA signature.
 *
 * If rsa_pubkey is NULL, RSA verification is skipped (useful for testing).
 * If rsa_pubkey is provided, it must be a DER-encoded RSA-2048 public key.
 *
 * Returns true on success. On failure, the sigdb is zeroed and the error
 * string describes what went wrong.
 */
bool akav_sigdb_open(akav_sigdb_t* db, const char* path,
                      const uint8_t* rsa_pubkey, size_t rsa_pubkey_len,
                      char* error_buf, size_t error_buf_size);

/**
 * Close the database, unmap the file, and release all handles.
 */
void akav_sigdb_close(akav_sigdb_t* db);

/**
 * Find a section by type. Returns pointer to the section entry, or NULL.
 */
const akav_db_section_entry_t* akav_sigdb_find_section(
    const akav_sigdb_t* db, akav_section_type_t type);

/**
 * Get a pointer to the raw section data. Returns NULL if the section
 * doesn't exist or the offset/size is invalid.
 */
const uint8_t* akav_sigdb_section_data(const akav_sigdb_t* db,
                                        const akav_db_section_entry_t* section);

/**
 * Look up a string in the string table by name_index (byte offset).
 * Returns the null-terminated string, or NULL if out of bounds.
 */
const char* akav_sigdb_lookup_string(const akav_sigdb_t* db,
                                      uint32_t name_index);

/**
 * Open a .akavdb from an in-memory buffer (no file mapping).
 * The caller must keep the buffer alive for the lifetime of the db.
 * Useful for testing without files on disk.
 */
bool akav_sigdb_open_memory(akav_sigdb_t* db, const uint8_t* data, size_t size,
                             const uint8_t* rsa_pubkey, size_t rsa_pubkey_len,
                             char* error_buf, size_t error_buf_size);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_SIGDB_H */
