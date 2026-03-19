#ifndef AKAV_FILE_TYPE_H
#define AKAV_FILE_TYPE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    AKAV_FILETYPE_UNKNOWN = 0,
    AKAV_FILETYPE_PE,       /* MZ header (DOS/PE) */
    AKAV_FILETYPE_ELF,      /* 7F 45 4C 46 */
    AKAV_FILETYPE_ZIP,      /* PK (50 4B 03 04 or 50 4B 05 06) */
    AKAV_FILETYPE_GZIP,     /* 1F 8B */
    AKAV_FILETYPE_TAR,      /* "ustar" at offset 257 */
    AKAV_FILETYPE_PDF,      /* %PDF (25 50 44 46) */
    AKAV_FILETYPE_OLE2,     /* D0 CF 11 E0 A1 B4 1A E1 */
} akav_file_type_t;

/* Detect file type from magic bytes. Reads the first bytes via SafeReader.
 * Returns AKAV_FILETYPE_UNKNOWN if no known magic matches or if buf is too small. */
akav_file_type_t akav_detect_file_type(const uint8_t* buf, size_t len);

/* Return a human-readable string for the file type. */
const char* akav_file_type_name(akav_file_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_FILE_TYPE_H */
