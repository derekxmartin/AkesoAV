#include "file_type.h"
#include "parsers/safe_reader.h"

akav_file_type_t akav_detect_file_type(const uint8_t* buf, size_t len)
{
    if (!buf || len == 0)
        return AKAV_FILETYPE_UNKNOWN;

    akav_safe_reader_t r;
    akav_reader_init(&r, buf, len);

    /* Need at least 2 bytes for the shortest magic (MZ, PK, 1F 8B) */
    if (len < 2)
        return AKAV_FILETYPE_UNKNOWN;

    /* OLE2: D0 CF 11 E0 A1 B1 1A E1 (8 bytes) — MS-CFB spec */
    if (len >= 8)
    {
        static const uint8_t ole2_magic[] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
        bool match = true;
        for (int i = 0; i < 8; i++)
        {
            if (buf[i] != ole2_magic[i])
            {
                match = false;
                break;
            }
        }
        if (match)
            return AKAV_FILETYPE_OLE2;
    }

    /* ELF: 7F 45 4C 46 (4 bytes) */
    if (len >= 4 && buf[0] == 0x7F && buf[1] == 0x45 && buf[2] == 0x4C && buf[3] == 0x46)
        return AKAV_FILETYPE_ELF;

    /* PDF: 25 50 44 46 (%PDF) */
    if (len >= 4 && buf[0] == 0x25 && buf[1] == 0x50 && buf[2] == 0x44 && buf[3] == 0x46)
        return AKAV_FILETYPE_PDF;

    /* ZIP: PK (50 4B 03 04 or 50 4B 05 06) */
    if (len >= 4 && buf[0] == 0x50 && buf[1] == 0x4B)
    {
        if ((buf[2] == 0x03 && buf[3] == 0x04) || (buf[2] == 0x05 && buf[3] == 0x06))
            return AKAV_FILETYPE_ZIP;
    }

    /* GZIP: 1F 8B */
    if (buf[0] == 0x1F && buf[1] == 0x8B)
        return AKAV_FILETYPE_GZIP;

    /* PE: 4D 5A (MZ) */
    if (buf[0] == 0x4D && buf[1] == 0x5A)
        return AKAV_FILETYPE_PE;

    /* TAR: "ustar" at offset 257 */
    if (len >= 262)
    {
        if (buf[257] == 'u' && buf[258] == 's' && buf[259] == 't' &&
            buf[260] == 'a' && buf[261] == 'r')
            return AKAV_FILETYPE_TAR;
    }

    return AKAV_FILETYPE_UNKNOWN;
}

const char* akav_file_type_name(akav_file_type_t type)
{
    switch (type)
    {
    case AKAV_FILETYPE_PE:      return "PE";
    case AKAV_FILETYPE_ELF:     return "ELF";
    case AKAV_FILETYPE_ZIP:     return "ZIP";
    case AKAV_FILETYPE_GZIP:    return "GZIP";
    case AKAV_FILETYPE_TAR:     return "TAR";
    case AKAV_FILETYPE_PDF:     return "PDF";
    case AKAV_FILETYPE_OLE2:    return "OLE2";
    case AKAV_FILETYPE_UNKNOWN: return "UNKNOWN";
    default:                   return "UNKNOWN";
    }
}
