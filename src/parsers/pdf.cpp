// pdf.cpp -- PDF parser for AV scanning (P7-T2).
//
// Extraction-focused parser: xref tables (traditional + streams),
// stream decompression (Flate/ASCII85/ASCIIHex/LZW), JS extraction,
// embedded file extraction. Not a renderer.
//
// All buffer access is bounds-checked. Malformed input produces an
// error message, not a crash.

#include "parsers/pdf.h"
#include "parsers/safe_reader.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <zlib.h>

// ── Helpers ────────────────────────────────────────────────────────

static void pdf_error(akav_pdf_t* pdf, const char* msg)
{
    pdf->valid = false;
    strncpy_s(pdf->error, sizeof(pdf->error), msg, _TRUNCATE);
}

static void pdf_warn(akav_pdf_t* pdf, const char* msg)
{
    if (pdf->warning_count < 4)
        strncpy_s(pdf->warnings[pdf->warning_count], 128, msg, _TRUNCATE);
    pdf->warning_count++;
}

// Skip whitespace in PDF (space, tab, CR, LF, FF, NUL)
static bool is_pdf_ws(uint8_t c)
{
    return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
}

// Skip whitespace starting at pos, return new pos
static size_t skip_ws(const uint8_t* data, size_t data_len, size_t pos)
{
    while (pos < data_len && is_pdf_ws(data[pos]))
        pos++;
    return pos;
}

// Find a byte sequence in a buffer (forward search)
static size_t find_bytes(const uint8_t* data, size_t data_len,
                          size_t start, const char* needle, size_t needle_len)
{
    if (needle_len == 0 || start + needle_len > data_len)
        return (size_t)-1;
    for (size_t i = start; i + needle_len <= data_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0)
            return i;
    }
    return (size_t)-1;
}

// Find a byte sequence searching backwards from 'start'
static size_t rfind_bytes(const uint8_t* data, size_t start,
                           const char* needle, size_t needle_len)
{
    if (needle_len == 0 || start < needle_len)
        return (size_t)-1;
    for (size_t i = start - needle_len + 1; i > 0; i--) {
        if (memcmp(data + i - 1, needle, needle_len) == 0)
            return i - 1;
    }
    return (size_t)-1;
}

// Parse a non-negative integer from ASCII at data[pos]. Returns -1 on failure.
static int64_t parse_int(const uint8_t* data, size_t data_len, size_t* pos)
{
    size_t p = *pos;
    while (p < data_len && is_pdf_ws(data[p])) p++;
    if (p >= data_len || !isdigit(data[p]))
        return -1;
    int64_t val = 0;
    while (p < data_len && isdigit(data[p])) {
        val = val * 10 + (data[p] - '0');
        if (val > (int64_t)AKAV_PDF_MAX_DECOMPRESSED) return -1; // overflow guard
        p++;
    }
    *pos = p;
    return val;
}

// Decode a PDF name's #XX hex escapes in-place.
static void decode_pdf_name(char* name)
{
    char* dst = name;
    char* src = name;
    while (*src) {
        if (*src == '#' && isxdigit((uint8_t)src[1]) && isxdigit((uint8_t)src[2])) {
            char hex[3] = { src[1], src[2], 0 };
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

// ── PDF name/value extraction from dictionaries ───────────────────

// Find a /Name key in a dictionary region. Returns position after the name,
// or (size_t)-1 if not found. Handles #XX escapes in name matching.
static size_t find_dict_key(const uint8_t* data, size_t data_len,
                             size_t dict_start, size_t dict_end,
                             const char* key)
{
    size_t key_len = strlen(key);
    for (size_t i = dict_start; i + key_len < dict_end && i < data_len; i++) {
        if (data[i] == '/' && i + 1 + key_len <= dict_end) {
            // Extract the name token
            size_t name_start = i + 1;
            size_t name_end = name_start;
            while (name_end < dict_end && name_end < data_len &&
                   !is_pdf_ws(data[name_end]) && data[name_end] != '/' &&
                   data[name_end] != '<' && data[name_end] != '(' &&
                   data[name_end] != '[' && data[name_end] != '>') {
                name_end++;
            }

            // Copy and decode
            size_t nlen = name_end - name_start;
            if (nlen < 256) {
                char nbuf[256];
                memcpy(nbuf, data + name_start, nlen);
                nbuf[nlen] = '\0';
                decode_pdf_name(nbuf);
                if (strcmp(nbuf, key) == 0)
                    return name_end;
            }
        }
    }
    return (size_t)-1;
}

// Find matching >> for a << starting at pos (pos points to first <)
static size_t find_dict_end(const uint8_t* data, size_t data_len, size_t pos)
{
    if (pos + 1 >= data_len || data[pos] != '<' || data[pos + 1] != '<')
        return (size_t)-1;

    int depth = 0;
    for (size_t i = pos; i + 1 < data_len; i++) {
        if (data[i] == '<' && data[i + 1] == '<') { depth++; i++; }
        else if (data[i] == '>' && data[i + 1] == '>') {
            depth--;
            if (depth == 0) return i + 2;
            i++;
        }
    }
    return (size_t)-1;
}

// Extract an indirect reference "N G R" at position, returning obj number.
// Returns 0 on failure.
static uint32_t parse_ref(const uint8_t* data, size_t data_len, size_t pos)
{
    size_t p = skip_ws(data, data_len, pos);
    int64_t obj_num = parse_int(data, data_len, &p);
    if (obj_num < 0) return 0;
    p = skip_ws(data, data_len, p);
    int64_t gen = parse_int(data, data_len, &p);
    if (gen < 0) return 0;
    p = skip_ws(data, data_len, p);
    if (p < data_len && data[p] == 'R')
        return (uint32_t)obj_num;
    return 0;
}

// Extract a PDF string value: either (...) literal or <hex>.
// Returns malloc'd null-terminated string, or NULL on failure.
static uint8_t* extract_string(const uint8_t* data, size_t data_len,
                                size_t pos, size_t* out_len)
{
    size_t p = skip_ws(data, data_len, pos);
    if (p >= data_len) return nullptr;

    if (data[p] == '(') {
        // Literal string
        p++;
        int paren_depth = 1;
        size_t start = p;
        while (p < data_len && paren_depth > 0) {
            if (data[p] == '\\' && p + 1 < data_len) { p += 2; continue; }
            if (data[p] == '(') paren_depth++;
            else if (data[p] == ')') paren_depth--;
            if (paren_depth > 0) p++;
        }
        size_t len = p - start;
        uint8_t* result = (uint8_t*)malloc(len + 1);
        if (!result) return nullptr;
        // Basic unescape (just copy for now — full escape handling not needed for JS content)
        size_t dst = 0;
        for (size_t i = start; i < start + len; i++) {
            if (data[i] == '\\' && i + 1 < start + len) {
                i++;
                switch (data[i]) {
                case 'n': result[dst++] = '\n'; break;
                case 'r': result[dst++] = '\r'; break;
                case 't': result[dst++] = '\t'; break;
                case '(': result[dst++] = '('; break;
                case ')': result[dst++] = ')'; break;
                case '\\': result[dst++] = '\\'; break;
                default: result[dst++] = data[i]; break;
                }
            } else {
                result[dst++] = data[i];
            }
        }
        result[dst] = '\0';
        *out_len = dst;
        return result;
    }

    if (data[p] == '<' && (p + 1 >= data_len || data[p + 1] != '<')) {
        // Hex string
        p++;
        size_t start = p;
        while (p < data_len && data[p] != '>') p++;
        size_t hex_len = p - start;
        size_t out_cap = hex_len / 2 + 1;
        uint8_t* result = (uint8_t*)malloc(out_cap + 1);
        if (!result) return nullptr;
        size_t dst = 0;
        uint8_t byte = 0;
        int nibbles = 0;
        for (size_t i = start; i < start + hex_len; i++) {
            uint8_t c = data[i];
            int nib = -1;
            if (c >= '0' && c <= '9') nib = c - '0';
            else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
            if (nib >= 0) {
                byte = (byte << 4) | (uint8_t)nib;
                nibbles++;
                if (nibbles == 2) {
                    result[dst++] = byte;
                    byte = 0;
                    nibbles = 0;
                }
            }
        }
        if (nibbles == 1) result[dst++] = (byte << 4);
        result[dst] = '\0';
        *out_len = dst;
        return result;
    }

    return nullptr;
}

// ── Filter decoders ───────────────────────────────────────────────

bool akav_pdf_decode_flate(const uint8_t* in, size_t in_len,
                            uint8_t** out, size_t* out_len)
{
    if (!in || in_len == 0 || !out || !out_len) return false;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = (Bytef*)in;
    strm.avail_in = (uInt)in_len;

    // Try zlib-wrapped first (MAX_WBITS), fall back to raw (-MAX_WBITS)
    int init_ret = inflateInit2(&strm, MAX_WBITS);
    if (init_ret != Z_OK) return false;

    size_t buf_size = in_len * 4;
    if (buf_size < 4096) buf_size = 4096;
    if (buf_size > AKAV_PDF_MAX_DECOMPRESSED) buf_size = AKAV_PDF_MAX_DECOMPRESSED;

    uint8_t* buf = (uint8_t*)malloc(buf_size);
    if (!buf) { inflateEnd(&strm); return false; }

    size_t total_out = 0;
    int ret;
    bool retry_raw = false;

    for (;;) {
        if (total_out >= AKAV_PDF_MAX_DECOMPRESSED) {
            free(buf); inflateEnd(&strm); return false;
        }
        if (total_out >= buf_size) {
            size_t new_size = buf_size * 2;
            if (new_size > AKAV_PDF_MAX_DECOMPRESSED) new_size = AKAV_PDF_MAX_DECOMPRESSED;
            uint8_t* nb = (uint8_t*)realloc(buf, new_size);
            if (!nb) { free(buf); inflateEnd(&strm); return false; }
            buf = nb;
            buf_size = new_size;
        }

        strm.next_out = (Bytef*)(buf + total_out);
        strm.avail_out = (uInt)(buf_size - total_out);

        ret = inflate(&strm, Z_NO_FLUSH);
        total_out = strm.total_out;

        if (ret == Z_STREAM_END) break;
        if (ret == Z_DATA_ERROR && strm.total_out == 0) {
            // Might be raw deflate, retry
            retry_raw = true;
            break;
        }
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            free(buf); inflateEnd(&strm); return false;
        }
        if (strm.avail_in == 0 && strm.avail_out > 0) break;
    }

    inflateEnd(&strm);

    if (retry_raw) {
        memset(&strm, 0, sizeof(strm));
        strm.next_in = (Bytef*)in;
        strm.avail_in = (uInt)in_len;
        if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) { free(buf); return false; }

        total_out = 0;
        for (;;) {
            if (total_out >= AKAV_PDF_MAX_DECOMPRESSED) {
                free(buf); inflateEnd(&strm); return false;
            }
            if (total_out >= buf_size) {
                size_t new_size = buf_size * 2;
                if (new_size > AKAV_PDF_MAX_DECOMPRESSED) new_size = AKAV_PDF_MAX_DECOMPRESSED;
                uint8_t* nb = (uint8_t*)realloc(buf, new_size);
                if (!nb) { free(buf); inflateEnd(&strm); return false; }
                buf = nb;
                buf_size = new_size;
            }
            strm.next_out = (Bytef*)(buf + total_out);
            strm.avail_out = (uInt)(buf_size - total_out);
            ret = inflate(&strm, Z_NO_FLUSH);
            total_out = strm.total_out;
            if (ret == Z_STREAM_END) break;
            if (ret != Z_OK && ret != Z_BUF_ERROR) {
                free(buf); inflateEnd(&strm); return false;
            }
            if (strm.avail_in == 0 && strm.avail_out > 0) break;
        }
        inflateEnd(&strm);
    }

    *out = buf;
    *out_len = total_out;
    return total_out > 0;
}

bool akav_pdf_decode_ascii85(const uint8_t* in, size_t in_len,
                              uint8_t** out, size_t* out_len)
{
    if (!in || !out || !out_len) return false;

    size_t out_cap = (in_len / 5) * 4 + 4;
    uint8_t* buf = (uint8_t*)malloc(out_cap + 1);
    if (!buf) return false;

    size_t dst = 0;
    uint32_t tuple = 0;
    int count = 0;

    for (size_t i = 0; i < in_len; i++) {
        uint8_t c = in[i];

        if (is_pdf_ws(c)) continue;

        // End-of-data marker
        if (c == '~' && i + 1 < in_len && in[i + 1] == '>') {
            break;
        }

        // 'z' encodes four zero bytes
        if (c == 'z') {
            if (count != 0) { free(buf); return false; }
            if (dst + 4 > out_cap) {
                out_cap = out_cap * 2;
                uint8_t* nb = (uint8_t*)realloc(buf, out_cap + 1);
                if (!nb) { free(buf); return false; }
                buf = nb;
            }
            buf[dst++] = 0; buf[dst++] = 0; buf[dst++] = 0; buf[dst++] = 0;
            continue;
        }

        if (c < 33 || c > 117) { free(buf); return false; } // invalid char

        tuple = tuple * 85 + (c - 33);
        count++;

        if (count == 5) {
            if (dst + 4 > out_cap) {
                out_cap = out_cap * 2;
                uint8_t* nb = (uint8_t*)realloc(buf, out_cap + 1);
                if (!nb) { free(buf); return false; }
                buf = nb;
            }
            buf[dst++] = (uint8_t)(tuple >> 24);
            buf[dst++] = (uint8_t)(tuple >> 16);
            buf[dst++] = (uint8_t)(tuple >> 8);
            buf[dst++] = (uint8_t)(tuple);
            tuple = 0;
            count = 0;
        }
    }

    // Handle remaining bytes (partial group)
    if (count > 1) {
        // Pad with 'u' (84) chars
        for (int i = count; i < 5; i++)
            tuple = tuple * 85 + 84;
        int out_bytes = count - 1;
        if (dst + (size_t)out_bytes > out_cap) {
            out_cap = dst + (size_t)out_bytes;
            uint8_t* nb = (uint8_t*)realloc(buf, out_cap + 1);
            if (!nb) { free(buf); return false; }
            buf = nb;
        }
        for (int i = 0; i < out_bytes; i++)
            buf[dst++] = (uint8_t)(tuple >> (24 - i * 8));
    }

    buf[dst] = '\0';
    *out = buf;
    *out_len = dst;
    return true;
}

bool akav_pdf_decode_asciihex(const uint8_t* in, size_t in_len,
                               uint8_t** out, size_t* out_len)
{
    if (!in || !out || !out_len) return false;

    size_t out_cap = in_len / 2 + 1;
    uint8_t* buf = (uint8_t*)malloc(out_cap + 1);
    if (!buf) return false;

    size_t dst = 0;
    uint8_t byte = 0;
    int nibbles = 0;

    for (size_t i = 0; i < in_len; i++) {
        uint8_t c = in[i];

        if (c == '>') break; // EOD

        if (is_pdf_ws(c)) continue;

        int nib = -1;
        if (c >= '0' && c <= '9') nib = c - '0';
        else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
        if (nib < 0) { free(buf); return false; }

        byte = (byte << 4) | (uint8_t)nib;
        nibbles++;
        if (nibbles == 2) {
            if (dst >= out_cap) {
                out_cap *= 2;
                uint8_t* nb = (uint8_t*)realloc(buf, out_cap + 1);
                if (!nb) { free(buf); return false; }
                buf = nb;
            }
            buf[dst++] = byte;
            byte = 0;
            nibbles = 0;
        }
    }

    // Trailing odd nibble: pad with 0
    if (nibbles == 1) {
        if (dst >= out_cap) {
            out_cap++;
            uint8_t* nb = (uint8_t*)realloc(buf, out_cap + 1);
            if (!nb) { free(buf); return false; }
            buf = nb;
        }
        buf[dst++] = (byte << 4);
    }

    buf[dst] = '\0';
    *out = buf;
    *out_len = dst;
    return true;
}

bool akav_pdf_decode_lzw(const uint8_t* in, size_t in_len,
                          uint8_t** out, size_t* out_len)
{
    if (!in || in_len == 0 || !out || !out_len) return false;

    // LZW constants (PDF uses MSB-first, early-change)
    const int CLEAR_CODE = 256;
    const int EOD_CODE = 257;
    const int FIRST_CODE = 258;
    const int MAX_CODE = 4096;

    // Table entry: prefix code + suffix byte
    struct LzwEntry {
        int16_t prefix;
        uint8_t suffix;
        uint16_t length;
    };

    LzwEntry* table = (LzwEntry*)calloc(MAX_CODE, sizeof(LzwEntry));
    if (!table) return false;

    size_t buf_size = in_len * 4;
    if (buf_size < 4096) buf_size = 4096;
    uint8_t* buf = (uint8_t*)malloc(buf_size);
    if (!buf) { free(table); return false; }

    // Initialize table with single-byte entries
    auto reset_table = [&](int& next_code, int& code_size) {
        for (int i = 0; i < 256; i++) {
            table[i].prefix = -1;
            table[i].suffix = (uint8_t)i;
            table[i].length = 1;
        }
        table[CLEAR_CODE].prefix = -1;
        table[CLEAR_CODE].length = 0;
        table[EOD_CODE].prefix = -1;
        table[EOD_CODE].length = 0;
        next_code = FIRST_CODE;
        code_size = 9;
    };

    // MSB-first bit reader
    size_t bit_pos = 0;
    auto read_bits = [&](int nbits) -> int {
        int result = 0;
        for (int i = 0; i < nbits; i++) {
            size_t byte_idx = (bit_pos + (size_t)i) / 8;
            int bit_idx = 7 - (int)((bit_pos + (size_t)i) % 8); // MSB first
            if (byte_idx >= in_len) return -1;
            result = (result << 1) | ((in[byte_idx] >> bit_idx) & 1);
        }
        bit_pos += (size_t)nbits;
        return result;
    };

    // Output a decoded string for a code
    uint8_t* stack = (uint8_t*)malloc(MAX_CODE);
    if (!stack) { free(table); free(buf); return false; }

    auto output_code = [&](int code, size_t& dst) -> uint8_t {
        int stack_len = 0;
        int c = code;
        while (c >= 0 && stack_len < MAX_CODE) {
            stack[stack_len++] = table[c].suffix;
            c = table[c].prefix;
        }
        // Output in reverse
        for (int i = stack_len - 1; i >= 0; i--) {
            if (dst >= buf_size) {
                size_t new_size = buf_size * 2;
                if (new_size > AKAV_PDF_MAX_DECOMPRESSED) {
                    free(stack); free(table); free(buf);
                    return 0; // will be caught
                }
                uint8_t* nb = (uint8_t*)realloc(buf, new_size);
                if (!nb) return 0;
                buf = nb;
                buf_size = new_size;
            }
            buf[dst++] = stack[i];
        }
        return stack_len > 0 ? stack[stack_len - 1] : 0; // first byte
    };

    int next_code, code_size;
    reset_table(next_code, code_size);

    size_t dst = 0;
    int old_code = -1;

    for (;;) {
        int code = read_bits(code_size);
        if (code < 0) break;

        if (code == EOD_CODE) break;

        if (code == CLEAR_CODE) {
            reset_table(next_code, code_size);
            old_code = -1;
            continue;
        }

        if (old_code == -1) {
            // First code after clear
            if (code >= next_code) { break; }
            output_code(code, dst);
            old_code = code;
            continue;
        }

        uint8_t first_byte;
        if (code < next_code) {
            first_byte = output_code(code, dst);
        } else if (code == next_code) {
            // Special case: code not yet in table
            // String = string(old_code) + first_byte(old_code)
            int c = old_code;
            while (table[c].prefix >= 0) c = table[c].prefix;
            first_byte = table[c].suffix;
            output_code(old_code, dst);
            if (dst >= buf_size) {
                size_t new_size = buf_size * 2;
                if (new_size > AKAV_PDF_MAX_DECOMPRESSED) break;
                uint8_t* nb = (uint8_t*)realloc(buf, new_size);
                if (!nb) break;
                buf = nb;
                buf_size = new_size;
            }
            buf[dst++] = first_byte;
        } else {
            break; // invalid
        }

        // Add to table
        if (next_code < MAX_CODE) {
            table[next_code].prefix = (int16_t)old_code;
            table[next_code].suffix = first_byte;
            table[next_code].length = table[old_code].length + 1;
            next_code++;
            // Early change: increase code size before it's needed
            if (next_code >= (1 << code_size) && code_size < 12)
                code_size++;
        }

        old_code = code;

        if (dst >= AKAV_PDF_MAX_DECOMPRESSED) break;
    }

    free(stack);
    free(table);

    *out = buf;
    *out_len = dst;
    return dst > 0;
}

// ── Stream decompression with filter chain ────────────────────────

bool akav_pdf_decompress_stream(const uint8_t* stream_data, size_t stream_len,
                                 const akav_pdf_filter_t* filters,
                                 uint32_t num_filters,
                                 uint8_t** out_data, size_t* out_len)
{
    if (!stream_data || !out_data || !out_len) return false;
    *out_data = nullptr;
    *out_len = 0;

    if (num_filters == 0) {
        // No filters -- just copy
        uint8_t* copy = (uint8_t*)malloc(stream_len + 1);
        if (!copy) return false;
        memcpy(copy, stream_data, stream_len);
        copy[stream_len] = '\0';
        *out_data = copy;
        *out_len = stream_len;
        return true;
    }

    // Apply filters in chain
    uint8_t* current = (uint8_t*)malloc(stream_len);
    if (!current) return false;
    memcpy(current, stream_data, stream_len);
    size_t current_len = stream_len;

    for (uint32_t i = 0; i < num_filters; i++) {
        uint8_t* decoded = nullptr;
        size_t decoded_len = 0;
        bool ok = false;

        switch (filters[i]) {
        case AKAV_PDF_FILTER_FLATE:
            ok = akav_pdf_decode_flate(current, current_len, &decoded, &decoded_len);
            break;
        case AKAV_PDF_FILTER_ASCII85:
            ok = akav_pdf_decode_ascii85(current, current_len, &decoded, &decoded_len);
            break;
        case AKAV_PDF_FILTER_ASCIIHEX:
            ok = akav_pdf_decode_asciihex(current, current_len, &decoded, &decoded_len);
            break;
        case AKAV_PDF_FILTER_LZW:
            ok = akav_pdf_decode_lzw(current, current_len, &decoded, &decoded_len);
            break;
        case AKAV_PDF_FILTER_NONE:
            decoded = (uint8_t*)malloc(current_len + 1);
            if (decoded) { memcpy(decoded, current, current_len); decoded[current_len] = '\0'; decoded_len = current_len; ok = true; }
            break;
        default:
            break;
        }

        free(current);
        if (!ok) return false;

        current = decoded;
        current_len = decoded_len;
    }

    *out_data = current;
    *out_len = current_len;
    return true;
}

// ── Xref parsing ──────────────────────────────────────────────────

// Parse traditional xref table at given offset.
// Adds entries to pdf->objects. Returns offset of trailer dict start, or 0.
static size_t parse_traditional_xref(akav_pdf_t* pdf, const uint8_t* data,
                                      size_t data_len, size_t xref_offset)
{
    size_t pos = xref_offset;

    // Expect "xref" keyword
    if (pos + 4 > data_len || memcmp(data + pos, "xref", 4) != 0)
        return 0;
    pos += 4;
    pos = skip_ws(data, data_len, pos);

    // Parse subsections
    while (pos < data_len && isdigit(data[pos])) {
        int64_t first_obj = parse_int(data, data_len, &pos);
        if (first_obj < 0) break;
        pos = skip_ws(data, data_len, pos);
        int64_t count = parse_int(data, data_len, &pos);
        if (count < 0 || count > AKAV_PDF_MAX_OBJECTS) break;
        pos = skip_ws(data, data_len, pos);

        for (int64_t i = 0; i < count && pos + 20 <= data_len; i++) {
            // Each entry: "oooooooooo ggggg n \r\n" (20 bytes)
            // Parse offset (10 digits)
            size_t epos = pos;
            int64_t offset = parse_int(data, data_len, &epos);
            epos = skip_ws(data, data_len, epos);
            int64_t gen = parse_int(data, data_len, &epos);
            epos = skip_ws(data, data_len, epos);

            char type = (epos < data_len) ? (char)data[epos] : 'f';
            epos++;

            uint32_t obj_num = (uint32_t)(first_obj + i);
            if (obj_num < AKAV_PDF_MAX_OBJECTS && offset >= 0 && gen >= 0) {
                // Grow objects array if needed
                if (obj_num >= pdf->num_objects) {
                    uint32_t new_count = obj_num + 1;
                    akav_pdf_xref_entry_t* new_objs = (akav_pdf_xref_entry_t*)realloc(
                        pdf->objects, new_count * sizeof(akav_pdf_xref_entry_t));
                    if (new_objs) {
                        // Zero-init new entries
                        for (uint32_t j = pdf->num_objects; j < new_count; j++)
                            memset(&new_objs[j], 0, sizeof(akav_pdf_xref_entry_t));
                        pdf->objects = new_objs;
                        pdf->num_objects = new_count;
                    }
                }

                if (obj_num < pdf->num_objects) {
                    akav_pdf_xref_entry_t* e = &pdf->objects[obj_num];
                    // Only set if not already defined (first xref wins for incremental)
                    if (e->offset == 0 && !e->in_use) {
                        e->obj_num = obj_num;
                        e->gen_num = (uint32_t)gen;
                        e->offset = (uint64_t)offset;
                        e->in_use = (type == 'n');
                    }
                }
            }

            // Advance to next line
            while (epos < data_len && (data[epos] == '\r' || data[epos] == '\n' ||
                   is_pdf_ws(data[epos])))
                epos++;
            pos = epos;
        }
    }

    // Find trailer
    size_t trailer_pos = find_bytes(data, data_len, pos, "trailer", 7);
    if (trailer_pos == (size_t)-1)
        trailer_pos = find_bytes(data, data_len, xref_offset, "trailer", 7);
    if (trailer_pos != (size_t)-1)
        return trailer_pos + 7;

    return 0;
}

// Parse xref stream object at given offset.
static bool parse_xref_stream(akav_pdf_t* pdf, const uint8_t* data,
                                size_t data_len, size_t obj_offset,
                                size_t* prev_offset)
{
    *prev_offset = 0;
    pdf->has_xref_streams = true;

    // Find the dictionary << ... >>
    size_t dict_start = find_bytes(data, data_len, obj_offset, "<<", 2);
    if (dict_start == (size_t)-1) return false;
    size_t dict_end = find_dict_end(data, data_len, dict_start);
    if (dict_end == (size_t)-1) return false;

    // Find /W array (required for xref stream)
    size_t w_pos = find_dict_key(data, data_len, dict_start, dict_end, "W");
    if (w_pos == (size_t)-1) return false;

    // Parse /W [w1 w2 w3]
    size_t p = skip_ws(data, data_len, w_pos);
    if (p >= data_len || data[p] != '[') return false;
    p++;
    int w[3] = { 0, 0, 0 };
    for (int i = 0; i < 3; i++) {
        int64_t v = parse_int(data, data_len, &p);
        if (v < 0 || v > 8) return false;
        w[i] = (int)v;
        p = skip_ws(data, data_len, p);
    }

    // Find /Size
    size_t size_pos = find_dict_key(data, data_len, dict_start, dict_end, "Size");
    int64_t xref_size = 0;
    if (size_pos != (size_t)-1) {
        size_t sp = size_pos;
        xref_size = parse_int(data, data_len, &sp);
    }

    // Find /Root for catalog
    size_t root_pos = find_dict_key(data, data_len, dict_start, dict_end, "Root");
    if (root_pos != (size_t)-1) {
        uint32_t catalog = parse_ref(data, data_len, root_pos);
        if (catalog > 0) pdf->catalog_obj = catalog;
    }

    // Find /Prev
    size_t prev_pos = find_dict_key(data, data_len, dict_start, dict_end, "Prev");
    if (prev_pos != (size_t)-1) {
        size_t pp = prev_pos;
        int64_t pv = parse_int(data, data_len, &pp);
        if (pv > 0) *prev_offset = (size_t)pv;
    }

    // Find /Length
    size_t len_pos = find_dict_key(data, data_len, dict_start, dict_end, "Length");
    if (len_pos == (size_t)-1) return false;
    size_t lp = len_pos;
    int64_t stream_length = parse_int(data, data_len, &lp);
    if (stream_length <= 0) return false;

    // Parse /Filter
    akav_pdf_filter_t filters[AKAV_PDF_MAX_FILTERS];
    uint32_t num_filters = 0;
    size_t filter_pos = find_dict_key(data, data_len, dict_start, dict_end, "Filter");
    if (filter_pos != (size_t)-1) {
        size_t fp = skip_ws(data, data_len, filter_pos);
        if (fp < data_len && data[fp] == '/') {
            // Single filter
            fp++;
            if (fp + 11 <= data_len && memcmp(data + fp, "FlateDecode", 11) == 0)
                filters[num_filters++] = AKAV_PDF_FILTER_FLATE;
        }
    }

    // Find stream data
    size_t stream_start = find_bytes(data, data_len, dict_end, "stream", 6);
    if (stream_start == (size_t)-1) return false;
    stream_start += 6;
    // Skip CR/LF after "stream"
    if (stream_start < data_len && data[stream_start] == '\r') stream_start++;
    if (stream_start < data_len && data[stream_start] == '\n') stream_start++;

    if (stream_start + (size_t)stream_length > data_len) return false;

    // Decompress
    uint8_t* decoded = nullptr;
    size_t decoded_len = 0;
    if (num_filters > 0) {
        if (!akav_pdf_decompress_stream(data + stream_start, (size_t)stream_length,
                                         filters, num_filters, &decoded, &decoded_len))
            return false;
    } else {
        decoded = (uint8_t*)malloc((size_t)stream_length);
        if (!decoded) return false;
        memcpy(decoded, data + stream_start, (size_t)stream_length);
        decoded_len = (size_t)stream_length;
    }

    // Parse xref stream entries using /W widths
    int entry_size = w[0] + w[1] + w[2];
    if (entry_size <= 0 || (size_t)entry_size > decoded_len) {
        free(decoded);
        return false;
    }

    // Parse /Index array (optional, defaults to [0 Size])
    int64_t index_pairs[128]; // first, count pairs
    int num_pairs = 0;

    size_t idx_pos = find_dict_key(data, data_len, dict_start, dict_end, "Index");
    if (idx_pos != (size_t)-1) {
        size_t ip = skip_ws(data, data_len, idx_pos);
        if (ip < data_len && data[ip] == '[') {
            ip++;
            while (num_pairs < 64) {
                ip = skip_ws(data, data_len, ip);
                if (ip >= data_len || data[ip] == ']') break;
                int64_t first = parse_int(data, data_len, &ip);
                if (first < 0) break;
                ip = skip_ws(data, data_len, ip);
                int64_t count = parse_int(data, data_len, &ip);
                if (count < 0) break;
                index_pairs[num_pairs * 2] = first;
                index_pairs[num_pairs * 2 + 1] = count;
                num_pairs++;
            }
        }
    }
    if (num_pairs == 0) {
        index_pairs[0] = 0;
        index_pairs[1] = xref_size;
        num_pairs = 1;
    }

    size_t data_pos = 0;
    for (int pair = 0; pair < num_pairs; pair++) {
        int64_t first_obj = index_pairs[pair * 2];
        int64_t count = index_pairs[pair * 2 + 1];

        for (int64_t i = 0; i < count && data_pos + (size_t)entry_size <= decoded_len; i++) {
            // Read fields
            uint64_t field[3] = { 0, 0, 0 };
            for (int f = 0; f < 3; f++) {
                for (int b = 0; b < w[f]; b++) {
                    field[f] = (field[f] << 8) | decoded[data_pos++];
                }
            }
            // Default type is 1 if w[0] == 0
            if (w[0] == 0) field[0] = 1;

            uint32_t obj_num = (uint32_t)(first_obj + i);
            if (obj_num >= AKAV_PDF_MAX_OBJECTS) continue;

            // Grow array
            if (obj_num >= pdf->num_objects) {
                uint32_t new_count = obj_num + 1;
                akav_pdf_xref_entry_t* new_objs = (akav_pdf_xref_entry_t*)realloc(
                    pdf->objects, new_count * sizeof(akav_pdf_xref_entry_t));
                if (!new_objs) continue;
                for (uint32_t j = pdf->num_objects; j < new_count; j++)
                    memset(&new_objs[j], 0, sizeof(akav_pdf_xref_entry_t));
                pdf->objects = new_objs;
                pdf->num_objects = new_count;
            }

            akav_pdf_xref_entry_t* e = &pdf->objects[obj_num];
            if (e->offset == 0 && !e->in_use && !e->compressed) {
                e->obj_num = obj_num;
                if (field[0] == 0) {
                    // Free entry
                    e->in_use = false;
                } else if (field[0] == 1) {
                    // Uncompressed: field[1]=offset, field[2]=gen
                    e->offset = field[1];
                    e->gen_num = (uint32_t)field[2];
                    e->in_use = true;
                } else if (field[0] == 2) {
                    // Compressed: field[1]=ObjStm obj, field[2]=index
                    e->compressed = true;
                    e->stream_obj = (uint32_t)field[1];
                    e->stream_idx = (uint32_t)field[2];
                    e->in_use = true;
                }
            }
        }
    }

    free(decoded);
    return true;
}

// ── Object content locating ───────────────────────────────────────

// Find the start of object N's content (after "N G obj").
// Returns position after "obj" keyword, or (size_t)-1.
static size_t find_obj_content(const uint8_t* data, size_t data_len,
                                const akav_pdf_t* pdf, uint32_t obj_num)
{
    if (obj_num >= pdf->num_objects) return (size_t)-1;
    const akav_pdf_xref_entry_t* e = &pdf->objects[obj_num];
    if (!e->in_use || e->compressed) return (size_t)-1;

    size_t pos = (size_t)e->offset;
    if (pos >= data_len) return (size_t)-1;

    // Skip "N G obj"
    size_t p = pos;
    parse_int(data, data_len, &p); // obj num
    p = skip_ws(data, data_len, p);
    parse_int(data, data_len, &p); // gen num
    p = skip_ws(data, data_len, p);
    if (p + 3 <= data_len && memcmp(data + p, "obj", 3) == 0)
        p += 3;
    return skip_ws(data, data_len, p);
}

// Find endobj for the object starting at obj_start
static size_t find_obj_end(const uint8_t* data, size_t data_len, size_t obj_start)
{
    size_t pos = find_bytes(data, data_len, obj_start, "endobj", 6);
    return (pos != (size_t)-1) ? pos : data_len;
}

// Get stream data for an object that has one. Returns stream body start and length.
static bool get_object_stream(const uint8_t* data, size_t data_len,
                               size_t obj_start, size_t obj_end,
                               size_t* stream_start, size_t* stream_length,
                               akav_pdf_filter_t* filters, uint32_t* num_filters)
{
    *num_filters = 0;

    // Find dictionary
    size_t dict_start = find_bytes(data, data_len, obj_start, "<<", 2);
    if (dict_start == (size_t)-1 || dict_start >= obj_end) return false;
    size_t dict_end = find_dict_end(data, data_len, dict_start);
    if (dict_end == (size_t)-1 || dict_end > obj_end) return false;

    // Get /Length
    size_t len_pos = find_dict_key(data, data_len, dict_start, dict_end, "Length");
    if (len_pos == (size_t)-1) return false;
    size_t lp = len_pos;
    int64_t length = parse_int(data, data_len, &lp);
    if (length <= 0 || length > (int64_t)(data_len - obj_start)) return false;

    // Parse /Filter
    size_t filter_pos = find_dict_key(data, data_len, dict_start, dict_end, "Filter");
    if (filter_pos != (size_t)-1) {
        size_t fp = skip_ws(data, data_len, filter_pos);
        if (fp < data_len && data[fp] == '[') {
            // Array of filters
            fp++;
            while (*num_filters < AKAV_PDF_MAX_FILTERS && fp < dict_end) {
                fp = skip_ws(data, data_len, fp);
                if (fp >= dict_end || data[fp] == ']') break;
                if (data[fp] == '/') {
                    fp++;
                    if (fp + 11 <= data_len && memcmp(data + fp, "FlateDecode", 11) == 0)
                        { filters[(*num_filters)++] = AKAV_PDF_FILTER_FLATE; fp += 11; }
                    else if (fp + 13 <= data_len && memcmp(data + fp, "ASCII85Decode", 13) == 0)
                        { filters[(*num_filters)++] = AKAV_PDF_FILTER_ASCII85; fp += 13; }
                    else if (fp + 14 <= data_len && memcmp(data + fp, "ASCIIHexDecode", 14) == 0)
                        { filters[(*num_filters)++] = AKAV_PDF_FILTER_ASCIIHEX; fp += 14; }
                    else if (fp + 9 <= data_len && memcmp(data + fp, "LZWDecode", 9) == 0)
                        { filters[(*num_filters)++] = AKAV_PDF_FILTER_LZW; fp += 9; }
                    else {
                        // Skip unknown filter name
                        while (fp < dict_end && !is_pdf_ws(data[fp]) &&
                               data[fp] != '/' && data[fp] != ']') fp++;
                    }
                } else {
                    fp++;
                }
            }
        } else if (fp < data_len && data[fp] == '/') {
            fp++;
            if (fp + 11 <= data_len && memcmp(data + fp, "FlateDecode", 11) == 0)
                filters[(*num_filters)++] = AKAV_PDF_FILTER_FLATE;
            else if (fp + 13 <= data_len && memcmp(data + fp, "ASCII85Decode", 13) == 0)
                filters[(*num_filters)++] = AKAV_PDF_FILTER_ASCII85;
            else if (fp + 14 <= data_len && memcmp(data + fp, "ASCIIHexDecode", 14) == 0)
                filters[(*num_filters)++] = AKAV_PDF_FILTER_ASCIIHEX;
            else if (fp + 9 <= data_len && memcmp(data + fp, "LZWDecode", 9) == 0)
                filters[(*num_filters)++] = AKAV_PDF_FILTER_LZW;
        }
    }

    // Find "stream" keyword
    size_t s = find_bytes(data, data_len, dict_end, "stream", 6);
    if (s == (size_t)-1 || s >= obj_end) return false;
    s += 6;
    if (s < data_len && data[s] == '\r') s++;
    if (s < data_len && data[s] == '\n') s++;

    if (s + (size_t)length > data_len) return false;

    *stream_start = s;
    *stream_length = (size_t)length;
    return true;
}

// ── Main parse ────────────────────────────────────────────────────

bool akav_pdf_parse(akav_pdf_t* pdf, const uint8_t* data, size_t data_len)
{
    if (!pdf) return false;
    memset(pdf, 0, sizeof(*pdf));

    if (!data || data_len < 8) {
        pdf_error(pdf, "Buffer too small for PDF");
        return false;
    }

    // Find %PDF header (may not be at byte 0)
    size_t header_pos = (size_t)-1;
    for (size_t i = 0; i < data_len - 4 && i < 1024; i++) {
        if (data[i] == '%' && data[i+1] == 'P' && data[i+2] == 'D' && data[i+3] == 'F') {
            header_pos = i;
            break;
        }
    }
    if (header_pos == (size_t)-1) {
        pdf_error(pdf, "No %PDF header found");
        return false;
    }

    // Parse version: %PDF-M.m
    if (header_pos + 7 < data_len && data[header_pos + 4] == '-') {
        pdf->major_version = data[header_pos + 5] - '0';
        pdf->minor_version = data[header_pos + 7] - '0';
    }

    // Find startxref (search backwards from end)
    size_t search_start = data_len > 1024 ? data_len - 1024 : 0;
    size_t startxref_pos = (size_t)-1;
    for (size_t i = data_len; i > search_start; ) {
        startxref_pos = rfind_bytes(data, i, "startxref", 9);
        if (startxref_pos != (size_t)-1) break;
        break;
    }

    if (startxref_pos == (size_t)-1) {
        // Try linear search as fallback
        startxref_pos = find_bytes(data, data_len, search_start, "startxref", 9);
    }

    if (startxref_pos == (size_t)-1) {
        pdf_error(pdf, "No startxref found");
        return false;
    }

    // Parse the offset after "startxref"
    size_t p = startxref_pos + 9;
    p = skip_ws(data, data_len, p);
    int64_t xref_offset = parse_int(data, data_len, &p);
    if (xref_offset < 0 || (size_t)xref_offset >= data_len) {
        pdf_error(pdf, "Invalid startxref offset");
        return false;
    }

    // Follow xref chain (handles incremental updates)
    size_t visited[AKAV_PDF_MAX_XREF_TABLES];
    int num_visited = 0;

    size_t cur_offset = (size_t)xref_offset;
    while (cur_offset > 0 && cur_offset < data_len &&
           num_visited < AKAV_PDF_MAX_XREF_TABLES) {
        // Loop detection
        bool seen = false;
        for (int i = 0; i < num_visited; i++) {
            if (visited[i] == cur_offset) { seen = true; break; }
        }
        if (seen) {
            pdf_warn(pdf, "Circular xref chain detected");
            break;
        }
        visited[num_visited++] = cur_offset;
        pdf->num_xref_tables++;

        // Determine if traditional or stream xref
        if (cur_offset + 4 <= data_len && memcmp(data + cur_offset, "xref", 4) == 0) {
            // Traditional xref
            size_t trailer_start = parse_traditional_xref(pdf, data, data_len, cur_offset);
            if (trailer_start == 0) break;

            // Parse trailer dictionary
            size_t tdict_start = find_bytes(data, data_len, trailer_start, "<<", 2);
            if (tdict_start == (size_t)-1) break;
            size_t tdict_end = find_dict_end(data, data_len, tdict_start);
            if (tdict_end == (size_t)-1) break;

            // /Root
            size_t root_pos = find_dict_key(data, data_len, tdict_start, tdict_end, "Root");
            if (root_pos != (size_t)-1 && pdf->catalog_obj == 0) {
                uint32_t catalog = parse_ref(data, data_len, root_pos);
                if (catalog > 0) pdf->catalog_obj = catalog;
            }

            // /Prev
            size_t prev_pos = find_dict_key(data, data_len, tdict_start, tdict_end, "Prev");
            if (prev_pos != (size_t)-1) {
                size_t pp = prev_pos;
                int64_t pv = parse_int(data, data_len, &pp);
                if (pv > 0 && (size_t)pv < data_len) {
                    cur_offset = (size_t)pv;
                    continue;
                }
            }
            break;
        } else {
            // Xref stream
            size_t prev = 0;
            if (!parse_xref_stream(pdf, data, data_len, cur_offset, &prev)) {
                pdf_warn(pdf, "Failed to parse xref stream");
                break;
            }
            if (prev > 0 && prev < data_len)
                cur_offset = prev;
            else
                break;
        }
    }

    if (pdf->num_objects == 0) {
        pdf_error(pdf, "No objects found in xref");
        return false;
    }

    pdf->valid = true;
    return true;
}

void akav_pdf_free(akav_pdf_t* pdf)
{
    if (!pdf) return;

    free(pdf->objects);
    pdf->objects = nullptr;
    pdf->num_objects = 0;

    if (pdf->js_entries) {
        for (uint32_t i = 0; i < pdf->num_js; i++)
            free(pdf->js_entries[i].data);
        free(pdf->js_entries);
        pdf->js_entries = nullptr;
    }
    pdf->num_js = 0;

    if (pdf->embedded_files) {
        for (uint32_t i = 0; i < pdf->num_embedded; i++)
            free(pdf->embedded_files[i].data);
        free(pdf->embedded_files);
        pdf->embedded_files = nullptr;
    }
    pdf->num_embedded = 0;
}

// ── JS extraction ─────────────────────────────────────────────────

static void add_js_entry(akav_pdf_t* pdf, uint32_t source_obj,
                          uint8_t* js_data, size_t js_len, const char* trigger)
{
    if (pdf->num_js >= AKAV_PDF_MAX_JS_ENTRIES) { free(js_data); return; }

    akav_pdf_js_entry_t* entries = (akav_pdf_js_entry_t*)realloc(
        pdf->js_entries, (pdf->num_js + 1) * sizeof(akav_pdf_js_entry_t));
    if (!entries) { free(js_data); return; }

    pdf->js_entries = entries;
    akav_pdf_js_entry_t* e = &entries[pdf->num_js];
    e->source_obj = source_obj;
    e->data = js_data;
    e->data_len = js_len;
    strncpy_s(e->trigger, sizeof(e->trigger), trigger, _TRUNCATE);
    pdf->num_js++;
    pdf->has_javascript = true;
}

// Extract JS from an action dictionary region
static void extract_js_from_action(akav_pdf_t* pdf, const uint8_t* data,
                                    size_t data_len, size_t dict_start,
                                    size_t dict_end, uint32_t obj_num,
                                    const char* trigger)
{
    // Check for /S /JavaScript
    size_t s_pos = find_dict_key(data, data_len, dict_start, dict_end, "S");
    if (s_pos == (size_t)-1) return;
    size_t sp = skip_ws(data, data_len, s_pos);
    if (sp >= data_len || data[sp] != '/') return;
    sp++;
    if (sp + 10 > data_len || memcmp(data + sp, "JavaScript", 10) != 0) return;

    // Found /S /JavaScript -- extract /JS value
    size_t js_pos = find_dict_key(data, data_len, dict_start, dict_end, "JS");
    if (js_pos == (size_t)-1) return;

    size_t jp = skip_ws(data, data_len, js_pos);

    // Could be a string literal or a reference to a stream
    if (jp < data_len && (data[jp] == '(' || (data[jp] == '<' && jp + 1 < data_len && data[jp+1] != '<'))) {
        size_t js_len = 0;
        uint8_t* js_data = extract_string(data, data_len, jp, &js_len);
        if (js_data && js_len > 0) {
            add_js_entry(pdf, obj_num, js_data, js_len, trigger);
        } else {
            free(js_data);
        }
    } else if (jp < data_len && isdigit(data[jp])) {
        // Reference to stream object
        uint32_t ref_obj = parse_ref(data, data_len, jp);
        if (ref_obj > 0) {
            size_t obj_start = find_obj_content(data, data_len, pdf, ref_obj);
            if (obj_start != (size_t)-1) {
                size_t obj_end = find_obj_end(data, data_len, obj_start);
                size_t stream_start, stream_length;
                akav_pdf_filter_t filters[AKAV_PDF_MAX_FILTERS];
                uint32_t num_filters;
                if (get_object_stream(data, data_len, obj_start, obj_end,
                                       &stream_start, &stream_length, filters, &num_filters)) {
                    uint8_t* js_data = nullptr;
                    size_t js_len = 0;
                    if (akav_pdf_decompress_stream(data + stream_start, stream_length,
                                                    filters, num_filters, &js_data, &js_len)) {
                        add_js_entry(pdf, ref_obj, js_data, js_len, trigger);
                    }
                }
            }
        }
    }
}

bool akav_pdf_extract_js(akav_pdf_t* pdf, const uint8_t* data, size_t data_len)
{
    if (!pdf || !pdf->valid || !data) return false;

    // Check catalog object for /OpenAction and /AA
    if (pdf->catalog_obj > 0 && pdf->catalog_obj < pdf->num_objects) {
        size_t cat_start = find_obj_content(data, data_len, pdf, pdf->catalog_obj);
        if (cat_start != (size_t)-1) {
            size_t cat_end = find_obj_end(data, data_len, cat_start);

            size_t dict_start = find_bytes(data, data_len, cat_start, "<<", 2);
            if (dict_start != (size_t)-1 && dict_start < cat_end) {
                size_t dict_end = find_dict_end(data, data_len, dict_start);
                if (dict_end == (size_t)-1) dict_end = cat_end;

                // /OpenAction
                size_t oa_pos = find_dict_key(data, data_len, dict_start, dict_end, "OpenAction");
                if (oa_pos != (size_t)-1) {
                    pdf->has_open_action = true;
                    size_t op = skip_ws(data, data_len, oa_pos);
                    if (op < data_len && data[op] == '<' && op + 1 < data_len && data[op+1] == '<') {
                        size_t oa_end = find_dict_end(data, data_len, op);
                        if (oa_end != (size_t)-1)
                            extract_js_from_action(pdf, data, data_len, op, oa_end,
                                                    pdf->catalog_obj, "OpenAction");
                    } else if (op < data_len && isdigit(data[op])) {
                        uint32_t ref = parse_ref(data, data_len, op);
                        if (ref > 0) {
                            size_t obj_s = find_obj_content(data, data_len, pdf, ref);
                            if (obj_s != (size_t)-1) {
                                size_t obj_e = find_obj_end(data, data_len, obj_s);
                                size_t d = find_bytes(data, data_len, obj_s, "<<", 2);
                                if (d != (size_t)-1 && d < obj_e) {
                                    size_t de = find_dict_end(data, data_len, d);
                                    if (de != (size_t)-1)
                                        extract_js_from_action(pdf, data, data_len, d, de,
                                                                ref, "OpenAction");
                                }
                            }
                        }
                    }
                }

                // /AA (additional actions)
                size_t aa_pos = find_dict_key(data, data_len, dict_start, dict_end, "AA");
                if (aa_pos != (size_t)-1) {
                    pdf->has_auto_action = true;
                }

                // /AcroForm
                if (find_dict_key(data, data_len, dict_start, dict_end, "AcroForm") != (size_t)-1)
                    pdf->has_acroform = true;
            }
        }
    }

    // Scan all objects for /S /JavaScript patterns (catches annotation actions, etc.)
    // This is a broad sweep -- we search for /JavaScript in the raw data
    size_t search_pos = 0;
    while (search_pos < data_len && pdf->num_js < AKAV_PDF_MAX_JS_ENTRIES) {
        size_t js_match = find_bytes(data, data_len, search_pos, "/JavaScript", 11);
        if (js_match == (size_t)-1) break;

        // Find the enclosing dictionary
        // Search backwards for <<
        size_t dict_start = (size_t)-1;
        for (size_t b = js_match; b > 0 && js_match - b < 512; b--) {
            if (data[b] == '<' && b + 1 < data_len && data[b + 1] == '<') {
                dict_start = b;
                break;
            }
        }

        if (dict_start != (size_t)-1) {
            size_t dict_end = find_dict_end(data, data_len, dict_start);
            if (dict_end != (size_t)-1) {
                // Determine source object
                uint32_t src_obj = 0;
                for (uint32_t i = 0; i < pdf->num_objects; i++) {
                    if (pdf->objects[i].in_use && !pdf->objects[i].compressed &&
                        pdf->objects[i].offset <= dict_start &&
                        pdf->objects[i].offset + 10000 >= dict_start) {
                        src_obj = i;
                    }
                }

                extract_js_from_action(pdf, data, data_len, dict_start, dict_end,
                                        src_obj, "Action");
            }
        }

        search_pos = js_match + 11;
    }

    return pdf->num_js > 0;
}

// ── Embedded file extraction ──────────────────────────────────────

bool akav_pdf_extract_embedded(akav_pdf_t* pdf, const uint8_t* data, size_t data_len)
{
    if (!pdf || !pdf->valid || !data) return false;

    // Look for /EmbeddedFiles in catalog or via raw search
    size_t search_pos = 0;
    while (search_pos < data_len && pdf->num_embedded < AKAV_PDF_MAX_EMBEDDED) {
        size_t ef_match = find_bytes(data, data_len, search_pos, "/EmbeddedFiles", 14);
        if (ef_match == (size_t)-1) break;
        pdf->has_embedded_files = true;
        search_pos = ef_match + 14;

        // TODO: Walk the name tree to extract individual files.
        // For now, flag that embedded files are present.
    }

    // Also search for /Type /EmbeddedFile streams directly
    search_pos = 0;
    while (search_pos < data_len && pdf->num_embedded < AKAV_PDF_MAX_EMBEDDED) {
        size_t match = find_bytes(data, data_len, search_pos, "/EmbeddedFile", 13);
        if (match == (size_t)-1) break;
        search_pos = match + 13;

        // Find the enclosing object
        size_t dict_start = (size_t)-1;
        for (size_t b = match; b > 0 && match - b < 1024; b--) {
            if (data[b] == '<' && b + 1 < data_len && data[b + 1] == '<') {
                dict_start = b;
                break;
            }
        }
        if (dict_start == (size_t)-1) continue;

        size_t dict_end = find_dict_end(data, data_len, dict_start);
        if (dict_end == (size_t)-1) continue;

        // Find the object boundary
        size_t obj_end = find_bytes(data, data_len, dict_end, "endobj", 6);
        if (obj_end == (size_t)-1) obj_end = data_len;

        // Try to extract the stream
        size_t stream_start, stream_length;
        akav_pdf_filter_t filters[AKAV_PDF_MAX_FILTERS];
        uint32_t num_filters;
        if (!get_object_stream(data, data_len, dict_start, obj_end,
                                &stream_start, &stream_length, filters, &num_filters))
            continue;

        uint8_t* file_data = nullptr;
        size_t file_len = 0;
        if (!akav_pdf_decompress_stream(data + stream_start, stream_length,
                                         filters, num_filters, &file_data, &file_len))
            continue;

        // Add to embedded files
        akav_pdf_embedded_file_t* files = (akav_pdf_embedded_file_t*)realloc(
            pdf->embedded_files,
            (pdf->num_embedded + 1) * sizeof(akav_pdf_embedded_file_t));
        if (!files) { free(file_data); continue; }
        pdf->embedded_files = files;

        akav_pdf_embedded_file_t* ef = &files[pdf->num_embedded];
        memset(ef, 0, sizeof(*ef));
        strncpy_s(ef->filename, sizeof(ef->filename), "embedded", _TRUNCATE);
        ef->data = file_data;
        ef->data_len = file_len;
        pdf->num_embedded++;
    }

    return pdf->num_embedded > 0 || pdf->has_embedded_files;
}

// ── Analyze (convenience) ─────────────────────────────────────────

void akav_pdf_analyze(akav_pdf_t* pdf, const uint8_t* data, size_t data_len)
{
    if (!pdf || !pdf->valid || !data) return;

    akav_pdf_extract_js(pdf, data, data_len);
    akav_pdf_extract_embedded(pdf, data, data_len);

    // Check for /Encrypt
    if (find_bytes(data, data_len, 0, "/Encrypt", 8) != (size_t)-1)
        pdf->has_encrypted = true;

    // Check for /Launch
    if (find_bytes(data, data_len, 0, "/Launch", 7) != (size_t)-1)
        pdf->has_launch_action = true;
}
