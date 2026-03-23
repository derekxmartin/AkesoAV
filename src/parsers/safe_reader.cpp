#include "parsers/safe_reader.h"
#include <string.h>

void akav_reader_init(akav_safe_reader_t* r, const uint8_t* buf, size_t size)
{
    if (!r)
        return;
    r->data = buf;
    r->size = (buf != NULL) ? size : 0;
    r->pos = 0;
}

bool akav_reader_read_u8(akav_safe_reader_t* r, uint8_t* out)
{
    if (!r || !out)
        return false;
    if (r->pos >= r->size)
        return false;
    *out = r->data[r->pos];
    r->pos += 1;
    return true;
}

bool akav_reader_read_u16_le(akav_safe_reader_t* r, uint16_t* out)
{
    if (!r || !out)
        return false;
    if (r->size - r->pos < 2 || r->pos > r->size)
        return false;
    *out = (uint16_t)r->data[r->pos] |
           ((uint16_t)r->data[r->pos + 1] << 8);
    r->pos += 2;
    return true;
}

bool akav_reader_read_u32_le(akav_safe_reader_t* r, uint32_t* out)
{
    if (!r || !out)
        return false;
    if (r->size - r->pos < 4 || r->pos > r->size)
        return false;
    *out = (uint32_t)r->data[r->pos] |
           ((uint32_t)r->data[r->pos + 1] << 8) |
           ((uint32_t)r->data[r->pos + 2] << 16) |
           ((uint32_t)r->data[r->pos + 3] << 24);
    r->pos += 4;
    return true;
}

bool akav_reader_read_u64_le(akav_safe_reader_t* r, uint64_t* out)
{
    if (!r || !out)
        return false;
    if (r->size - r->pos < 8 || r->pos > r->size)
        return false;
    *out = (uint64_t)r->data[r->pos] |
           ((uint64_t)r->data[r->pos + 1] << 8) |
           ((uint64_t)r->data[r->pos + 2] << 16) |
           ((uint64_t)r->data[r->pos + 3] << 24) |
           ((uint64_t)r->data[r->pos + 4] << 32) |
           ((uint64_t)r->data[r->pos + 5] << 40) |
           ((uint64_t)r->data[r->pos + 6] << 48) |
           ((uint64_t)r->data[r->pos + 7] << 56);
    r->pos += 8;
    return true;
}

bool akav_reader_read_bytes(akav_safe_reader_t* r, uint8_t* out, size_t count)
{
    if (!r || !out)
        return false;
    /* Zero-length read always succeeds */
    if (count == 0)
        return true;
    /* Integer overflow check: pos + count might wrap */
    if (count > r->size - r->pos || r->pos > r->size)
        return false;
    memcpy(out, r->data + r->pos, count);
    r->pos += count;
    return true;
}

bool akav_reader_skip(akav_safe_reader_t* r, size_t count)
{
    if (!r)
        return false;
    if (count == 0)
        return true;
    /* Integer overflow check */
    if (count > r->size - r->pos || r->pos > r->size)
        return false;
    r->pos += count;
    return true;
}

bool akav_reader_seek_to(akav_safe_reader_t* r, size_t pos)
{
    if (!r)
        return false;
    if (pos > r->size)
        return false;
    r->pos = pos;
    return true;
}

size_t akav_reader_remaining(const akav_safe_reader_t* r)
{
    if (!r || r->pos > r->size)
        return 0;
    return r->size - r->pos;
}

size_t akav_reader_position(const akav_safe_reader_t* r)
{
    if (!r)
        return 0;
    return r->pos;
}

bool akav_reader_read_u16_be(akav_safe_reader_t* r, uint16_t* out)
{
    if (!r || !out)
        return false;
    if (r->size - r->pos < 2 || r->pos > r->size)
        return false;
    *out = ((uint16_t)r->data[r->pos] << 8) |
           (uint16_t)r->data[r->pos + 1];
    r->pos += 2;
    return true;
}

bool akav_reader_read_u32_be(akav_safe_reader_t* r, uint32_t* out)
{
    if (!r || !out)
        return false;
    if (r->size - r->pos < 4 || r->pos > r->size)
        return false;
    *out = ((uint32_t)r->data[r->pos] << 24) |
           ((uint32_t)r->data[r->pos + 1] << 16) |
           ((uint32_t)r->data[r->pos + 2] << 8) |
           (uint32_t)r->data[r->pos + 3];
    r->pos += 4;
    return true;
}

bool akav_reader_read_u64_be(akav_safe_reader_t* r, uint64_t* out)
{
    if (!r || !out)
        return false;
    if (r->size - r->pos < 8 || r->pos > r->size)
        return false;
    *out = ((uint64_t)r->data[r->pos] << 56) |
           ((uint64_t)r->data[r->pos + 1] << 48) |
           ((uint64_t)r->data[r->pos + 2] << 40) |
           ((uint64_t)r->data[r->pos + 3] << 32) |
           ((uint64_t)r->data[r->pos + 4] << 24) |
           ((uint64_t)r->data[r->pos + 5] << 16) |
           ((uint64_t)r->data[r->pos + 6] << 8) |
           (uint64_t)r->data[r->pos + 7];
    r->pos += 8;
    return true;
}
