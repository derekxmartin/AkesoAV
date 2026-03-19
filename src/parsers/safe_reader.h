#ifndef AKAV_SAFE_READER_H
#define AKAV_SAFE_READER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const uint8_t* data;
    size_t size;
    size_t pos;
} akav_safe_reader_t;

/* Initialize a SafeReader over a buffer. buf may be NULL only if size==0. */
void akav_reader_init(akav_safe_reader_t* r, const uint8_t* buf, size_t size);

/* Read a single byte. Returns false on OOB. */
bool akav_reader_read_u8(akav_safe_reader_t* r, uint8_t* out);

/* Read a 16-bit little-endian value. Returns false on OOB. */
bool akav_reader_read_u16_le(akav_safe_reader_t* r, uint16_t* out);

/* Read a 32-bit little-endian value. Returns false on OOB. */
bool akav_reader_read_u32_le(akav_safe_reader_t* r, uint32_t* out);

/* Read a 64-bit little-endian value. Returns false on OOB. */
bool akav_reader_read_u64_le(akav_safe_reader_t* r, uint64_t* out);

/* Read 'count' bytes into 'out'. Returns false if not enough data.
 * Integer overflow safe: returns false if count would overflow size_t arithmetic. */
bool akav_reader_read_bytes(akav_safe_reader_t* r, uint8_t* out, size_t count);

/* Skip 'count' bytes. Returns false on OOB.
 * Integer overflow safe. */
bool akav_reader_skip(akav_safe_reader_t* r, size_t count);

/* Seek to an absolute position. Returns false if pos > size. */
bool akav_reader_seek_to(akav_safe_reader_t* r, size_t pos);

/* Returns bytes remaining from current position. */
size_t akav_reader_remaining(const akav_safe_reader_t* r);

/* Returns current position. */
size_t akav_reader_position(const akav_safe_reader_t* r);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_SAFE_READER_H */
