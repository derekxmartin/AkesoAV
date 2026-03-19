#include <gtest/gtest.h>
#include "parsers/safe_reader.h"

TEST(SafeReader, EmptyBuffer)
{
    akav_safe_reader_t r;
    akav_reader_init(&r, nullptr, 0);
    EXPECT_EQ(akav_reader_remaining(&r), 0u);
    EXPECT_EQ(akav_reader_position(&r), 0u);

    uint8_t val;
    EXPECT_FALSE(akav_reader_read_u8(&r, &val));
}

TEST(SafeReader, SingleByte)
{
    uint8_t data[] = {0x42};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 1);

    EXPECT_EQ(akav_reader_remaining(&r), 1u);

    uint8_t val;
    EXPECT_TRUE(akav_reader_read_u8(&r, &val));
    EXPECT_EQ(val, 0x42);
    EXPECT_EQ(akav_reader_remaining(&r), 0u);

    EXPECT_FALSE(akav_reader_read_u8(&r, &val));
}

TEST(SafeReader, ReadU16LE)
{
    uint8_t data[] = {0x34, 0x12};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 2);

    uint16_t val;
    EXPECT_TRUE(akav_reader_read_u16_le(&r, &val));
    EXPECT_EQ(val, 0x1234);
}

TEST(SafeReader, ReadU32LE)
{
    uint8_t data[] = {0x78, 0x56, 0x34, 0x12};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 4);

    uint32_t val;
    EXPECT_TRUE(akav_reader_read_u32_le(&r, &val));
    EXPECT_EQ(val, 0x12345678u);
}

TEST(SafeReader, ReadU64LE)
{
    uint8_t data[] = {0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 8);

    uint64_t val;
    EXPECT_TRUE(akav_reader_read_u64_le(&r, &val));
    EXPECT_EQ(val, 0x1234567890ABCDEFull);
}

TEST(SafeReader, BoundaryOnePastEnd)
{
    uint8_t data[] = {0x01, 0x02};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 2);

    uint16_t val16;
    EXPECT_TRUE(akav_reader_read_u16_le(&r, &val16));
    /* Now at pos 2 (end), reading should fail */
    uint8_t val8;
    EXPECT_FALSE(akav_reader_read_u8(&r, &val8));
}

TEST(SafeReader, SkipPastEnd)
{
    uint8_t data[] = {0x01, 0x02, 0x03};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 3);

    EXPECT_TRUE(akav_reader_skip(&r, 2));
    EXPECT_EQ(akav_reader_remaining(&r), 1u);
    EXPECT_FALSE(akav_reader_skip(&r, 2));
    /* Position should not change on failure */
    EXPECT_EQ(akav_reader_position(&r), 2u);
}

TEST(SafeReader, ZeroLengthReadBytes)
{
    uint8_t data[] = {0x01};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 1);

    uint8_t out;
    EXPECT_TRUE(akav_reader_read_bytes(&r, &out, 0));
    EXPECT_EQ(akav_reader_position(&r), 0u);
}

TEST(SafeReader, ReadBytes)
{
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 4);

    uint8_t out[4];
    EXPECT_TRUE(akav_reader_read_bytes(&r, out, 4));
    EXPECT_EQ(out[0], 0x01);
    EXPECT_EQ(out[3], 0x04);
}

TEST(SafeReader, ReadBytesTooMany)
{
    uint8_t data[] = {0x01, 0x02};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 2);

    uint8_t out[4];
    EXPECT_FALSE(akav_reader_read_bytes(&r, out, 4));
}

TEST(SafeReader, SIZEMAXOverflow)
{
    uint8_t data[] = {0x01};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 1);

    uint8_t out;
    EXPECT_FALSE(akav_reader_read_bytes(&r, &out, SIZE_MAX));
    EXPECT_FALSE(akav_reader_skip(&r, SIZE_MAX));
}

TEST(SafeReader, SeekTo)
{
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    akav_safe_reader_t r;
    akav_reader_init(&r, data, 4);

    EXPECT_TRUE(akav_reader_seek_to(&r, 2));
    EXPECT_EQ(akav_reader_position(&r), 2u);

    uint8_t val;
    EXPECT_TRUE(akav_reader_read_u8(&r, &val));
    EXPECT_EQ(val, 0x03);

    /* Seek to end is valid */
    EXPECT_TRUE(akav_reader_seek_to(&r, 4));
    EXPECT_EQ(akav_reader_remaining(&r), 0u);

    /* Seek past end is invalid */
    EXPECT_FALSE(akav_reader_seek_to(&r, 5));

    /* Seek backward */
    EXPECT_TRUE(akav_reader_seek_to(&r, 0));
    EXPECT_EQ(akav_reader_position(&r), 0u);
}
