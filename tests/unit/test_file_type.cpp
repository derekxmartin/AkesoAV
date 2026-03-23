#include <gtest/gtest.h>
#include "file_type.h"

TEST(FileType, DetectPE)
{
    uint8_t mz[] = {0x4D, 0x5A, 0x90, 0x00};
    EXPECT_EQ(akav_detect_file_type(mz, sizeof(mz)), AKAV_FILETYPE_PE);
}

TEST(FileType, DetectELF)
{
    uint8_t elf[] = {0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01};
    EXPECT_EQ(akav_detect_file_type(elf, sizeof(elf)), AKAV_FILETYPE_ELF);
}

TEST(FileType, DetectZIP)
{
    uint8_t zip[] = {0x50, 0x4B, 0x03, 0x04};
    EXPECT_EQ(akav_detect_file_type(zip, sizeof(zip)), AKAV_FILETYPE_ZIP);
}

TEST(FileType, DetectZIPEndOfCentralDir)
{
    uint8_t zip[] = {0x50, 0x4B, 0x05, 0x06};
    EXPECT_EQ(akav_detect_file_type(zip, sizeof(zip)), AKAV_FILETYPE_ZIP);
}

TEST(FileType, DetectGZIP)
{
    uint8_t gz[] = {0x1F, 0x8B, 0x08};
    EXPECT_EQ(akav_detect_file_type(gz, sizeof(gz)), AKAV_FILETYPE_GZIP);
}

TEST(FileType, DetectPDF)
{
    uint8_t pdf[] = {0x25, 0x50, 0x44, 0x46, 0x2D, 0x31};
    EXPECT_EQ(akav_detect_file_type(pdf, sizeof(pdf)), AKAV_FILETYPE_PDF);
}

TEST(FileType, DetectOLE2)
{
    uint8_t ole2[] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    EXPECT_EQ(akav_detect_file_type(ole2, sizeof(ole2)), AKAV_FILETYPE_OLE2);
}

TEST(FileType, DetectTAR)
{
    /* TAR: "ustar" at offset 257. Need 262 bytes min. */
    uint8_t tar[262] = {0};
    tar[257] = 'u';
    tar[258] = 's';
    tar[259] = 't';
    tar[260] = 'a';
    tar[261] = 'r';
    EXPECT_EQ(akav_detect_file_type(tar, sizeof(tar)), AKAV_FILETYPE_TAR);
}

TEST(FileType, UnknownData)
{
    uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    EXPECT_EQ(akav_detect_file_type(data, sizeof(data)), AKAV_FILETYPE_UNKNOWN);
}

TEST(FileType, EmptyFile)
{
    EXPECT_EQ(akav_detect_file_type(nullptr, 0), AKAV_FILETYPE_UNKNOWN);
}

TEST(FileType, SingleByteFile)
{
    uint8_t data[] = {0x4D}; /* Just 'M', not enough for MZ */
    EXPECT_EQ(akav_detect_file_type(data, 1), AKAV_FILETYPE_UNKNOWN);
}

TEST(FileType, TypeNameStrings)
{
    EXPECT_STREQ(akav_file_type_name(AKAV_FILETYPE_PE), "PE");
    EXPECT_STREQ(akav_file_type_name(AKAV_FILETYPE_ELF), "ELF");
    EXPECT_STREQ(akav_file_type_name(AKAV_FILETYPE_ZIP), "ZIP");
    EXPECT_STREQ(akav_file_type_name(AKAV_FILETYPE_GZIP), "GZIP");
    EXPECT_STREQ(akav_file_type_name(AKAV_FILETYPE_TAR), "TAR");
    EXPECT_STREQ(akav_file_type_name(AKAV_FILETYPE_PDF), "PDF");
    EXPECT_STREQ(akav_file_type_name(AKAV_FILETYPE_OLE2), "OLE2");
    EXPECT_STREQ(akav_file_type_name(AKAV_FILETYPE_UNKNOWN), "UNKNOWN");
}
