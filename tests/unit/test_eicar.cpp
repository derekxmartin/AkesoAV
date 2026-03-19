#include <gtest/gtest.h>
#include "akesoav.h"
#include <cstring>

class EicarTest : public ::testing::Test
{
protected:
    akav_engine_t* engine = nullptr;

    void SetUp() override
    {
        ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);
        ASSERT_EQ(akav_engine_init(engine, nullptr), AKAV_OK);
    }

    void TearDown() override
    {
        if (engine)
            akav_engine_destroy(engine);
    }
};

static const char EICAR[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

TEST_F(EicarTest, DetectsEicarString)
{
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, (const uint8_t*)EICAR,
                                       strlen(EICAR), "eicar.com",
                                       &opts, &result);
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.malware_name, "EICAR-Test-Signature");
    EXPECT_STREQ(result.scanner_id, "byte_stream");
}

TEST_F(EicarTest, CleanBufferNotDetected)
{
    const char* clean = "This is a completely clean file with no malware.";
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, (const uint8_t*)clean,
                                       strlen(clean), "clean.txt",
                                       &opts, &result);
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0);
    EXPECT_STREQ(result.malware_name, "");
}

TEST_F(EicarTest, EmptyBufferClean)
{
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, (const uint8_t*)"", 0,
                                       "empty.bin", &opts, &result);
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0);
}

TEST_F(EicarTest, EicarWithPrefix)
{
    /* EICAR preceded by some garbage — should still detect */
    char buf[256];
    memset(buf, 'A', sizeof(buf));
    memcpy(buf + 50, EICAR, strlen(EICAR));

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, (const uint8_t*)buf,
                                       sizeof(buf), "embedded_eicar",
                                       &opts, &result);
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
}

TEST_F(EicarTest, ScanTimePopulated)
{
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_scan_buffer(engine, (const uint8_t*)EICAR, strlen(EICAR),
                    "eicar.com", &opts, &result);
    EXPECT_GE(result.scan_time_ms, 0);
}
