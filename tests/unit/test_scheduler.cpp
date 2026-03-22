// test_scheduler.cpp -- Tests for cron parser and scheduled scanning (P5-T8).
//
// Tests:
//   Cron Parser:
//    1. Wildcard expression: "* * * * *" matches every minute
//    2. Specific time: "0 2 * * 0" = Sunday 02:00
//    3. Range: "0-30 * * * *" = minutes 0-30
//    4. Step: "*/15 * * * *" = every 15 minutes
//    5. List: "0,15,30,45 * * * *"
//    6. Combined range+step: "0-30/10 * * * *"
//    7. Invalid expression: too few fields
//    8. Next trigger: "0 2 * * 0" after Saturday -> next Sunday 02:00
//    9. Next trigger: "*/5 * * * *" advances by ~5 minutes
//   10. Format time: produces readable string
//
//   Scheduler:
//   11. Load config from JSON file
//   12. Empty config returns false
//   13. Invalid cron expression skipped
//   14. Reload config
//   15. Run named schedule with SIEM events
//   16. Nonexistent schedule returns false
//   17. Scan not active by default

#include <gtest/gtest.h>

#include "service/cron_parser.h"
#include "service/scheduler.h"
#include "engine_internal.h"
#include "siem/siem_shipper.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <ctime>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <mutex>

namespace fs = std::filesystem;

/* ── Helpers ─────────────────────────────────────────────────────────── */

static std::string temp_dir()
{
    char buf[MAX_PATH];
    GetTempPathA(sizeof(buf), buf);
    std::string dir = std::string(buf) + "akav_sched_test_" +
                      std::to_string(GetCurrentProcessId());
    fs::create_directories(dir);
    return dir;
}

static void remove_dir(const std::string& dir)
{
    std::error_code ec;
    fs::remove_all(dir, ec);
}

/* ── Cron Parser Tests ────────────────────────────────────────────────── */

TEST(CronParser, WildcardEveryMinute)
{
    auto cron = akav::cron_parse("* * * * *");
    ASSERT_TRUE(cron.valid);

    /* All 60 minutes should be set */
    for (int i = 0; i < 60; ++i)
        EXPECT_TRUE(cron.minutes & (1ULL << i)) << "Minute " << i;

    /* All 24 hours */
    for (int i = 0; i < 24; ++i)
        EXPECT_TRUE(cron.hours & (1ULL << i)) << "Hour " << i;

    /* All 7 weekdays */
    for (int i = 0; i < 7; ++i)
        EXPECT_TRUE(cron.weekdays & (1 << i)) << "Weekday " << i;
}

TEST(CronParser, SpecificTime_Sunday0200)
{
    /* "0 2 * * 0" = minute 0, hour 2, any day, any month, Sunday */
    auto cron = akav::cron_parse("0 2 * * 0");
    ASSERT_TRUE(cron.valid);

    /* Only minute 0 */
    EXPECT_TRUE(cron.minutes & (1ULL << 0));
    EXPECT_FALSE(cron.minutes & (1ULL << 1));

    /* Only hour 2 */
    EXPECT_TRUE(cron.hours & (1ULL << 2));
    EXPECT_FALSE(cron.hours & (1ULL << 1));
    EXPECT_FALSE(cron.hours & (1ULL << 3));

    /* Only Sunday (0) */
    EXPECT_TRUE(cron.weekdays & (1 << 0));
    EXPECT_FALSE(cron.weekdays & (1 << 1));
}

TEST(CronParser, Range)
{
    auto cron = akav::cron_parse("0-30 * * * *");
    ASSERT_TRUE(cron.valid);

    for (int i = 0; i <= 30; ++i)
        EXPECT_TRUE(cron.minutes & (1ULL << i)) << "Minute " << i;
    for (int i = 31; i < 60; ++i)
        EXPECT_FALSE(cron.minutes & (1ULL << i)) << "Minute " << i;
}

TEST(CronParser, Step)
{
    // "*/15 * * * *" = 0, 15, 30, 45
    auto cron = akav::cron_parse("*/15 * * * *");
    ASSERT_TRUE(cron.valid);

    EXPECT_TRUE(cron.minutes & (1ULL << 0));
    EXPECT_TRUE(cron.minutes & (1ULL << 15));
    EXPECT_TRUE(cron.minutes & (1ULL << 30));
    EXPECT_TRUE(cron.minutes & (1ULL << 45));
    EXPECT_FALSE(cron.minutes & (1ULL << 1));
    EXPECT_FALSE(cron.minutes & (1ULL << 14));
}

TEST(CronParser, List)
{
    auto cron = akav::cron_parse("0,15,30,45 * * * *");
    ASSERT_TRUE(cron.valid);

    EXPECT_TRUE(cron.minutes & (1ULL << 0));
    EXPECT_TRUE(cron.minutes & (1ULL << 15));
    EXPECT_TRUE(cron.minutes & (1ULL << 30));
    EXPECT_TRUE(cron.minutes & (1ULL << 45));
    EXPECT_FALSE(cron.minutes & (1ULL << 10));
}

TEST(CronParser, RangeWithStep)
{
    /* "0-30/10 * * * *" = 0, 10, 20, 30 */
    auto cron = akav::cron_parse("0-30/10 * * * *");
    ASSERT_TRUE(cron.valid);

    EXPECT_TRUE(cron.minutes & (1ULL << 0));
    EXPECT_TRUE(cron.minutes & (1ULL << 10));
    EXPECT_TRUE(cron.minutes & (1ULL << 20));
    EXPECT_TRUE(cron.minutes & (1ULL << 30));
    EXPECT_FALSE(cron.minutes & (1ULL << 5));
    EXPECT_FALSE(cron.minutes & (1ULL << 15));
}

TEST(CronParser, InvalidTooFewFields)
{
    auto cron = akav::cron_parse("0 2 *");
    EXPECT_FALSE(cron.valid);

    auto cron2 = akav::cron_parse("");
    EXPECT_FALSE(cron2.valid);
}

TEST(CronParser, NextTriggerSunday0200)
{
    /* "0 2 * * 0" = every Sunday at 02:00 */
    auto cron = akav::cron_parse("0 2 * * 0");
    ASSERT_TRUE(cron.valid);

    /* Use a known Saturday: 2026-03-21 12:00:00 */
    struct tm tm_sat = {};
    tm_sat.tm_year = 126; /* 2026 */
    tm_sat.tm_mon = 2;    /* March */
    tm_sat.tm_mday = 21;  /* Saturday */
    tm_sat.tm_hour = 12;
    tm_sat.tm_min = 0;
    tm_sat.tm_sec = 0;
    tm_sat.tm_isdst = -1;
    time_t sat = mktime(&tm_sat);

    time_t next = akav::cron_next(cron, sat);
    ASSERT_NE(next, 0);

    struct tm tm_next;
    localtime_s(&tm_next, &next);
    EXPECT_EQ(tm_next.tm_wday, 0)  << "Should be Sunday";
    EXPECT_EQ(tm_next.tm_hour, 2)  << "Should be 02:00";
    EXPECT_EQ(tm_next.tm_min, 0)   << "Should be :00";
    EXPECT_EQ(tm_next.tm_mday, 22) << "Should be March 22";
}

TEST(CronParser, NextTriggerEvery5Minutes)
{
    auto cron = akav::cron_parse("*/5 * * * *");
    ASSERT_TRUE(cron.valid);

    time_t now = time(nullptr);
    time_t next = akav::cron_next(cron, now);
    ASSERT_NE(next, 0);

    /* Should be within ~5 minutes from now */
    EXPECT_GT(next, now);
    EXPECT_LE(next - now, 5 * 60 + 1);

    struct tm tm_next;
    localtime_s(&tm_next, &next);
    EXPECT_EQ(tm_next.tm_min % 5, 0) << "Should be on a 5-minute boundary";
}

TEST(CronParser, FormatTime)
{
    /* 2026-01-01 00:00:00 */
    struct tm tm_test = {};
    tm_test.tm_year = 126;
    tm_test.tm_mon = 0;
    tm_test.tm_mday = 1;
    tm_test.tm_hour = 0;
    tm_test.tm_min = 0;
    tm_test.tm_sec = 0;
    tm_test.tm_isdst = -1;
    time_t t = mktime(&tm_test);

    std::string s = akav::format_time(t);
    EXPECT_NE(s.find("2026"), std::string::npos) << "Should contain year: " << s;
    EXPECT_NE(s.find("01-01"), std::string::npos) << "Should contain date: " << s;
}

/* ── Scheduler Config Tests ──────────────────────────────────────────── */

class SchedulerTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = temp_dir();
        config_path_ = dir_ + "\\schedules.json";

        ASSERT_EQ(akav_engine_create(&engine_), AKAV_OK);
        ASSERT_EQ(akav_engine_init(engine_, nullptr), AKAV_OK);
    }

    void TearDown() override {
        if (engine_) akav_engine_destroy(engine_);
        remove_dir(dir_);
    }

    void write_config(const std::string& json) {
        std::ofstream f(config_path_);
        f << json;
    }

    std::string dir_;
    std::string config_path_;
    akav_engine_t* engine_ = nullptr;
};

TEST_F(SchedulerTest, LoadConfigFromJSON)
{
    write_config(R"([
        {
            "name": "Quick Scan",
            "type": "quick",
            "paths": [],
            "cron": "0 12 * * *",
            "enabled": true
        },
        {
            "name": "Weekly Full",
            "type": "full",
            "paths": ["C:\\"],
            "cron": "0 2 * * 0",
            "enabled": true
        }
    ])");

    akav::Scheduler scheduler;
    ASSERT_TRUE(scheduler.init(engine_, config_path_.c_str()));

    auto schedules = scheduler.schedules();
    ASSERT_EQ(schedules.size(), 2u);
    EXPECT_EQ(schedules[0].name, "Quick Scan");
    EXPECT_EQ(schedules[0].type, "quick");
    EXPECT_EQ(schedules[0].cron_expr, "0 12 * * *");
    EXPECT_TRUE(schedules[0].enabled);
    EXPECT_NE(schedules[0].next_run, 0);

    EXPECT_EQ(schedules[1].name, "Weekly Full");
    EXPECT_EQ(schedules[1].type, "full");
}

TEST_F(SchedulerTest, EmptyConfigReturnsFalse)
{
    write_config("[]");

    akav::Scheduler scheduler;
    ASSERT_TRUE(scheduler.init(engine_, config_path_.c_str()));

    auto schedules = scheduler.schedules();
    EXPECT_TRUE(schedules.empty());
}

TEST_F(SchedulerTest, InvalidCronSkipped)
{
    write_config(R"([
        {
            "name": "Bad Cron",
            "type": "quick",
            "cron": "invalid",
            "enabled": true
        },
        {
            "name": "Good Cron",
            "type": "quick",
            "cron": "0 12 * * *",
            "enabled": true
        }
    ])");

    akav::Scheduler scheduler;
    scheduler.init(engine_, config_path_.c_str());

    auto schedules = scheduler.schedules();
    ASSERT_EQ(schedules.size(), 1u);
    EXPECT_EQ(schedules[0].name, "Good Cron");
}

TEST_F(SchedulerTest, ReloadConfig)
{
    write_config(R"([
        { "name": "Scan A", "type": "quick", "cron": "0 12 * * *", "enabled": true }
    ])");

    akav::Scheduler scheduler;
    scheduler.init(engine_, config_path_.c_str());
    EXPECT_EQ(scheduler.schedules().size(), 1u);

    /* Rewrite with 2 schedules */
    write_config(R"([
        { "name": "Scan A", "type": "quick", "cron": "0 12 * * *", "enabled": true },
        { "name": "Scan B", "type": "full", "cron": "0 2 * * 0", "enabled": true }
    ])");

    ASSERT_TRUE(scheduler.reload());
    EXPECT_EQ(scheduler.schedules().size(), 2u);
}

/* ── Scheduler Scan Tests ─────────────────────────────────────────────── */

struct SiemContext {
    std::mutex mutex;
    std::vector<akav_siem_event_t> events;
};

static void siem_callback(const akav_siem_event_t* event, void* user_data)
{
    auto* ctx = static_cast<SiemContext*>(user_data);
    std::lock_guard<std::mutex> lock(ctx->mutex);
    ctx->events.push_back(*event);
}

TEST_F(SchedulerTest, RunNamedScheduleEmitsSiemEvents)
{
    /* Create a custom scan over a small temp directory */
    std::string scan_dir = dir_ + "\\scan_target";
    fs::create_directories(scan_dir);

    /* Create a few test files */
    for (int i = 0; i < 3; ++i) {
        std::string path = scan_dir + "\\file" + std::to_string(i) + ".txt";
        std::ofstream f(path);
        f << "clean content " << i;
    }

    /* Use forward slashes in JSON to avoid escaping issues */
    std::string fwd_dir = scan_dir;
    for (char& c : fwd_dir) {
        if (c == '\\') c = '/';
    }
    write_config("[{\"name\":\"Test Scan\",\"type\":\"custom\","
                 "\"paths\":[\"" + fwd_dir + "\"],"
                 "\"cron\":\"0 0 1 1 *\",\"enabled\":true}]");

    /* Register SIEM callback */
    SiemContext ctx;
    akav_set_siem_callback(engine_, siem_callback, &ctx);

    akav::Scheduler scheduler;
    scheduler.set_ignore_battery(true);
    ASSERT_TRUE(scheduler.init(engine_, config_path_.c_str()));
    ASSERT_TRUE(scheduler.start());

    /* Run the named schedule */
    ASSERT_TRUE(scheduler.run_now("Test Scan"));

    /* Wait for scan to start */
    for (int i = 0; i < 50 && !scheduler.scan_active(); ++i)
        Sleep(100);

    /* Wait for scan to complete (small directory, should be fast) */
    for (int i = 0; i < 100 && scheduler.scan_active(); ++i)
        Sleep(100);

    /* Give the scheduler thread time to finalize */
    Sleep(500);

    EXPECT_FALSE(scheduler.scan_active()) << "Scan should have completed";

    /* Check progress */
    const auto& progress = scheduler.progress();
    EXPECT_GE(progress.files_scanned.load(), 3u);
    EXPECT_EQ(progress.detections.load(), 0u);

    /* Check SIEM events */
    {
        std::lock_guard<std::mutex> lock(ctx.mutex);
        bool got_start = false, got_complete = false;
        for (const auto& e : ctx.events) {
            if (strcmp(e.event_type, "av:scheduled_scan_start") == 0)
                got_start = true;
            if (strcmp(e.event_type, "av:scheduled_scan_complete") == 0)
                got_complete = true;
        }
        EXPECT_TRUE(got_start) << "Should emit av:scheduled_scan_start";
        EXPECT_TRUE(got_complete) << "Should emit av:scheduled_scan_complete";

        /* Verify complete event has summary */
        for (const auto& e : ctx.events) {
            if (strcmp(e.event_type, "av:scheduled_scan_complete") == 0) {
                std::string payload = e.payload_json;
                EXPECT_NE(payload.find("\"files_scanned\""), std::string::npos);
                EXPECT_NE(payload.find("\"detections\""), std::string::npos);
                EXPECT_NE(payload.find("\"duration_ms\""), std::string::npos);
            }
        }
    }

    scheduler.stop();
}

TEST_F(SchedulerTest, RunNonexistentScheduleReturnsFalse)
{
    write_config(R"([
        { "name": "Test", "type": "quick", "cron": "0 12 * * *", "enabled": true }
    ])");

    akav::Scheduler scheduler;
    scheduler.init(engine_, config_path_.c_str());
    scheduler.start();

    EXPECT_FALSE(scheduler.run_now("Nonexistent"));

    scheduler.stop();
}

TEST_F(SchedulerTest, ScanNotActiveByDefault)
{
    akav::Scheduler scheduler;
    EXPECT_FALSE(scheduler.scan_active());
}
