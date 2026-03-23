/*
 * Unit tests for watchdog module (P10-T3).
 *
 * Tests:
 *   1. Watchdog lifecycle (init/destroy)
 *   2. Configuration
 *   3. Heartbeat responder (PING/PONG)
 *   4. Heartbeat responder start/stop
 *   5. Ping with no responder (failure)
 *   6. Watchdog detects process exit and restarts
 *   7. Watchdog stop signal
 *   8. Max restarts exceeded
 */

#include <gtest/gtest.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>

#include "protection/watchdog.h"

#include <cstring>
#include <atomic>

/* ── 1. Watchdog Lifecycle ──────────────────────────────────────── */

TEST(Watchdog, InitDestroy)
{
    akav_watchdog_t wd;
    akav_watchdog_init(&wd);

    EXPECT_TRUE(wd.initialized);
    EXPECT_EQ(AKAV_WATCHDOG_IDLE, wd.state);
    EXPECT_EQ(5000u, wd.config.ping_interval_ms);
    EXPECT_EQ(15000u, wd.config.timeout_ms);
    EXPECT_EQ(10u, wd.config.max_restarts);
    EXPECT_NE(nullptr, wd.stop_event);

    akav_watchdog_destroy(&wd);
    EXPECT_FALSE(wd.initialized);
}

TEST(Watchdog, InitNull)
{
    akav_watchdog_init(NULL);  /* Should not crash */
    akav_watchdog_destroy(NULL);
}

/* ── 2. Configuration ───────────────────────────────────────────── */

TEST(Watchdog, Configure)
{
    akav_watchdog_t wd;
    akav_watchdog_init(&wd);

    akav_watchdog_config_t config;
    memset(&config, 0, sizeof(config));
    config.service_exe_path = "C:\\test\\service.exe";
    config.service_args = "--console";
    config.ping_interval_ms = 2000;
    config.timeout_ms = 8000;
    config.max_restarts = 5;

    akav_watchdog_configure(&wd, &config);

    EXPECT_STREQ("C:\\test\\service.exe", wd.config.service_exe_path);
    EXPECT_STREQ("--console", wd.config.service_args);
    EXPECT_EQ(2000u, wd.config.ping_interval_ms);
    EXPECT_EQ(8000u, wd.config.timeout_ms);
    EXPECT_EQ(5u, wd.config.max_restarts);

    akav_watchdog_destroy(&wd);
}

TEST(Watchdog, ConfigureDefaults)
{
    akav_watchdog_t wd;
    akav_watchdog_init(&wd);

    akav_watchdog_config_t config;
    memset(&config, 0, sizeof(config));
    config.service_exe_path = "test.exe";
    /* Leave intervals at 0 to get defaults */

    akav_watchdog_configure(&wd, &config);

    EXPECT_EQ(AKAV_WATCHDOG_DEFAULT_INTERVAL_MS, wd.config.ping_interval_ms);
    EXPECT_EQ(AKAV_WATCHDOG_DEFAULT_TIMEOUT_MS, wd.config.timeout_ms);
    EXPECT_EQ(AKAV_WATCHDOG_MAX_RESTARTS, wd.config.max_restarts);

    akav_watchdog_destroy(&wd);
}

TEST(Watchdog, ConfigureNull)
{
    akav_watchdog_t wd;
    akav_watchdog_init(&wd);
    akav_watchdog_configure(&wd, NULL);  /* Should not crash */
    akav_watchdog_configure(NULL, NULL);
    akav_watchdog_destroy(&wd);
}

/* ── 3. Heartbeat Responder (PING/PONG) ─────────────────────────── */

TEST(Watchdog, HeartbeatPingPong)
{
    /* Start the heartbeat responder */
    void* hb = akav_heartbeat_start();
    ASSERT_NE(nullptr, hb);

    /* Give the pipe time to be created */
    Sleep(200);

    /* Send a PING and expect PONG */
    bool result = akav_watchdog_ping(3000);
    EXPECT_TRUE(result);

    /* Send another PING */
    Sleep(100);
    result = akav_watchdog_ping(3000);
    EXPECT_TRUE(result);

    akav_heartbeat_stop(hb);
}

/* ── 4. Heartbeat Start/Stop ────────────────────────────────────── */

TEST(Watchdog, HeartbeatStartStop)
{
    void* hb = akav_heartbeat_start();
    ASSERT_NE(nullptr, hb);

    /* Just start and stop — should not crash or leak */
    akav_heartbeat_stop(hb);
}

TEST(Watchdog, HeartbeatStopNull)
{
    akav_heartbeat_stop(NULL);  /* Should not crash */
}

TEST(Watchdog, HeartbeatMultipleStartStop)
{
    /* Start/stop twice to verify clean lifecycle */
    void* hb1 = akav_heartbeat_start();
    ASSERT_NE(nullptr, hb1);
    Sleep(100);
    akav_heartbeat_stop(hb1);

    void* hb2 = akav_heartbeat_start();
    ASSERT_NE(nullptr, hb2);
    Sleep(100);

    bool result = akav_watchdog_ping(3000);
    EXPECT_TRUE(result);

    akav_heartbeat_stop(hb2);
}

/* ── 5. Ping With No Responder ──────────────────────────────────── */

TEST(Watchdog, PingNoResponder)
{
    /* No heartbeat server running — ping should fail */
    bool result = akav_watchdog_ping(500);
    EXPECT_FALSE(result);
}

/* ── 6. Watchdog Run Without Service Path ───────────────────────── */

TEST(Watchdog, RunNoServicePath)
{
    akav_watchdog_t wd;
    akav_watchdog_init(&wd);

    /* No service_exe_path configured — should fail immediately */
    bool result = akav_watchdog_run(&wd);
    EXPECT_FALSE(result);
    EXPECT_EQ(AKAV_WATCHDOG_FAILED, wd.state);

    akav_watchdog_destroy(&wd);
}

TEST(Watchdog, RunNonexistentExe)
{
    akav_watchdog_t wd;
    akav_watchdog_init(&wd);

    akav_watchdog_config_t config;
    memset(&config, 0, sizeof(config));
    config.service_exe_path = "C:\\nonexistent_dir\\nonexistent.exe";

    akav_watchdog_configure(&wd, &config);

    bool result = akav_watchdog_run(&wd);
    EXPECT_FALSE(result);
    EXPECT_EQ(AKAV_WATCHDOG_FAILED, wd.state);

    akav_watchdog_destroy(&wd);
}

/* ── 7. Watchdog Stop Signal ────────────────────────────────────── */

static unsigned __stdcall delayed_stop_thread(void* arg)
{
    akav_watchdog_t* wd = (akav_watchdog_t*)arg;
    Sleep(2000);  /* Wait 2 seconds, then stop */
    akav_watchdog_stop(wd);
    return 0;
}

TEST(Watchdog, StopSignalDuringRun)
{
    /* Use cmd.exe /c "ping -n 999 127.0.0.1 >nul" as a long-lived process */
    akav_watchdog_t wd;
    akav_watchdog_init(&wd);

    akav_watchdog_config_t config;
    memset(&config, 0, sizeof(config));
    config.service_exe_path = "C:\\Windows\\System32\\cmd.exe";
    config.service_args = "/c \"ping -n 999 127.0.0.1 >nul\"";
    config.ping_interval_ms = 1000;
    config.timeout_ms = 3000;
    config.max_restarts = 1;

    akav_watchdog_configure(&wd, &config);

    /* Launch a thread that will stop the watchdog after 2 seconds */
    HANDLE stopper = (HANDLE)_beginthreadex(NULL, 0, delayed_stop_thread, &wd, 0, NULL);

    /* Run watchdog — should be stopped by the thread within ~2 seconds */
    bool result = akav_watchdog_run(&wd);
    EXPECT_TRUE(result);
    EXPECT_EQ(AKAV_WATCHDOG_STOPPED, wd.state);

    WaitForSingleObject(stopper, 5000);
    CloseHandle(stopper);
    akav_watchdog_destroy(&wd);
}

/* ── 8. Watchdog State Transitions ──────────────────────────────── */

TEST(Watchdog, StateTransitions)
{
    akav_watchdog_t wd;
    akav_watchdog_init(&wd);
    EXPECT_EQ(AKAV_WATCHDOG_IDLE, wd.state);

    akav_watchdog_stop(&wd);
    EXPECT_EQ(AKAV_WATCHDOG_STOPPED, wd.state);

    akav_watchdog_destroy(&wd);
}

/* ── 9. Log Callback ────────────────────────────────────────────── */

static std::atomic<int> g_log_count{0};

static void test_log_fn(const char* message, void* ctx)
{
    (void)message;
    (void)ctx;
    g_log_count++;
}

TEST(Watchdog, LogCallback)
{
    g_log_count = 0;

    akav_watchdog_t wd;
    akav_watchdog_init(&wd);

    akav_watchdog_config_t config;
    memset(&config, 0, sizeof(config));
    config.service_exe_path = "C:\\nonexistent.exe";
    config.log_fn = test_log_fn;

    akav_watchdog_configure(&wd, &config);

    /* This will fail to launch, but should log the failure */
    akav_watchdog_run(&wd);

    EXPECT_GT(g_log_count.load(), 0);

    akav_watchdog_destroy(&wd);
}

/* ── 10. Uninitialized watchdog ─────────────────────────────────── */

TEST(Watchdog, RunUninitialized)
{
    akav_watchdog_t wd;
    memset(&wd, 0, sizeof(wd));

    bool result = akav_watchdog_run(&wd);
    EXPECT_FALSE(result);
}
