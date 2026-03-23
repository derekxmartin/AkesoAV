/*
 * watchdog_main.cpp - AkesoAV Watchdog Process entry point (P10-T3)
 *
 * Usage:
 *   akesoav-watchdog.exe <service_exe_path> [--console] [--interval <ms>]
 *                        [--timeout <ms>] [--max-restarts <n>]
 *
 * Monitors the AkesoAV service via named pipe heartbeat.
 * Can run as a standalone process or be registered as a secondary service.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "protection/watchdog.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

/* ── Globals ────────────────────────────────────────────────────── */

static akav_watchdog_t g_watchdog;

/* ── Log callback: write to stderr and optionally a log file ────── */

static FILE* g_log_file = NULL;

static void log_callback(const char* message, void* ctx)
{
    (void)ctx;
    if (g_log_file) {
        fprintf(g_log_file, "%s\n", message);
        fflush(g_log_file);
    }
}

/* ── Console Ctrl handler (Ctrl+C) ─────────────────────────────── */

static BOOL WINAPI console_handler(DWORD ctrl)
{
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT ||
        ctrl == CTRL_CLOSE_EVENT) {
        akav_watchdog_stop(&g_watchdog);
        return TRUE;
    }
    return FALSE;
}

/* ── Usage ──────────────────────────────────────────────────────── */

static void usage(const char* prog)
{
    fprintf(stderr,
        "AkesoAV Watchdog - Service health monitor\n\n"
        "Usage: %s <service_exe_path> [options]\n\n"
        "Options:\n"
        "  --console         Run in console mode (default)\n"
        "  --interval <ms>   Heartbeat interval (default: 5000)\n"
        "  --timeout <ms>    Timeout before restart (default: 15000)\n"
        "  --max-restarts <n> Max consecutive restarts (default: 10)\n"
        "  --log <file>      Write events to log file\n"
        "  --args <args>     Arguments to pass to service exe\n",
        prog);
}

/* ── Main ───────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    const char* service_path = argv[1];
    const char* service_args = NULL;
    const char* log_path = NULL;
    uint32_t interval = 0;
    uint32_t timeout = 0;
    uint32_t max_restarts = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            interval = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-restarts") == 0 && i + 1 < argc) {
            max_restarts = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "--args") == 0 && i + 1 < argc) {
            service_args = argv[++i];
        } else if (strcmp(argv[i], "--console") == 0) {
            /* Default mode, no-op */
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    /* Open log file if requested */
    if (log_path) {
        fopen_s(&g_log_file, log_path, "a");
        if (!g_log_file) {
            fprintf(stderr, "Warning: could not open log file: %s\n", log_path);
        }
    }

    /* Set up console handler */
    SetConsoleCtrlHandler(console_handler, TRUE);

    /* Initialize and configure watchdog */
    akav_watchdog_init(&g_watchdog);

    akav_watchdog_config_t config;
    memset(&config, 0, sizeof(config));
    config.service_exe_path = service_path;
    config.service_args = service_args;
    config.ping_interval_ms = interval;
    config.timeout_ms = timeout;
    config.max_restarts = max_restarts;
    config.log_fn = log_callback;
    config.log_ctx = NULL;

    akav_watchdog_configure(&g_watchdog, &config);

    fprintf(stderr, "AkesoAV Watchdog starting\n");
    fprintf(stderr, "  Service: %s\n", service_path);
    fprintf(stderr, "  Interval: %ums\n", g_watchdog.config.ping_interval_ms);
    fprintf(stderr, "  Timeout: %ums\n", g_watchdog.config.timeout_ms);
    fprintf(stderr, "  Max restarts: %u\n", g_watchdog.config.max_restarts);
    fprintf(stderr, "  Press Ctrl+C to stop\n\n");

    /* Run the watchdog (blocks until stopped or failed) */
    bool ok = akav_watchdog_run(&g_watchdog);

    akav_watchdog_destroy(&g_watchdog);

    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    return ok ? 0 : 1;
}
