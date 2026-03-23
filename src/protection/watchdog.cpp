/*
 * AkesoAV - Watchdog Process (P10-T3)
 *
 * Monitors the AkesoAV service via named pipe PING/PONG heartbeat.
 * Automatically restarts the service on crash or hang.
 *
 * Per §5.11:
 *   - Named pipe PING/PONG heartbeat (5s interval, 15s timeout)
 *   - Auto-restart via CreateProcess on crash or hang
 *   - Separate watchdog.exe process
 *   - Log all events
 */

#include "watchdog.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Logging helper ─────────────────────────────────────────────── */

static void wd_log(const akav_watchdog_t* wd, const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);

    /* Timestamp prefix */
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_s(&tm_buf, &now);
    int off = (int)strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S] ", &tm_buf);

    vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, ap);
    va_end(ap);

    if (wd && wd->config.log_fn) {
        wd->config.log_fn(buf, wd->config.log_ctx);
    }
    /* Always print to stderr as well */
    fprintf(stderr, "%s\n", buf);
}

/* ── Process management ─────────────────────────────────────────── */

static bool launch_service(akav_watchdog_t* wd)
{
    if (!wd->config.service_exe_path)
        return false;

    /* Build command line */
    char cmdline[1024];
    if (wd->config.service_args) {
        snprintf(cmdline, sizeof(cmdline), "\"%s\" %s",
                 wd->config.service_exe_path, wd->config.service_args);
    } else {
        snprintf(cmdline, sizeof(cmdline), "\"%s\"",
                 wd->config.service_exe_path);
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessA(
        NULL,       /* Use command line */
        cmdline,
        NULL,       /* Process security */
        NULL,       /* Thread security */
        FALSE,      /* Inherit handles */
        0,          /* Creation flags */
        NULL,       /* Environment */
        NULL,       /* Working directory */
        &si, &pi);

    if (!ok) {
        wd_log(wd, "WATCHDOG: Failed to launch service: error %lu", GetLastError());
        return false;
    }

    /* We don't need the thread handle */
    CloseHandle(pi.hThread);

    wd->process_handle = pi.hProcess;
    wd_log(wd, "WATCHDOG: Service launched (PID %lu)", pi.dwProcessId);
    return true;
}

static void terminate_service(akav_watchdog_t* wd)
{
    if (wd->process_handle) {
        TerminateProcess((HANDLE)wd->process_handle, 1);
        WaitForSingleObject((HANDLE)wd->process_handle, 5000);
        CloseHandle((HANDLE)wd->process_handle);
        wd->process_handle = NULL;
    }
}

static bool is_process_alive(akav_watchdog_t* wd)
{
    if (!wd->process_handle)
        return false;
    DWORD exitCode = 0;
    if (!GetExitCodeProcess((HANDLE)wd->process_handle, &exitCode))
        return false;
    return (exitCode == STILL_ACTIVE);
}

/* ── Heartbeat (PING/PONG) ──────────────────────────────────────── */

static bool send_ping(uint32_t timeout_ms)
{
    if (timeout_ms == 0) timeout_ms = 3000;

    /* Connect to the service's heartbeat pipe */
    if (!WaitNamedPipeA(AKAV_WATCHDOG_PIPE_NAME, timeout_ms))
        return false;

    HANDLE pipe = CreateFileA(
        AKAV_WATCHDOG_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, NULL);

    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    /* Send PING (synchronous write is fine for 4 bytes) */
    OVERLAPPED ov_w;
    memset(&ov_w, 0, sizeof(ov_w));
    ov_w.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    DWORD written = 0;

    WriteFile(pipe, AKAV_WATCHDOG_PING, 4, NULL, &ov_w);
    DWORD wait = WaitForSingleObject(ov_w.hEvent, timeout_ms);
    if (wait != WAIT_OBJECT_0 || !GetOverlappedResult(pipe, &ov_w, &written, FALSE) || written != 4) {
        CancelIo(pipe);
        CloseHandle(ov_w.hEvent);
        CloseHandle(pipe);
        return false;
    }
    CloseHandle(ov_w.hEvent);

    /* Read PONG with timeout using overlapped I/O */
    char response[16] = {0};
    DWORD bytes_read = 0;
    OVERLAPPED ov_r;
    memset(&ov_r, 0, sizeof(ov_r));
    ov_r.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    ReadFile(pipe, response, sizeof(response) - 1, NULL, &ov_r);
    wait = WaitForSingleObject(ov_r.hEvent, timeout_ms);

    bool ok = false;
    if (wait == WAIT_OBJECT_0 &&
        GetOverlappedResult(pipe, &ov_r, &bytes_read, FALSE) &&
        bytes_read >= 4) {
        ok = (memcmp(response, AKAV_WATCHDOG_PONG, 4) == 0);
    } else {
        CancelIo(pipe);
    }

    CloseHandle(ov_r.hEvent);
    CloseHandle(pipe);
    return ok;
}

/* ── Watchdog API ───────────────────────────────────────────────── */

void akav_watchdog_init(akav_watchdog_t* wd)
{
    if (!wd) return;
    memset(wd, 0, sizeof(*wd));
    wd->config.ping_interval_ms = AKAV_WATCHDOG_DEFAULT_INTERVAL_MS;
    wd->config.timeout_ms = AKAV_WATCHDOG_DEFAULT_TIMEOUT_MS;
    wd->config.max_restarts = AKAV_WATCHDOG_MAX_RESTARTS;
    wd->state = AKAV_WATCHDOG_IDLE;
    wd->stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    wd->initialized = true;
}

void akav_watchdog_configure(akav_watchdog_t* wd,
                              const akav_watchdog_config_t* config)
{
    if (!wd || !config) return;
    wd->config = *config;
    if (wd->config.ping_interval_ms == 0)
        wd->config.ping_interval_ms = AKAV_WATCHDOG_DEFAULT_INTERVAL_MS;
    if (wd->config.timeout_ms == 0)
        wd->config.timeout_ms = AKAV_WATCHDOG_DEFAULT_TIMEOUT_MS;
    if (wd->config.max_restarts == 0)
        wd->config.max_restarts = AKAV_WATCHDOG_MAX_RESTARTS;
}

bool akav_watchdog_run(akav_watchdog_t* wd)
{
    if (!wd || !wd->initialized || !wd->config.service_exe_path) {
        if (wd) wd->state = AKAV_WATCHDOG_FAILED;
        return false;
    }

    wd->state = AKAV_WATCHDOG_RUNNING;
    wd->restart_count = 0;

    /* Launch the service */
    if (!launch_service(wd)) {
        wd->state = AKAV_WATCHDOG_FAILED;
        return false;
    }

    wd_log(wd, "WATCHDOG: Monitoring started (interval=%ums, timeout=%ums)",
           wd->config.ping_interval_ms, wd->config.timeout_ms);

    /* Give the service time to start up and create the pipe */
    DWORD startup_grace_ms = 3000;
    WaitForSingleObject((HANDLE)wd->stop_event, startup_grace_ms);

    uint32_t consecutive_failures = 0;
    uint32_t max_failures = wd->config.timeout_ms / wd->config.ping_interval_ms;
    if (max_failures < 1) max_failures = 1;

    while (wd->state == AKAV_WATCHDOG_RUNNING) {
        /* Check for stop signal */
        if (WaitForSingleObject((HANDLE)wd->stop_event, 0) == WAIT_OBJECT_0)
            break;

        /* Check if process is still alive */
        if (!is_process_alive(wd)) {
            wd_log(wd, "WATCHDOG: Service process exited unexpectedly");
            goto restart;
        }

        /* Send heartbeat */
        if (send_ping(wd->config.ping_interval_ms)) {
            consecutive_failures = 0;
            /* Reset restart counter on successful heartbeat */
            wd->restart_count = 0;
        } else {
            consecutive_failures++;
            wd_log(wd, "WATCHDOG: Heartbeat failed (%u/%u)",
                   consecutive_failures, max_failures);

            if (consecutive_failures >= max_failures) {
                wd_log(wd, "WATCHDOG: Service appears hung (no response for %ums)",
                       consecutive_failures * wd->config.ping_interval_ms);
                goto restart;
            }
        }

        /* Wait for next ping interval (or stop signal) */
        if (WaitForSingleObject((HANDLE)wd->stop_event,
                                 wd->config.ping_interval_ms) == WAIT_OBJECT_0)
            break;

        continue;

restart:
        wd->restart_count++;
        wd->total_restarts++;

        if (wd->restart_count > wd->config.max_restarts) {
            wd_log(wd, "WATCHDOG: Max restarts (%u) exceeded, giving up",
                   wd->config.max_restarts);
            wd->state = AKAV_WATCHDOG_FAILED;
            return false;
        }

        wd_log(wd, "WATCHDOG: Restarting service (attempt %u/%u)",
               wd->restart_count, wd->config.max_restarts);

        wd->state = AKAV_WATCHDOG_RESTARTING;
        terminate_service(wd);
        consecutive_failures = 0;

        /* Brief delay before restart */
        Sleep(1000);

        if (!launch_service(wd)) {
            wd_log(wd, "WATCHDOG: Failed to restart service");
            wd->state = AKAV_WATCHDOG_FAILED;
            return false;
        }

        wd->state = AKAV_WATCHDOG_RUNNING;

        /* Grace period for restart */
        WaitForSingleObject((HANDLE)wd->stop_event, startup_grace_ms);
    }

    /* Clean shutdown */
    wd_log(wd, "WATCHDOG: Shutting down");
    terminate_service(wd);
    wd->state = AKAV_WATCHDOG_STOPPED;
    return true;
}

void akav_watchdog_stop(akav_watchdog_t* wd)
{
    if (!wd || !wd->initialized) return;
    wd->state = AKAV_WATCHDOG_STOPPED;
    if (wd->stop_event)
        SetEvent((HANDLE)wd->stop_event);
}

void akav_watchdog_destroy(akav_watchdog_t* wd)
{
    if (!wd) return;
    terminate_service(wd);
    if (wd->stop_event) {
        CloseHandle((HANDLE)wd->stop_event);
        wd->stop_event = NULL;
    }
    wd->initialized = false;
}

/* ── Service-side heartbeat responder ───────────────────────────── */

typedef struct {
    HANDLE stop_event;
    HANDLE pipe;
} heartbeat_ctx_t;

static unsigned __stdcall heartbeat_thread(void* arg)
{
    heartbeat_ctx_t* ctx = (heartbeat_ctx_t*)arg;

    while (WaitForSingleObject(ctx->stop_event, 0) != WAIT_OBJECT_0) {
        /* Create pipe instance */
        HANDLE pipe = CreateNamedPipeA(
            AKAV_WATCHDOG_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,      /* Max instances */
            256,    /* Out buffer */
            256,    /* In buffer */
            5000,   /* Default timeout */
            NULL);

        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        ctx->pipe = pipe;

        /* Wait for client (watchdog) to connect */
        BOOL connected = ConnectNamedPipe(pipe, NULL) ||
                         (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected) {
            CloseHandle(pipe);
            ctx->pipe = NULL;
            continue;
        }

        /* Read PING */
        char buf[16] = {0};
        DWORD bytes_read = 0;
        BOOL read_ok = ReadFile(pipe, buf, sizeof(buf) - 1, &bytes_read, NULL);

        if (read_ok && bytes_read >= 4 &&
            memcmp(buf, AKAV_WATCHDOG_PING, 4) == 0) {
            /* Send PONG */
            DWORD written = 0;
            WriteFile(pipe, AKAV_WATCHDOG_PONG, 4, &written, NULL);
            FlushFileBuffers(pipe);
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        ctx->pipe = NULL;
    }

    return 0;
}

void* akav_heartbeat_start(void)
{
    heartbeat_ctx_t* ctx = (heartbeat_ctx_t*)calloc(1, sizeof(heartbeat_ctx_t));
    if (!ctx) return NULL;

    ctx->stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ctx->stop_event) {
        free(ctx);
        return NULL;
    }

    HANDLE thread = (HANDLE)_beginthreadex(NULL, 0, heartbeat_thread, ctx, 0, NULL);
    if (!thread) {
        CloseHandle(ctx->stop_event);
        free(ctx);
        return NULL;
    }

    /* Store the thread handle in the context so we can retrieve it */
    /* We return the context pointer as the "handle" */
    /* Stash thread handle after stop_event by casting */
    /* Use a simple struct wrapper approach */

    /* We'll pack both into an allocated block:
     * [heartbeat_ctx_t][HANDLE thread] */
    /* Actually, just use two separate allocations tracked via a wrapper */

    /* Simpler: return a two-HANDLE array [thread, stop_event] packed
     * into a small struct. But the API returns void*. Let's just
     * extend heartbeat_ctx_t to include the thread handle. */

    /* Reuse: ctx already allocated, just add thread handle after it.
     * Actually we can't change the struct mid-function. Let's create
     * a wrapper struct. */

    typedef struct {
        HANDLE thread;
        heartbeat_ctx_t* ctx;
    } heartbeat_handle_t;

    heartbeat_handle_t* h = (heartbeat_handle_t*)calloc(1, sizeof(heartbeat_handle_t));
    if (!h) {
        SetEvent(ctx->stop_event);
        WaitForSingleObject(thread, 3000);
        CloseHandle(thread);
        CloseHandle(ctx->stop_event);
        free(ctx);
        return NULL;
    }
    h->thread = thread;
    h->ctx = ctx;
    return h;
}

void akav_heartbeat_stop(void* handle)
{
    if (!handle) return;

    typedef struct {
        HANDLE thread;
        heartbeat_ctx_t* ctx;
    } heartbeat_handle_t;

    heartbeat_handle_t* h = (heartbeat_handle_t*)handle;

    /* Signal stop */
    SetEvent(h->ctx->stop_event);

    /* Cancel any pending ConnectNamedPipe by connecting to the pipe ourselves */
    HANDLE dummy = CreateFileA(AKAV_WATCHDOG_PIPE_NAME,
                                GENERIC_READ | GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING, 0, NULL);
    if (dummy != INVALID_HANDLE_VALUE)
        CloseHandle(dummy);

    /* Wait for thread to finish */
    WaitForSingleObject(h->thread, 5000);
    CloseHandle(h->thread);

    /* Close pipe if still open */
    if (h->ctx->pipe) {
        DisconnectNamedPipe(h->ctx->pipe);
        CloseHandle(h->ctx->pipe);
    }

    CloseHandle(h->ctx->stop_event);
    free(h->ctx);
    free(h);
}

/* ── Utility: single PING/PONG ──────────────────────────────────── */

bool akav_watchdog_ping(uint32_t timeout_ms)
{
    (void)timeout_ms;
    return send_ping(timeout_ms);
}
