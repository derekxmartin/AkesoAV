/* akesoav_service.cpp -- AkesoAV standalone Windows service.
 *
 * Implements P5-T3 + P5 bundling:
 *   - SCM registration (SERVICE_WIN32_OWN_PROCESS)
 *   - Named pipe server (\\.\pipe\AkesoAVScan)
 *   - Thread pool via _beginthreadex (one thread per client)
 *   - Full protocol per section 3.5:
 *       SCAN <path>, VERSION, RELOAD, STATS, PING, QUIT
 *       SCHEDULE LIST, SCHEDULE RUN <name>, SCHEDULE STATUS
 *   - Signature preload at startup
 *   - SIEM JSONL logging at startup (local forensic log)
 *   - Scheduled scanning via Scheduler (cron-based)
 *   - Graceful shutdown via SERVICE_CONTROL_STOP
 *
 * Can also run in console mode (--console) for testing.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>  /* _beginthreadex */

#include "akesoav.h"
#include "service/scheduler.h"
#include "protection/self_protect.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <atomic>
#include <chrono>
#include <string>

/* ── Constants ──────────────────────────────────────────────────── */

static const char SERVICE_NAME[]   = "AkesoAV";
static const char PIPE_NAME[]      = "\\\\.\\pipe\\AkesoAVScan";
static const DWORD PIPE_BUFSIZE    = 8192;
static const int   MAX_CLIENTS     = 16;

/* ── Global state ───────────────────────────────────────────────── */

static SERVICE_STATUS          g_svc_status{};
static SERVICE_STATUS_HANDLE   g_svc_status_handle = NULL;
static HANDLE                  g_stop_event = NULL;

static akav_engine_t*          g_engine = NULL;
static const char*             g_db_path = NULL;
static const char*             g_config_path = NULL;
static const char*             g_siem_jsonl_path = NULL;
static bool                    g_no_scheduler = false;

/* Stats (atomic for thread-safe access) */
static std::atomic<uint64_t>   g_files_scanned{0};
static std::atomic<uint64_t>   g_malware_found{0};
static std::chrono::steady_clock::time_point g_start_time;

/* Scheduler (service-owned, C++ object) */
static akav::Scheduler         g_scheduler;
static bool                    g_scheduler_running = false;

/* Self-protection integrity monitor */
static akav_integrity_monitor_t g_integrity_monitor;
static HANDLE                   g_integrity_thread = NULL;
static bool                     g_integrity_running = false;

/* ── Pipe protocol helpers ──────────────────────────────────────── */

static bool pipe_write(HANDLE pipe, const char* msg)
{
    DWORD len = (DWORD)strlen(msg);
    DWORD written = 0;
    return WriteFile(pipe, msg, len, &written, NULL) && written == len;
}

static bool pipe_read_line(HANDLE pipe, char* buf, DWORD buf_size)
{
    /* Read bytes until \r\n or buffer full.
     * Named pipe is in byte mode, so we read one byte at a time
     * to find the line boundary. */
    DWORD total = 0;
    while (total < buf_size - 1) {
        BYTE b = 0;
        DWORD read_count = 0;
        if (!ReadFile(pipe, &b, 1, &read_count, NULL) || read_count == 0)
            return total > 0;  /* Connection closed or error */

        if (b == '\n') {
            /* Strip trailing \r if present */
            if (total > 0 && buf[total - 1] == '\r')
                total--;
            buf[total] = '\0';
            return true;
        }
        buf[total++] = (char)b;
    }
    buf[total] = '\0';
    return true;
}

/* ── Command handlers ───────────────────────────────────────────── */

static void handle_scan(HANDLE pipe, const char* path)
{
    if (!path || !path[0]) {
        pipe_write(pipe, "500 Missing path argument\r\n");
        return;
    }

    if (!g_engine) {
        pipe_write(pipe, "500 Engine not initialized\r\n");
        return;
    }

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_scan_result_t result;
    akav_error_t err = akav_scan_file(g_engine, path, &opts, &result);

    if (err != AKAV_OK) {
        char errbuf[512];
        snprintf(errbuf, sizeof(errbuf), "500 Scan error: %s\r\n",
                 akav_strerror(err));
        pipe_write(pipe, errbuf);
        return;
    }

    g_files_scanned.fetch_add(1, std::memory_order_relaxed);

    pipe_write(pipe, "210 SCAN DATA\r\n");

    if (result.found) {
        g_malware_found.fetch_add(1, std::memory_order_relaxed);

        char line[1024];
        snprintf(line, sizeof(line), "%s\t%s\t%s\t%.1f\r\n",
                 path, result.malware_name, result.signature_id,
                 result.heuristic_score);
        pipe_write(pipe, line);
    }

    pipe_write(pipe, "200 SCAN OK\r\n");
}

static void handle_version(HANDLE pipe)
{
    const char* ver = akav_engine_version();
    const char* db_ver = g_engine ? akav_db_version(g_engine) : "none";

    char buf[256];
    snprintf(buf, sizeof(buf), "220 AkesoAV %s DB:%s\r\n", ver, db_ver);
    pipe_write(pipe, buf);
}

static void handle_reload(HANDLE pipe)
{
    if (!g_engine || !g_db_path) {
        pipe_write(pipe, "500 No engine or DB path configured\r\n");
        return;
    }

    akav_error_t err = akav_engine_load_signatures(g_engine, g_db_path);
    if (err != AKAV_OK) {
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "500 Reload failed: %s\r\n",
                 akav_strerror(err));
        pipe_write(pipe, errbuf);
        return;
    }

    /* Also reload scheduler config */
    if (g_scheduler_running) {
        g_scheduler.reload();
    }

    pipe_write(pipe, "220 RELOAD OK\r\n");
}

static void handle_stats(HANDLE pipe)
{
    uint64_t cache_hits = 0, cache_misses = 0, cache_entries = 0;
    if (g_engine) {
        akav_cache_stats(g_engine, &cache_hits, &cache_misses, &cache_entries);
    }

    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        now - g_start_time).count();

    char buf[1024];
    int offset = snprintf(buf, sizeof(buf), "220 %llu %llu %llu %lld",
             (unsigned long long)g_files_scanned.load(std::memory_order_relaxed),
             (unsigned long long)g_malware_found.load(std::memory_order_relaxed),
             (unsigned long long)cache_hits,
             (long long)uptime);

    /* Append scheduler status if active */
    if (g_scheduler_running) {
        const auto& prog = g_scheduler.progress();
        if (prog.active.load(std::memory_order_relaxed)) {
            offset += snprintf(buf + offset, sizeof(buf) - (size_t)offset,
                " SCHED_ACTIVE %llu %llu %llu",
                (unsigned long long)prog.files_scanned.load(std::memory_order_relaxed),
                (unsigned long long)prog.detections.load(std::memory_order_relaxed),
                (unsigned long long)prog.errors.load(std::memory_order_relaxed));
        } else {
            offset += snprintf(buf + offset, sizeof(buf) - (size_t)offset,
                " SCHED_IDLE");
        }
    }

    snprintf(buf + offset, sizeof(buf) - (size_t)offset, "\r\n");
    pipe_write(pipe, buf);
}

static void handle_ping(HANDLE pipe)
{
    pipe_write(pipe, "220 PONG\r\n");
}

/* ── Schedule command handlers ─────────────────────────────────── */

static void handle_schedule(HANDLE pipe, const char* subcmd)
{
    if (!g_scheduler_running) {
        pipe_write(pipe, "500 Scheduler not running\r\n");
        return;
    }

    if (!subcmd || !subcmd[0]) {
        pipe_write(pipe, "500 Usage: SCHEDULE LIST|RUN <name>|STATUS\r\n");
        return;
    }

    if (_stricmp(subcmd, "LIST") == 0) {
        auto entries = g_scheduler.schedules();
        char buf[512];
        snprintf(buf, sizeof(buf), "220 %zu schedules\r\n",
                 entries.size());
        pipe_write(pipe, buf);

        for (const auto& e : entries) {
            snprintf(buf, sizeof(buf), "  %s\t%s\t%s\t%s\r\n",
                     e.name.c_str(), e.type.c_str(), e.cron_expr.c_str(),
                     e.enabled ? "enabled" : "disabled");
            pipe_write(pipe, buf);
        }
        pipe_write(pipe, "200 OK\r\n");

    } else if (_stricmp(subcmd, "STATUS") == 0) {
        const auto& prog = g_scheduler.progress();
        char buf[512];
        if (prog.active.load(std::memory_order_relaxed)) {
            snprintf(buf, sizeof(buf),
                "220 ACTIVE schedule=%s type=%s files=%llu detections=%llu errors=%llu\r\n",
                prog.schedule_name.c_str(), prog.scan_type.c_str(),
                (unsigned long long)prog.files_scanned.load(std::memory_order_relaxed),
                (unsigned long long)prog.detections.load(std::memory_order_relaxed),
                (unsigned long long)prog.errors.load(std::memory_order_relaxed));
        } else {
            snprintf(buf, sizeof(buf), "220 IDLE\r\n");
        }
        pipe_write(pipe, buf);

    } else if (_strnicmp(subcmd, "RUN ", 4) == 0) {
        const char* name = subcmd + 4;
        if (!name[0]) {
            pipe_write(pipe, "500 Missing schedule name\r\n");
            return;
        }

        if (g_scheduler.run_now(name)) {
            char buf[256];
            snprintf(buf, sizeof(buf), "220 Scheduled run: %s\r\n", name);
            pipe_write(pipe, buf);
        } else {
            char buf[256];
            snprintf(buf, sizeof(buf), "500 Schedule not found: %s\r\n", name);
            pipe_write(pipe, buf);
        }

    } else {
        pipe_write(pipe, "500 Usage: SCHEDULE LIST|RUN <name>|STATUS\r\n");
    }
}

/* ── Client thread ──────────────────────────────────────────────── */

struct ClientContext {
    HANDLE pipe;
};

static unsigned __stdcall client_thread(void* arg)
{
    ClientContext* ctx = (ClientContext*)arg;
    HANDLE pipe = ctx->pipe;
    delete ctx;

    /* Send greeting */
    pipe_write(pipe, "220 AKESOAV READY\r\n");

    char line[PIPE_BUFSIZE];
    while (WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
        if (!pipe_read_line(pipe, line, sizeof(line)))
            break;  /* Client disconnected */

        if (line[0] == '\0')
            continue;  /* Empty line */

        /* Parse command */
        if (_strnicmp(line, "SCAN ", 5) == 0) {
            handle_scan(pipe, line + 5);
        } else if (_stricmp(line, "VERSION") == 0) {
            handle_version(pipe);
        } else if (_stricmp(line, "RELOAD") == 0) {
            handle_reload(pipe);
        } else if (_stricmp(line, "STATS") == 0) {
            handle_stats(pipe);
        } else if (_stricmp(line, "PING") == 0) {
            handle_ping(pipe);
        } else if (_strnicmp(line, "SCHEDULE ", 9) == 0) {
            handle_schedule(pipe, line + 9);
        } else if (_stricmp(line, "SCHEDULE") == 0) {
            handle_schedule(pipe, "");
        } else if (_stricmp(line, "QUIT") == 0) {
            break;  /* Close connection */
        } else {
            char errbuf[512];
            snprintf(errbuf, sizeof(errbuf),
                     "500 Unknown command: %s\r\n", line);
            pipe_write(pipe, errbuf);
        }
    }

    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

/* ── Pipe server loop ───────────────────────────────────────────── */

static void pipe_server_loop()
{
    while (WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
        /* Create a new pipe instance for the next client */
        HANDLE pipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            MAX_CLIENTS,
            PIPE_BUFSIZE,
            PIPE_BUFSIZE,
            0,
            NULL);

        if (pipe == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "[service] CreateNamedPipe failed: %lu\n",
                    GetLastError());
            Sleep(1000);
            continue;
        }

        /* Wait for a client to connect.
         * Use overlapped I/O so we can check the stop event. */
        OVERLAPPED ov{};
        ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        BOOL connected = ConnectNamedPipe(pipe, &ov);
        if (!connected) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                /* Wait for either client connection or stop event */
                HANDLE events[2] = { ov.hEvent, g_stop_event };
                DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);

                if (wait == WAIT_OBJECT_0 + 1) {
                    /* Stop event signaled */
                    CancelIo(pipe);
                    CloseHandle(ov.hEvent);
                    CloseHandle(pipe);
                    break;
                }
                /* Client connected — fall through */
            } else if (err == ERROR_PIPE_CONNECTED) {
                /* Client already connected before ConnectNamedPipe — OK */
            } else {
                fprintf(stderr, "[service] ConnectNamedPipe failed: %lu\n", err);
                CloseHandle(ov.hEvent);
                CloseHandle(pipe);
                continue;
            }
        }

        CloseHandle(ov.hEvent);

        /* Spawn a thread to handle this client */
        ClientContext* ctx = new ClientContext{ pipe };
        HANDLE thread = (HANDLE)_beginthreadex(
            NULL, 0, client_thread, ctx, 0, NULL);
        if (thread) {
            CloseHandle(thread);  /* Detach — thread cleans up pipe */
        } else {
            /* Thread creation failed — clean up */
            delete ctx;
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }
}

/* ── Integrity monitor thread ───────────────────────────────────── */

static unsigned __stdcall integrity_thread_fn(void* arg)
{
    (void)arg;
    DWORD interval_ms = g_integrity_monitor.check_interval_sec * 1000;

    while (g_integrity_running) {
        /* Sleep in small increments so we can exit promptly */
        for (DWORD elapsed = 0; elapsed < interval_ms && g_integrity_running; elapsed += 1000)
            Sleep(1000);

        if (!g_integrity_running)
            break;

        akav_integrity_result_t result = akav_integrity_monitor_check(&g_integrity_monitor);
        if (result.files_modified > 0 || result.files_missing > 0) {
            fprintf(stderr, "[SELF-PROTECT] INTEGRITY ALERT: %d modified, %d missing\n",
                    result.files_modified, result.files_missing);
            for (int i = 0; i < 4 && result.modified_paths[i][0]; i++) {
                fprintf(stderr, "[SELF-PROTECT]   -> %s\n", result.modified_paths[i]);
            }
        }
    }
    return 0;
}

/* ── Engine lifecycle ───────────────────────────────────────────── */

static bool engine_init()
{
    akav_error_t err = akav_engine_create(&g_engine);
    if (err != AKAV_OK) {
        fprintf(stderr, "[service] Engine create failed: %s\n",
                akav_strerror(err));
        return false;
    }

    err = akav_engine_init(g_engine, g_config_path);
    if (err != AKAV_OK) {
        fprintf(stderr, "[service] Engine init failed: %s\n",
                akav_strerror(err));
        akav_engine_destroy(g_engine);
        g_engine = NULL;
        return false;
    }

    /* Load signatures if DB path provided */
    if (g_db_path) {
        err = akav_engine_load_signatures(g_engine, g_db_path);
        if (err != AKAV_OK) {
            fprintf(stderr, "[service] Warning: signature load failed: %s\n",
                    akav_strerror(err));
            /* Continue without signatures -- EICAR/heuristics still work */
        }
    }

    /* Start SIEM JSONL logging (local forensic log) */
    err = akav_siem_start_jsonl(g_engine, g_siem_jsonl_path);
    if (err != AKAV_OK) {
        fprintf(stderr, "[service] Warning: SIEM JSONL init failed: %s\n",
                akav_strerror(err));
        /* Non-fatal: continue without local logging */
    } else {
        fprintf(stderr, "[service] SIEM JSONL logging started\n");
    }

    /* Start scheduler (unless disabled) */
    if (!g_no_scheduler) {
        if (g_scheduler.init(g_engine, g_config_path)) {
            if (g_scheduler.start()) {
                g_scheduler_running = true;
                fprintf(stderr, "[service] Scheduler started (%zu schedules)\n",
                        g_scheduler.schedules().size());
            } else {
                fprintf(stderr, "[service] Warning: scheduler start failed\n");
            }
        } else {
            fprintf(stderr, "[service] Warning: scheduler init failed "
                    "(no schedules.json or invalid config)\n");
        }
    }

    /* Start file integrity monitor — hash engine binaries */
    akav_integrity_monitor_init(&g_integrity_monitor, 60);
    {
        /* Get our own module path to determine the install directory */
        char exe_path[520] = {0};
        GetModuleFileNameA(NULL, exe_path, sizeof(exe_path) - 1);
        /* Strip filename to get directory */
        char* last_sep = strrchr(exe_path, '\\');
        if (last_sep) *last_sep = '\0';

        int added = akav_integrity_monitor_add_dir(&g_integrity_monitor, exe_path);
        fprintf(stderr, "[service] Integrity monitor: tracking %d files in %s\n",
                added, exe_path);
    }

    /* Launch integrity monitor thread */
    if (g_integrity_monitor.file_count > 0) {
        g_integrity_running = true;
        g_integrity_thread = (HANDLE)_beginthreadex(
            NULL, 0, integrity_thread_fn, NULL, 0, NULL);
    }

    return true;
}

static void engine_shutdown()
{
    /* Stop integrity monitor */
    if (g_integrity_running) {
        g_integrity_running = false;
        if (g_integrity_thread) {
            WaitForSingleObject(g_integrity_thread, 5000);
            CloseHandle(g_integrity_thread);
            g_integrity_thread = NULL;
        }
        akav_integrity_monitor_destroy(&g_integrity_monitor);
        fprintf(stderr, "[service] Integrity monitor stopped\n");
    }

    /* Stop scheduler first */
    if (g_scheduler_running) {
        g_scheduler.stop();
        g_scheduler_running = false;
        fprintf(stderr, "[service] Scheduler stopped\n");
    }

    /* Stop SIEM JSONL (flushes remaining events) */
    if (g_engine) {
        akav_siem_stop_jsonl(g_engine);
    }

    if (g_engine) {
        akav_engine_destroy(g_engine);
        g_engine = NULL;
    }
}

/* ── SCM service control handler ────────────────────────────────── */

static VOID WINAPI svc_ctrl_handler(DWORD control)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_svc_status.dwCurrentState = SERVICE_STOP_PENDING;
        g_svc_status.dwWaitHint = 10000;
        SetServiceStatus(g_svc_status_handle, &g_svc_status);
        SetEvent(g_stop_event);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        SetServiceStatus(g_svc_status_handle, &g_svc_status);
        break;

    default:
        break;
    }
}

/* ── SCM service main ───────────────────────────────────────────── */

static VOID WINAPI svc_main(DWORD argc, LPSTR* argv)
{
    (void)argc;
    (void)argv;

    g_svc_status_handle = RegisterServiceCtrlHandlerA(
        SERVICE_NAME, svc_ctrl_handler);
    if (!g_svc_status_handle)
        return;

    g_svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwCurrentState = SERVICE_START_PENDING;
    g_svc_status.dwControlsAccepted = 0;
    g_svc_status.dwWaitHint = 30000;
    SetServiceStatus(g_svc_status_handle, &g_svc_status);

    /* Harden process DACL — deny terminate/VM access from non-admin */
    if (akav_self_protect_harden_process()) {
        fprintf(stderr, "[service] Process DACL hardened\n");
    } else {
        fprintf(stderr, "[service] Warning: DACL hardening failed (error %lu)\n",
                GetLastError());
    }

    /* Create stop event */
    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_stop_event) {
        g_svc_status.dwCurrentState = SERVICE_STOPPED;
        g_svc_status.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_svc_status_handle, &g_svc_status);
        return;
    }

    /* Initialize engine */
    if (!engine_init()) {
        g_svc_status.dwCurrentState = SERVICE_STOPPED;
        g_svc_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_svc_status.dwServiceSpecificExitCode = 1;
        SetServiceStatus(g_svc_status_handle, &g_svc_status);
        CloseHandle(g_stop_event);
        return;
    }

    g_start_time = std::chrono::steady_clock::now();

    /* Service is now running */
    g_svc_status.dwCurrentState = SERVICE_RUNNING;
    g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svc_status.dwWaitHint = 0;
    SetServiceStatus(g_svc_status_handle, &g_svc_status);

    /* Run the pipe server (blocks until stop event) */
    pipe_server_loop();

    /* Clean shutdown */
    engine_shutdown();

    g_svc_status.dwCurrentState = SERVICE_STOPPED;
    g_svc_status.dwWin32ExitCode = 0;
    SetServiceStatus(g_svc_status_handle, &g_svc_status);
    CloseHandle(g_stop_event);
}

/* ── Console mode (for testing without SCM) ─────────────────────── */

static void run_console()
{
    printf("[service] Starting in console mode...\n");
    printf("[service] Pipe: %s\n", PIPE_NAME);

    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_stop_event) {
        fprintf(stderr, "[service] CreateEvent failed\n");
        return;
    }

    if (!engine_init()) {
        CloseHandle(g_stop_event);
        return;
    }

    g_start_time = std::chrono::steady_clock::now();

    printf("[service] Engine initialized. Listening for connections...\n");
    if (g_scheduler_running) {
        auto entries = g_scheduler.schedules();
        printf("[service] Scheduler active with %zu schedule(s)\n",
               entries.size());
    }
    printf("[service] Press Ctrl+C to stop.\n");

    /* Set console Ctrl+C handler */
    SetConsoleCtrlHandler([](DWORD type) -> BOOL {
        if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
            type == CTRL_CLOSE_EVENT) {
            printf("\n[service] Shutting down...\n");
            SetEvent(g_stop_event);
            return TRUE;
        }
        return FALSE;
    }, TRUE);

    pipe_server_loop();

    engine_shutdown();
    CloseHandle(g_stop_event);
    printf("[service] Stopped.\n");
}

/* ── Service install/uninstall helpers ──────────────────────────── */

static void install_service(const char* exe_path)
{
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fprintf(stderr, "OpenSCManager failed: %lu (run as admin)\n",
                GetLastError());
        return;
    }

    /* Build command line with --service flag */
    char cmd[MAX_PATH + 32];
    snprintf(cmd, sizeof(cmd), "\"%s\" --service", exe_path);

    SC_HANDLE svc = CreateServiceA(
        scm, SERVICE_NAME, "AkesoAV Scan Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        cmd,
        NULL, NULL, NULL, NULL, NULL);

    if (svc) {
        /* Set description */
        SERVICE_DESCRIPTIONA desc;
        desc.lpDescription = (LPSTR)"AkesoAV antivirus scan engine service";
        ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

        printf("Service '%s' installed successfully.\n", SERVICE_NAME);
        CloseServiceHandle(svc);
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            printf("Service '%s' already exists.\n", SERVICE_NAME);
        else
            fprintf(stderr, "CreateService failed: %lu\n", err);
    }

    CloseServiceHandle(scm);
}

static void uninstall_service()
{
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        fprintf(stderr, "OpenSCManager failed: %lu (run as admin)\n",
                GetLastError());
        return;
    }

    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, DELETE | SERVICE_STOP);
    if (svc) {
        SERVICE_STATUS status;
        ControlService(svc, SERVICE_CONTROL_STOP, &status);
        if (DeleteService(svc))
            printf("Service '%s' uninstalled.\n", SERVICE_NAME);
        else
            fprintf(stderr, "DeleteService failed: %lu\n", GetLastError());
        CloseServiceHandle(svc);
    } else {
        fprintf(stderr, "OpenService failed: %lu\n", GetLastError());
    }

    CloseServiceHandle(scm);
}

/* ── Usage ──────────────────────────────────────────────────────── */

static void print_usage(const char* prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  --console           Run in console mode (for testing)\n");
    printf("  --service           Run as Windows service (used by SCM)\n");
    printf("  --install           Install as Windows service\n");
    printf("  --uninstall         Uninstall Windows service\n");
    printf("  --db <path>         Path to .akavdb signature database\n");
    printf("  --config <path>     Path to config directory\n");
    printf("  --siem-jsonl <path> Path for SIEM JSONL log file\n");
    printf("  --no-scheduler      Disable scheduled scanning\n");
    printf("  -h, --help          Show this help\n");
}

/* ── Entry point ────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    bool console_mode = false;
    bool service_mode = false;
    bool do_install = false;
    bool do_uninstall = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--console") == 0) {
            console_mode = true;
        } else if (strcmp(argv[i], "--service") == 0) {
            service_mode = true;
        } else if (strcmp(argv[i], "--install") == 0) {
            do_install = true;
        } else if (strcmp(argv[i], "--uninstall") == 0) {
            do_uninstall = true;
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            g_db_path = argv[++i];
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            g_config_path = argv[++i];
        } else if (strcmp(argv[i], "--siem-jsonl") == 0 && i + 1 < argc) {
            g_siem_jsonl_path = argv[++i];
        } else if (strcmp(argv[i], "--no-scheduler") == 0) {
            g_no_scheduler = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (do_install) {
        char exe_path[MAX_PATH];
        GetModuleFileNameA(NULL, exe_path, MAX_PATH);
        install_service(exe_path);
        return 0;
    }

    if (do_uninstall) {
        uninstall_service();
        return 0;
    }

    if (console_mode) {
        run_console();
        return 0;
    }

    if (service_mode || (!console_mode && !do_install && !do_uninstall)) {
        /* Default: try to start as a service.
         * If not launched by SCM, StartServiceCtrlDispatcher will fail
         * and we fall back to console mode. */
        SERVICE_TABLE_ENTRYA dispatch[] = {
            { (LPSTR)SERVICE_NAME, svc_main },
            { NULL, NULL }
        };

        if (!StartServiceCtrlDispatcherA(dispatch)) {
            DWORD err = GetLastError();
            if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                /* Not launched by SCM — run in console mode */
                if (!service_mode) {
                    printf("[service] Not running as service. Use --console for interactive mode.\n");
                    print_usage(argv[0]);
                    return 1;
                }
            } else {
                fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n", err);
                return 1;
            }
        }
    }

    return 0;
}
