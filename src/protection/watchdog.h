#ifndef AKAV_WATCHDOG_H
#define AKAV_WATCHDOG_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Watchdog Configuration ─────────────────────────────────────── */

#define AKAV_WATCHDOG_PIPE_NAME    "\\\\.\\pipe\\AkesoAVWatchdog"
#define AKAV_WATCHDOG_PING         "PING"
#define AKAV_WATCHDOG_PONG         "PONG"

#define AKAV_WATCHDOG_DEFAULT_INTERVAL_MS   5000   /* 5s heartbeat */
#define AKAV_WATCHDOG_DEFAULT_TIMEOUT_MS   15000   /* 15s timeout */
#define AKAV_WATCHDOG_MAX_RESTARTS             10   /* max restarts before giving up */

/* ── Watchdog State ─────────────────────────────────────────────── */

typedef enum {
    AKAV_WATCHDOG_IDLE       = 0,
    AKAV_WATCHDOG_RUNNING    = 1,
    AKAV_WATCHDOG_RESTARTING = 2,
    AKAV_WATCHDOG_STOPPED    = 3,
    AKAV_WATCHDOG_FAILED     = 4   /* Exceeded max restarts */
} akav_watchdog_state_t;

/** Log callback for watchdog events */
typedef void (*akav_watchdog_log_fn)(const char* message, void* ctx);

/** Watchdog configuration */
typedef struct {
    const char*           service_exe_path;  /* Path to akesoav-service.exe */
    const char*           service_args;      /* Command-line args (or NULL) */
    uint32_t              ping_interval_ms;  /* Heartbeat interval (default 5000) */
    uint32_t              timeout_ms;        /* Timeout before restart (default 15000) */
    uint32_t              max_restarts;      /* Max consecutive restarts (default 10) */
    akav_watchdog_log_fn  log_fn;            /* Optional log callback */
    void*                 log_ctx;           /* Context for log callback */
} akav_watchdog_config_t;

/** Watchdog runtime state */
typedef struct {
    akav_watchdog_config_t config;
    akav_watchdog_state_t  state;
    uint32_t               restart_count;
    uint32_t               total_restarts;
    void*                  process_handle;   /* HANDLE to child process */
    void*                  stop_event;       /* HANDLE to stop event */
    bool                   initialized;
} akav_watchdog_t;

/* ── Watchdog API ───────────────────────────────────────────────── */

/**
 * Initialize watchdog with default configuration.
 */
void akav_watchdog_init(akav_watchdog_t* wd);

/**
 * Configure the watchdog. Call after init, before start.
 */
void akav_watchdog_configure(akav_watchdog_t* wd,
                              const akav_watchdog_config_t* config);

/**
 * Start the watchdog loop. Launches the service process and begins
 * heartbeat monitoring. This function blocks until the watchdog is
 * stopped or exceeds max restarts.
 * Returns true if stopped cleanly, false if max restarts exceeded.
 */
bool akav_watchdog_run(akav_watchdog_t* wd);

/**
 * Signal the watchdog to stop. Can be called from another thread
 * or a signal handler. The watchdog will terminate the child process
 * and exit the run loop.
 */
void akav_watchdog_stop(akav_watchdog_t* wd);

/**
 * Clean up watchdog resources.
 */
void akav_watchdog_destroy(akav_watchdog_t* wd);

/* ── Service-side heartbeat responder ───────────────────────────── */

/**
 * Start the heartbeat responder thread in the service process.
 * Creates a named pipe server that responds to PING with PONG.
 * Returns a thread handle (HANDLE) or NULL on failure.
 * Call akav_heartbeat_stop() to shut down.
 */
void* akav_heartbeat_start(void);

/**
 * Stop the heartbeat responder. Signals the thread to exit and
 * waits for it to finish. Pass the handle from akav_heartbeat_start.
 */
void akav_heartbeat_stop(void* thread_handle);

/* ── Utility: single PING/PONG round-trip (for testing) ─────────── */

/**
 * Send a PING to the watchdog pipe and wait for PONG.
 * Returns true if PONG received within timeout_ms.
 */
bool akav_watchdog_ping(uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_WATCHDOG_H */
