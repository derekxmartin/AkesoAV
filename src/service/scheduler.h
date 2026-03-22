/* scheduler.h -- Scheduled scanning for akesoav-service.
 *
 * Implements scheduled scanning per S5.13:
 *   - Config from %ProgramData%\Akeso\schedules.json
 *   - Quick scan (high-risk paths), full scan (all fixed drives), custom
 *   - I/O throttling: THREAD_MODE_BACKGROUND_BEGIN, CPU affinity cap 50%
 *   - Battery-aware pause (GetSystemPowerStatus)
 *   - Concurrency guard (one scan at a time)
 *   - SIEM events: av:scheduled_scan_start, av:scheduled_scan_complete
 *   - Progress tracking via STATS command
 */

#ifndef AKAV_SCHEDULER_H
#define AKAV_SCHEDULER_H

#include "akesoav.h"
#include "service/cron_parser.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <mutex>
#include <atomic>

namespace akav {

/* ---- Schedule entry -------------------------------------------------- */

struct ScheduleEntry {
    std::string    name;
    std::string    type;     /* "quick", "full", "custom" */
    std::vector<std::string> paths;
    std::string    cron_expr;
    CronExpression cron;
    bool           enabled;
    time_t         next_run; /* Next trigger time (computed) */
};

/* ---- Scan progress --------------------------------------------------- */

struct ScanProgress {
    std::atomic<bool>     active{false};
    std::atomic<uint64_t> files_scanned{0};
    std::atomic<uint64_t> detections{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> bytes_scanned{0};
    std::atomic<int64_t>  start_time_ms{0};
    std::string           schedule_name;
    std::string           scan_type;
    std::vector<std::string> paths;
};

/* ---- Scheduler ------------------------------------------------------- */

class Scheduler {
public:
    Scheduler();
    ~Scheduler();

    Scheduler(const Scheduler&) = delete;
    Scheduler& operator=(const Scheduler&) = delete;

    /* Initialize with engine handle (needed for scanning).
     * config_path: path to schedules.json (nullptr for default). */
    bool init(akav_engine_t* engine, const char* config_path = nullptr);

    /* Start the scheduler thread. */
    bool start();

    /* Stop the scheduler thread. */
    void stop();

    /* Reload schedules from config file. */
    bool reload();

    /* Run a named schedule immediately (for CLI --schedule run <name>). */
    bool run_now(const std::string& name);

    /* Get loaded schedules (for CLI --schedule list). */
    std::vector<ScheduleEntry> schedules() const;

    /* Get current scan progress (for STATS). */
    const ScanProgress& progress() const { return progress_; }

    /* Is a scan currently active? */
    bool scan_active() const { return progress_.active.load(); }

    /* Disable battery-aware pause (for testing). */
    void set_ignore_battery(bool ignore) { ignore_battery_ = ignore; }

private:
    akav_engine_t*            engine_;
    std::string               config_path_;
    std::vector<ScheduleEntry> schedules_;
    mutable std::mutex        schedules_mutex_;

    /* Scheduler thread */
    HANDLE                    thread_;
    HANDLE                    stop_event_;
    HANDLE                    run_event_;      /* Signaled for immediate run */
    volatile bool             running_;

    /* Scan execution */
    ScanProgress              progress_;
    std::string               pending_run_;    /* Name of schedule to run immediately */
    std::mutex                pending_mutex_;
    bool                      ignore_battery_{false};

    static DWORD WINAPI scheduler_thread_proc(LPVOID param);
    void scheduler_loop();

    /* Execute a scan for the given schedule entry. */
    void execute_scan(const ScheduleEntry& entry);

    /* Get paths for a quick scan (high-risk paths per S5.13). */
    std::vector<std::string> quick_scan_paths();

    /* Get paths for a full scan (all fixed drives). */
    std::vector<std::string> full_scan_paths();

    /* Apply I/O throttling to current thread. */
    void apply_throttling();
    void remove_throttling();

    /* Check battery status. Returns true if on battery (should pause). */
    bool on_battery();

    /* Load config from JSON file. */
    bool load_config();

    /* Emit SIEM events. */
    void emit_scan_start(const ScheduleEntry& entry);
    void emit_scan_complete(const ScheduleEntry& entry);
};

} /* namespace akav */

#endif /* AKAV_SCHEDULER_H */
