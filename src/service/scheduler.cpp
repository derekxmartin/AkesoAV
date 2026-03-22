/* scheduler.cpp -- Scheduled scanning implementation.
 *
 * Runs as a background thread in akesoav-service.exe, checking cron
 * triggers every 30 seconds. Scans run throttled (background I/O,
 * 50% CPU cap) and pause on battery.
 */

#include "service/scheduler.h"
#include "engine_internal.h"
#include "siem/event_serialize.h"
#include "siem/siem_shipper.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>

namespace akav {

/* ---- Minimal JSON helpers (no external dependency) ------------------- */

static std::string json_string_value(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    /* Find the colon after the key */
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";

    /* Find opening quote */
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";

    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";

    return json.substr(pos + 1, end - pos - 1);
}

static bool json_bool_value(const std::string& json, const std::string& key, bool default_val)
{
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return default_val;

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return default_val;

    /* Skip whitespace */
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        pos++;

    if (json.substr(pos, 4) == "true") return true;
    if (json.substr(pos, 5) == "false") return false;
    return default_val;
}

static std::vector<std::string> json_string_array(const std::string& json, const std::string& key)
{
    std::vector<std::string> result;
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return result;

    pos = json.find('[', pos);
    if (pos == std::string::npos) return result;

    auto end = json.find(']', pos);
    if (end == std::string::npos) return result;

    std::string arr = json.substr(pos + 1, end - pos - 1);

    /* Extract quoted strings */
    size_t i = 0;
    while (i < arr.size()) {
        auto q1 = arr.find('"', i);
        if (q1 == std::string::npos) break;
        auto q2 = arr.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        result.push_back(arr.substr(q1 + 1, q2 - q1 - 1));
        i = q2 + 1;
    }

    return result;
}

/* Split JSON array of objects (very basic: splits on "},") */
static std::vector<std::string> json_split_objects(const std::string& content)
{
    std::vector<std::string> objects;
    int depth = 0;
    size_t start = 0;
    bool in_array = false;

    for (size_t i = 0; i < content.size(); ++i) {
        if (content[i] == '[' && !in_array) {
            in_array = true;
            start = i + 1;
            continue;
        }
        if (content[i] == '{') {
            if (depth == 0) start = i;
            depth++;
        }
        if (content[i] == '}') {
            depth--;
            if (depth == 0) {
                objects.push_back(content.substr(start, i - start + 1));
            }
        }
    }

    return objects;
}

/* ---- Default config path --------------------------------------------- */

static std::string default_config_path()
{
    char buf[MAX_PATH];
    DWORD len = GetEnvironmentVariableA("ProgramData", buf, sizeof(buf));
    if (len == 0 || len >= sizeof(buf))
        return "C:\\ProgramData\\Akeso\\schedules.json";
    return std::string(buf, len) + "\\Akeso\\schedules.json";
}

/* ---- Constructor / Destructor ---------------------------------------- */

Scheduler::Scheduler()
    : engine_(nullptr)
    , thread_(nullptr)
    , stop_event_(nullptr)
    , run_event_(nullptr)
    , running_(false)
{
}

Scheduler::~Scheduler()
{
    stop();
}

/* ---- Initialization -------------------------------------------------- */

bool Scheduler::init(akav_engine_t* engine, const char* config_path)
{
    if (!engine)
        return false;

    engine_ = engine;
    config_path_ = config_path ? config_path : default_config_path();

    load_config();

    return true;
}

/* ---- Config loading -------------------------------------------------- */

bool Scheduler::load_config()
{
    std::ifstream file(config_path_);
    if (!file.is_open()) {
        fprintf(stderr, "[scheduler] Cannot open config '%s'\n",
                config_path_.c_str());
        return false;
    }

    std::stringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();

    auto objects = json_split_objects(content);

    std::lock_guard<std::mutex> lock(schedules_mutex_);
    schedules_.clear();

    for (const auto& obj : objects) {
        ScheduleEntry entry;
        entry.name = json_string_value(obj, "name");
        entry.type = json_string_value(obj, "type");
        entry.paths = json_string_array(obj, "paths");
        entry.cron_expr = json_string_value(obj, "cron");
        entry.enabled = json_bool_value(obj, "enabled", true);

        if (entry.name.empty() || entry.cron_expr.empty())
            continue;

        entry.cron = cron_parse(entry.cron_expr);
        if (!entry.cron.valid) {
            fprintf(stderr, "[scheduler] Invalid cron '%s' for '%s'\n",
                    entry.cron_expr.c_str(), entry.name.c_str());
            continue;
        }

        entry.next_run = cron_next(entry.cron, time(nullptr));
        schedules_.push_back(entry);
    }

    fprintf(stderr, "[scheduler] Loaded %zu schedule(s) from '%s'\n",
            schedules_.size(), config_path_.c_str());
    return !schedules_.empty();
}

bool Scheduler::reload()
{
    return load_config();
}

/* ---- Schedule access ------------------------------------------------- */

std::vector<ScheduleEntry> Scheduler::schedules() const
{
    std::lock_guard<std::mutex> lock(schedules_mutex_);
    return schedules_;
}

/* ---- Start / Stop ---------------------------------------------------- */

bool Scheduler::start()
{
    if (running_)
        return true;

    stop_event_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    run_event_ = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    if (!stop_event_ || !run_event_) {
        if (stop_event_) { CloseHandle(stop_event_); stop_event_ = nullptr; }
        if (run_event_) { CloseHandle(run_event_); run_event_ = nullptr; }
        return false;
    }

    running_ = true;
    thread_ = CreateThread(nullptr, 0, scheduler_thread_proc, this, 0, nullptr);
    if (!thread_) {
        running_ = false;
        CloseHandle(stop_event_); stop_event_ = nullptr;
        CloseHandle(run_event_); run_event_ = nullptr;
        return false;
    }

    return true;
}

void Scheduler::stop()
{
    if (!running_)
        return;

    running_ = false;
    if (stop_event_) SetEvent(stop_event_);

    if (thread_) {
        WaitForSingleObject(thread_, 30000);
        CloseHandle(thread_);
        thread_ = nullptr;
    }
    if (stop_event_) { CloseHandle(stop_event_); stop_event_ = nullptr; }
    if (run_event_) { CloseHandle(run_event_); run_event_ = nullptr; }
}

/* ---- Run now (CLI) --------------------------------------------------- */

bool Scheduler::run_now(const std::string& name)
{
    {
        std::lock_guard<std::mutex> lock(schedules_mutex_);
        bool found = false;
        for (const auto& e : schedules_) {
            if (e.name == name) { found = true; break; }
        }
        if (!found) return false;
    }

    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_run_ = name;
    }

    if (run_event_)
        SetEvent(run_event_);
    return true;
}

/* ---- Scheduler thread ------------------------------------------------ */

DWORD WINAPI Scheduler::scheduler_thread_proc(LPVOID param)
{
    auto* self = static_cast<Scheduler*>(param);
    self->scheduler_loop();
    return 0;
}

void Scheduler::scheduler_loop()
{
    HANDLE handles[2] = { stop_event_, run_event_ };

    while (running_) {
        /* Wait 30 seconds or until signaled */
        DWORD result = WaitForMultipleObjects(2, handles, FALSE, 30000);

        if (result == WAIT_OBJECT_0) {
            /* Stop requested */
            break;
        }

        /* Check for immediate run request */
        std::string run_name;
        {
            std::lock_guard<std::mutex> lock(pending_mutex_);
            run_name = pending_run_;
            pending_run_.clear();
        }

        if (!run_name.empty()) {
            std::lock_guard<std::mutex> lock(schedules_mutex_);
            for (const auto& entry : schedules_) {
                if (entry.name == run_name) {
                    if (progress_.active.load()) {
                        fprintf(stderr, "[scheduler] Scan already in progress, "
                                "skipping '%s'\n", run_name.c_str());
                    } else {
                        execute_scan(entry);
                    }
                    break;
                }
            }
            continue;
        }

        /* Check cron triggers */
        time_t now = time(nullptr);
        std::lock_guard<std::mutex> lock(schedules_mutex_);

        for (auto& entry : schedules_) {
            if (!entry.enabled || !entry.cron.valid)
                continue;

            if (entry.next_run != 0 && now >= entry.next_run) {
                if (progress_.active.load()) {
                    fprintf(stderr, "[scheduler] Scan in progress, skipping "
                            "trigger for '%s'\n", entry.name.c_str());
                } else {
                    execute_scan(entry);
                }

                /* Compute next trigger */
                entry.next_run = cron_next(entry.cron, now);
            }
        }
    }
}

/* ---- Quick/Full scan paths ------------------------------------------- */

std::vector<std::string> Scheduler::quick_scan_paths()
{
    std::vector<std::string> paths;
    char buf[MAX_PATH];

    /* %TEMP% */
    DWORD len = GetEnvironmentVariableA("TEMP", buf, sizeof(buf));
    if (len > 0 && len < sizeof(buf))
        paths.emplace_back(buf, len);

    /* %USERPROFILE%\Downloads */
    len = GetEnvironmentVariableA("USERPROFILE", buf, sizeof(buf));
    if (len > 0 && len < sizeof(buf))
        paths.push_back(std::string(buf, len) + "\\Downloads");

    /* %APPDATA% */
    len = GetEnvironmentVariableA("APPDATA", buf, sizeof(buf));
    if (len > 0 && len < sizeof(buf))
        paths.emplace_back(buf, len);

    /* %PROGRAMDATA% */
    len = GetEnvironmentVariableA("ProgramData", buf, sizeof(buf));
    if (len > 0 && len < sizeof(buf))
        paths.emplace_back(buf, len);

    return paths;
}

std::vector<std::string> Scheduler::full_scan_paths()
{
    std::vector<std::string> paths;
    char drives[512];
    DWORD len = GetLogicalDriveStringsA(sizeof(drives), drives);

    for (DWORD i = 0; i < len; ) {
        const char* drive = drives + i;
        if (GetDriveTypeA(drive) == DRIVE_FIXED)
            paths.emplace_back(drive);
        i += (DWORD)strlen(drive) + 1;
    }

    return paths;
}

/* ---- I/O Throttling -------------------------------------------------- */

void Scheduler::apply_throttling()
{
    /* Background I/O priority */
    SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);

    /* CPU affinity: limit to 50% of cores */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD num_cores = si.dwNumberOfProcessors;
    DWORD half = (num_cores + 1) / 2;
    if (half < 1) half = 1;

    DWORD_PTR mask = 0;
    for (DWORD i = 0; i < half; ++i)
        mask |= (1ULL << i);

    SetThreadAffinityMask(GetCurrentThread(), mask);
}

void Scheduler::remove_throttling()
{
    SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);

    /* Reset affinity to all processors */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD_PTR mask = 0;
    for (DWORD i = 0; i < si.dwNumberOfProcessors; ++i)
        mask |= (1ULL << i);
    SetThreadAffinityMask(GetCurrentThread(), mask);
}

bool Scheduler::on_battery()
{
    SYSTEM_POWER_STATUS sps;
    if (!GetSystemPowerStatus(&sps))
        return false;
    /* ACLineStatus: 0=offline(battery), 1=online(AC), 255=unknown */
    return sps.ACLineStatus == 0;
}

/* ---- SIEM events ----------------------------------------------------- */

void Scheduler::emit_scan_start(const ScheduleEntry& entry)
{
    if (!engine_ || !engine_->impl.siem_shipper())
        return;

    /* Build payload JSON manually */
    char payload[4096];
    std::string paths_json = "[";
    for (size_t i = 0; i < progress_.paths.size(); ++i) {
        if (i > 0) paths_json += ",";
        /* Simple escape for backslashes */
        std::string p = progress_.paths[i];
        std::string escaped;
        for (char c : p) {
            if (c == '\\') escaped += "\\\\";
            else escaped += c;
        }
        paths_json += "\"" + escaped + "\"";
    }
    paths_json += "]";

    snprintf(payload, sizeof(payload),
        "{\"schedule\":{\"name\":\"%s\",\"type\":\"%s\","
        "\"paths\":%s,\"trigger\":\"cron\"}}",
        entry.name.c_str(), entry.type.c_str(), paths_json.c_str());

    akav_siem_event_t event;
    memset(&event, 0, sizeof(event));

    auto uuid = generate_uuid_v4();
    auto ts = iso8601_now();
    auto host = get_hostname();

    strncpy_s(event.event_id, sizeof(event.event_id), uuid.c_str(), _TRUNCATE);
    strncpy_s(event.timestamp, sizeof(event.timestamp), ts.c_str(), _TRUNCATE);
    strncpy_s(event.source_type, sizeof(event.source_type), "akeso_av", _TRUNCATE);
    strncpy_s(event.event_type, sizeof(event.event_type),
              "av:scheduled_scan_start", _TRUNCATE);
    strncpy_s(event.agent_id, sizeof(event.agent_id), host.c_str(), _TRUNCATE);
    strncpy_s(event.payload_json, sizeof(event.payload_json), payload, _TRUNCATE);

    engine_->impl.siem_shipper()->submit(event);
}

void Scheduler::emit_scan_complete(const ScheduleEntry& entry)
{
    if (!engine_ || !engine_->impl.siem_shipper())
        return;

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    int64_t duration_ms = now_ms - progress_.start_time_ms.load();

    /* Build paths JSON */
    std::string paths_json = "[";
    for (size_t i = 0; i < progress_.paths.size(); ++i) {
        if (i > 0) paths_json += ",";
        std::string p = progress_.paths[i];
        std::string escaped;
        for (char c : p) {
            if (c == '\\') escaped += "\\\\";
            else escaped += c;
        }
        paths_json += "\"" + escaped + "\"";
    }
    paths_json += "]";

    char payload[4096];
    snprintf(payload, sizeof(payload),
        "{\"schedule\":{\"name\":\"%s\",\"type\":\"%s\","
        "\"paths\":%s,\"trigger\":\"cron\"},"
        "\"result\":{\"files_scanned\":%llu,\"detections\":%llu,"
        "\"errors\":%llu,\"duration_ms\":%lld,"
        "\"bytes_scanned\":%llu}}",
        entry.name.c_str(), entry.type.c_str(), paths_json.c_str(),
        (unsigned long long)progress_.files_scanned.load(),
        (unsigned long long)progress_.detections.load(),
        (unsigned long long)progress_.errors.load(),
        (long long)duration_ms,
        (unsigned long long)progress_.bytes_scanned.load());

    akav_siem_event_t event;
    memset(&event, 0, sizeof(event));

    auto uuid = generate_uuid_v4();
    auto ts = iso8601_now();
    auto host = get_hostname();

    strncpy_s(event.event_id, sizeof(event.event_id), uuid.c_str(), _TRUNCATE);
    strncpy_s(event.timestamp, sizeof(event.timestamp), ts.c_str(), _TRUNCATE);
    strncpy_s(event.source_type, sizeof(event.source_type), "akeso_av", _TRUNCATE);
    strncpy_s(event.event_type, sizeof(event.event_type),
              "av:scheduled_scan_complete", _TRUNCATE);
    strncpy_s(event.agent_id, sizeof(event.agent_id), host.c_str(), _TRUNCATE);
    strncpy_s(event.payload_json, sizeof(event.payload_json), payload, _TRUNCATE);

    engine_->impl.siem_shipper()->submit(event);
}

/* ---- Scan execution -------------------------------------------------- */

static void scan_callback(const char* path, const akav_scan_result_t* result,
                           void* user_data)
{
    (void)path;
    auto* progress = static_cast<ScanProgress*>(user_data);
    progress->files_scanned.fetch_add(1);
    progress->bytes_scanned.fetch_add((uint64_t)result->total_size);

    if (result->found)
        progress->detections.fetch_add(1);
}

void Scheduler::execute_scan(const ScheduleEntry& entry)
{
    /* Concurrency guard */
    if (progress_.active.load()) {
        fprintf(stderr, "[scheduler] Scan already active, skipping '%s'\n",
                entry.name.c_str());
        return;
    }

    /* Initialize progress */
    progress_.active.store(true);
    progress_.files_scanned.store(0);
    progress_.detections.store(0);
    progress_.errors.store(0);
    progress_.bytes_scanned.store(0);
    progress_.start_time_ms.store(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    progress_.schedule_name = entry.name;
    progress_.scan_type = entry.type;

    /* Determine scan paths */
    if (entry.type == "quick") {
        progress_.paths = quick_scan_paths();
    } else if (entry.type == "full") {
        progress_.paths = full_scan_paths();
    } else {
        progress_.paths = entry.paths;
    }

    fprintf(stderr, "[scheduler] Starting '%s' scan (%s) over %zu path(s)\n",
            entry.name.c_str(), entry.type.c_str(), progress_.paths.size());

    /* Emit SIEM start event */
    emit_scan_start(entry);

    /* Apply throttling */
    apply_throttling();

    /* Scan each path */
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_cache = 1;

    for (const auto& path : progress_.paths) {
        if (!running_)
            break;

        /* Battery check -- pause while on battery */
        while (!ignore_battery_ && on_battery() && running_) {
            fprintf(stderr, "[scheduler] On battery, pausing scan...\n");
            HANDLE handles[1] = { stop_event_ };
            WaitForMultipleObjects(1, handles, FALSE, 10000);
        }

        if (!running_)
            break;

        akav_error_t err = akav_scan_directory(engine_, path.c_str(), &opts,
                                                scan_callback, &progress_);
        if (err != AKAV_OK && err != AKAV_ERROR_IO) {
            progress_.errors.fetch_add(1);
        }
    }

    /* Remove throttling */
    remove_throttling();

    /* Emit SIEM complete event */
    emit_scan_complete(entry);

    fprintf(stderr, "[scheduler] Completed '%s': %llu files, %llu detections, "
            "%llu errors\n",
            entry.name.c_str(),
            (unsigned long long)progress_.files_scanned.load(),
            (unsigned long long)progress_.detections.load(),
            (unsigned long long)progress_.errors.load());

    progress_.active.store(false);
}

} /* namespace akav */
