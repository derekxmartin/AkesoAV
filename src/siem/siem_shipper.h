/* siem_shipper.h -- HTTP SIEM event shipper with ring buffer + batching.
 *
 * Implements the SIEM shipping pipeline per S3.7 and P5-T7:
 *   - Ring buffer: 1000 events capacity
 *   - Batch flush: 100 events OR 5 seconds, whichever comes first
 *   - HTTP POST to {siem_url}/api/v1/ingest (NDJSON body)
 *   - X-API-Key authentication header
 *   - WinHTTP for transport
 *   - Buffering on failure, delivered on reconnect
 *
 * Dual-mode:
 *   Standalone: service owns the shipper + JSONL writer
 *   Integrated: EDR agent registers callback; shipper not used
 */

#ifndef AKAV_SIEM_SHIPPER_H
#define AKAV_SIEM_SHIPPER_H

#include "akesoav.h"
#include "siem/jsonl_writer.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <mutex>

namespace akav {

class SiemShipper {
public:
    static constexpr size_t RING_BUFFER_CAPACITY = 1000;
    static constexpr size_t BATCH_SIZE            = 100;
    static constexpr DWORD  FLUSH_INTERVAL_MS     = 5000;

    SiemShipper();
    ~SiemShipper();

    SiemShipper(const SiemShipper&) = delete;
    SiemShipper& operator=(const SiemShipper&) = delete;

    /* ---- Callback mode (integrated) ---------------------------------- */

    /* Set a callback for event delivery. Pass nullptr to clear. */
    void set_callback(akav_siem_callback_t callback, void* user_data);

    /* ---- HTTP shipper mode (standalone) ------------------------------- */

    /* Start the HTTP shipping thread.
     * siem_url: base URL (e.g. "https://siem.example.com")
     * api_key: authentication key for X-API-Key header. */
    bool start_http(const char* siem_url, const char* api_key);

    /* Stop the HTTP shipping thread and flush remaining events. */
    void stop_http();

    /* ---- JSONL writer ------------------------------------------------- */

    /* Initialize the local JSONL writer. Can be used alongside HTTP or alone. */
    bool start_jsonl(const char* path = nullptr);

    /* Stop the JSONL writer. */
    void stop_jsonl();

    /* ---- Event submission -------------------------------------------- */

    /* Submit an event to the pipeline.
     * - If callback set: invokes callback immediately
     * - If HTTP running: queues to ring buffer
     * - If JSONL running: writes to log file
     * Thread-safe. */
    void submit(const akav_siem_event_t& event);

    /* ---- Stats ------------------------------------------------------- */

    size_t events_queued() const;
    size_t events_shipped() const { return events_shipped_; }
    size_t events_dropped() const { return events_dropped_; }

    bool is_http_running() const { return http_running_; }

private:
    /* Ring buffer */
    std::vector<akav_siem_event_t> ring_;
    size_t ring_head_;       /* Next write position */
    size_t ring_count_;      /* Current count */
    mutable std::mutex ring_mutex_;

    void ring_push(const akav_siem_event_t& event);
    std::vector<akav_siem_event_t> ring_drain(size_t max_count);

    /* HTTP shipping thread */
    HANDLE              http_thread_;
    HANDLE              http_stop_event_;   /* Signaled to stop the thread */
    HANDLE              http_flush_event_;  /* Signaled when events are ready */
    volatile bool       http_running_;
    std::string         siem_url_;
    std::string         api_key_;

    static DWORD WINAPI http_thread_proc(LPVOID param);
    void http_loop();
    bool http_post_batch(const std::vector<akav_siem_event_t>& batch);

    /* Callback mode */
    akav_siem_callback_t callback_;
    void*                callback_user_data_;
    std::mutex           callback_mutex_;

    /* JSONL writer */
    JsonlWriter          jsonl_;
    bool                 jsonl_running_;

    /* Stats */
    volatile size_t      events_shipped_;
    volatile size_t      events_dropped_;
};

} /* namespace akav */

#endif /* AKAV_SIEM_SHIPPER_H */
