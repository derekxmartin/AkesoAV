/* siem_shipper.cpp -- HTTP SIEM shipper with ring buffer + NDJSON batching.
 *
 * Implements the full event pipeline:
 *   - Ring buffer (1000 capacity, oldest dropped when full)
 *   - Flush worker thread (100 events or 5s timer)
 *   - WinHTTP POST to {siem_url}/api/v1/ingest
 *   - X-API-Key header
 *   - JSONL local writer integration
 *   - Callback mode for EDR integration
 */

#include "siem/siem_shipper.h"
#include "siem/event_serialize.h"

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#include <cstdio>
#include <cstring>

namespace akav {

/* ---- Constructor / Destructor ---------------------------------------- */

SiemShipper::SiemShipper()
    : ring_head_(0)
    , ring_count_(0)
    , http_thread_(nullptr)
    , http_stop_event_(nullptr)
    , http_flush_event_(nullptr)
    , http_running_(false)
    , callback_(nullptr)
    , callback_user_data_(nullptr)
    , jsonl_running_(false)
    , events_shipped_(0)
    , events_dropped_(0)
{
    ring_.resize(RING_BUFFER_CAPACITY);
}

SiemShipper::~SiemShipper()
{
    stop_http();
    stop_jsonl();
}

/* ---- Callback mode --------------------------------------------------- */

void SiemShipper::set_callback(akav_siem_callback_t callback, void* user_data)
{
    std::lock_guard<std::mutex> lock(callback_mutex_);
    callback_ = callback;
    callback_user_data_ = user_data;
}

/* ---- Ring buffer ----------------------------------------------------- */

void SiemShipper::ring_push(const akav_siem_event_t& event)
{
    std::lock_guard<std::mutex> lock(ring_mutex_);

    if (ring_count_ >= RING_BUFFER_CAPACITY) {
        /* Overwrite oldest — advance head and drop count stays same */
        events_dropped_++;
    } else {
        ring_count_++;
    }

    size_t write_pos = ring_head_;
    ring_[write_pos] = event;
    ring_head_ = (ring_head_ + 1) % RING_BUFFER_CAPACITY;
}

std::vector<akav_siem_event_t> SiemShipper::ring_drain(size_t max_count)
{
    std::lock_guard<std::mutex> lock(ring_mutex_);

    size_t to_drain = (ring_count_ < max_count) ? ring_count_ : max_count;
    if (to_drain == 0)
        return {};

    std::vector<akav_siem_event_t> batch;
    batch.reserve(to_drain);

    /* Read position = head - count (with wrap) */
    size_t read_pos = (ring_head_ + RING_BUFFER_CAPACITY - ring_count_)
                      % RING_BUFFER_CAPACITY;

    for (size_t i = 0; i < to_drain; ++i) {
        batch.push_back(ring_[read_pos]);
        read_pos = (read_pos + 1) % RING_BUFFER_CAPACITY;
    }

    ring_count_ -= to_drain;
    return batch;
}

size_t SiemShipper::events_queued() const
{
    std::lock_guard<std::mutex> lock(ring_mutex_);
    return ring_count_;
}

/* ---- Event submission ------------------------------------------------ */

void SiemShipper::submit(const akav_siem_event_t& event)
{
    /* 1. Callback (integrated mode) */
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (callback_) {
            callback_(&event, callback_user_data_);
        }
    }

    /* 2. JSONL writer */
    if (jsonl_running_) {
        jsonl_.write_event(&event);
    }

    /* 3. HTTP ring buffer */
    if (http_running_) {
        ring_push(event);
        /* Signal the flush thread that new events are available */
        if (http_flush_event_)
            SetEvent(http_flush_event_);
    }
}

/* ---- JSONL writer ---------------------------------------------------- */

bool SiemShipper::start_jsonl(const char* path)
{
    if (jsonl_running_)
        return true;

    if (!jsonl_.init(path))
        return false;

    jsonl_running_ = true;
    return true;
}

void SiemShipper::stop_jsonl()
{
    if (!jsonl_running_)
        return;

    jsonl_.shutdown();
    jsonl_running_ = false;
}

/* ---- HTTP shipper ---------------------------------------------------- */

bool SiemShipper::start_http(const char* siem_url, const char* api_key)
{
    if (http_running_)
        return true;

    if (!siem_url || !api_key)
        return false;

    siem_url_ = siem_url;
    api_key_ = api_key;

    /* Create events */
    http_stop_event_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    http_flush_event_ = CreateEventA(nullptr, FALSE, FALSE, nullptr);

    if (!http_stop_event_ || !http_flush_event_) {
        if (http_stop_event_) { CloseHandle(http_stop_event_); http_stop_event_ = nullptr; }
        if (http_flush_event_) { CloseHandle(http_flush_event_); http_flush_event_ = nullptr; }
        return false;
    }

    http_running_ = true;

    http_thread_ = CreateThread(nullptr, 0, http_thread_proc, this, 0, nullptr);
    if (!http_thread_) {
        http_running_ = false;
        CloseHandle(http_stop_event_);  http_stop_event_ = nullptr;
        CloseHandle(http_flush_event_); http_flush_event_ = nullptr;
        return false;
    }

    return true;
}

void SiemShipper::stop_http()
{
    if (!http_running_)
        return;

    /* Signal stop */
    http_running_ = false;
    if (http_stop_event_)
        SetEvent(http_stop_event_);

    /* Wait for thread to finish */
    if (http_thread_) {
        WaitForSingleObject(http_thread_, 10000);
        CloseHandle(http_thread_);
        http_thread_ = nullptr;
    }

    if (http_stop_event_) { CloseHandle(http_stop_event_); http_stop_event_ = nullptr; }
    if (http_flush_event_) { CloseHandle(http_flush_event_); http_flush_event_ = nullptr; }
}

DWORD WINAPI SiemShipper::http_thread_proc(LPVOID param)
{
    auto* self = static_cast<SiemShipper*>(param);
    self->http_loop();
    return 0;
}

void SiemShipper::http_loop()
{
    HANDLE handles[2] = { http_stop_event_, http_flush_event_ };

    while (http_running_) {
        /* Wait for: stop, flush signal, or 5s timeout */
        DWORD result = WaitForMultipleObjects(2, handles, FALSE, FLUSH_INTERVAL_MS);

        if (result == WAIT_OBJECT_0) {
            /* Stop requested — do a final flush */
            auto batch = ring_drain(RING_BUFFER_CAPACITY);
            if (!batch.empty())
                http_post_batch(batch);
            break;
        }

        /* Timer expired or flush signaled — drain up to BATCH_SIZE */
        auto batch = ring_drain(BATCH_SIZE);
        if (!batch.empty()) {
            if (!http_post_batch(batch)) {
                /* Post failed — push events back to ring buffer for retry.
                 * Push in reverse so they re-enter in original order. */
                for (auto it = batch.rbegin(); it != batch.rend(); ++it) {
                    ring_push(*it);
                }
            }
        }
    }
}

/* ---- WinHTTP POST ---------------------------------------------------- */

/* Build a single NDJSON line from an event (same format as JSONL writer). */
static std::string event_to_ndjson_line(const akav_siem_event_t& event)
{
    char line[16384];
    int len = snprintf(line, sizeof(line),
        "{\"event_id\":\"%s\",\"timestamp\":\"%s\","
        "\"source_type\":\"%s\",\"event_type\":\"%s\","
        "\"agent_id\":\"%s\",\"payload\":%s}",
        event.event_id, event.timestamp,
        event.source_type, event.event_type,
        event.agent_id, event.payload_json);

    if (len <= 0 || (size_t)len >= sizeof(line))
        return "{}";
    return std::string(line, (size_t)len);
}

bool SiemShipper::http_post_batch(const std::vector<akav_siem_event_t>& batch)
{
    if (batch.empty())
        return true;

    /* Build NDJSON body */
    std::string body;
    body.reserve(batch.size() * 2048);
    for (const auto& event : batch) {
        body += event_to_ndjson_line(event);
        body += '\n';
    }

    /* Build full URL: {siem_url}/api/v1/ingest */
    std::string full_url = siem_url_;
    if (!full_url.empty() && full_url.back() == '/')
        full_url.pop_back();
    full_url += "/api/v1/ingest";

    /* Convert URL to wide string for WinHTTP */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, full_url.c_str(), -1, nullptr, 0);
    if (wlen <= 0)
        return false;
    std::wstring wurl((size_t)wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, full_url.c_str(), -1, &wurl[0], wlen);

    /* Crack URL */
    URL_COMPONENTS uc;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = (DWORD)-1;
    uc.dwHostNameLength = (DWORD)-1;
    uc.dwUrlPathLength = (DWORD)-1;
    uc.dwExtraInfoLength = (DWORD)-1;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc))
        return false;

    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength > 0)
        path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);

    bool use_ssl = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort;

    /* Open session */
    HINTERNET session = WinHttpOpen(L"AkesoAV/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return false;

    /* Set timeouts: 5s connect, 10s send/receive */
    WinHttpSetTimeouts(session, 5000, 5000, 10000, 10000);

    HINTERNET conn = WinHttpConnect(session, host.c_str(), port, 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD flags = use_ssl ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(conn, L"POST", path.c_str(),
                                           nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return false;
    }

    /* Add headers */
    WinHttpAddRequestHeaders(request,
        L"Content-Type: application/x-ndjson\r\n",
        (DWORD)-1L, WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);

    /* X-API-Key header */
    std::wstring key_header = L"X-API-Key: ";
    int klen = MultiByteToWideChar(CP_UTF8, 0, api_key_.c_str(), -1, nullptr, 0);
    if (klen > 0) {
        std::wstring wkey((size_t)klen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, api_key_.c_str(), -1, &wkey[0], klen);
        key_header += wkey;
        key_header += L"\r\n";
        WinHttpAddRequestHeaders(request, key_header.c_str(),
            (DWORD)-1L, WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);
    }

    /* Send request */
    BOOL ok = WinHttpSendRequest(request,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body.c_str(), (DWORD)body.size(),
        (DWORD)body.size(), 0);

    bool success = false;
    if (ok) {
        ok = WinHttpReceiveResponse(request, nullptr);
        if (ok) {
            DWORD status = 0;
            DWORD sz = sizeof(status);
            WinHttpQueryHeaders(request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                WINHTTP_NO_HEADER_INDEX);
            /* 2xx = success */
            success = (status >= 200 && status < 300);

            if (success)
                events_shipped_ += batch.size();
        }
    }

    if (!success) {
        fprintf(stderr, "[siem_shipper] HTTP POST failed to %s\n",
                full_url.c_str());
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);

    return success;
}

} /* namespace akav */
