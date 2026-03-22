/* event_serialize.cpp -- SIEM event JSON serialization.
 *
 * Implements serialization for all 5 event types defined in S3.7.
 * Uses snprintf for JSON construction (no external JSON library).
 * UUID v4 via BCryptGenRandom (Windows CNG).
 */

#include "event_serialize.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstring>
#include <ctime>

namespace akav {

/* ---- JSON escaping --------------------------------------------------- */

static std::string json_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

/* ---- UUID v4 --------------------------------------------------------- */

std::string generate_uuid_v4()
{
    uint8_t bytes[16];
    BCryptGenRandom(nullptr, bytes, sizeof(bytes),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    /* Set version 4 (bits 12-15 of time_hi_and_version) */
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    /* Set variant (bits 6-7 of clock_seq_hi_and_reserved) */
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    char buf[40];
    snprintf(buf, sizeof(buf),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

/* ---- ISO 8601 timestamp ---------------------------------------------- */

std::string iso8601_now()
{
    SYSTEMTIME st;
    GetSystemTime(&st);

    char buf[40];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::string(buf);
}

/* ---- Hostname -------------------------------------------------------- */

std::string get_hostname()
{
    char buf[256];
    DWORD size = sizeof(buf);
    if (GetComputerNameA(buf, &size))
        return std::string(buf, size);
    return "UNKNOWN";
}

/* ---- Common envelope fill -------------------------------------------- */

static void fill_envelope(akav_siem_event_t* out, const char* event_type)
{
    memset(out, 0, sizeof(*out));

    std::string uuid = generate_uuid_v4();
    std::string ts = iso8601_now();
    std::string host = get_hostname();

    strncpy_s(out->event_id, sizeof(out->event_id), uuid.c_str(), _TRUNCATE);
    strncpy_s(out->timestamp, sizeof(out->timestamp), ts.c_str(), _TRUNCATE);
    strncpy_s(out->source_type, sizeof(out->source_type), "akeso_av", _TRUNCATE);
    strncpy_s(out->event_type, sizeof(out->event_type), event_type, _TRUNCATE);
    strncpy_s(out->agent_id, sizeof(out->agent_id), host.c_str(), _TRUNCATE);
}

/* ---- av:scan_result (S3.7.1) ----------------------------------------- */

void serialize_scan_result(const ScanResultPayload& p, akav_siem_event_t* out)
{
    fill_envelope(out, "av:scan_result");

    /* Build payload JSON. Use a large stack buffer to assemble, then copy. */
    char buf[8192];
    int n = 0;

    n += snprintf(buf + n, sizeof(buf) - (size_t)n,
        "{\"scan\":{\"result\":\"%s\",\"scanner_id\":\"%s\",\"scan_type\":\"%s\","
        "\"heuristic_score\":%.4f,\"duration_ms\":%llu},",
        json_escape(p.result).c_str(),
        json_escape(p.scanner_id).c_str(),
        json_escape(p.scan_type).c_str(),
        p.heuristic_score,
        (unsigned long long)p.duration_ms);

    n += snprintf(buf + n, sizeof(buf) - (size_t)n,
        "\"signature\":{\"name\":\"%s\",\"id\":\"%s\",\"engine\":\"%s\","
        "\"db_version\":\"%s\"},",
        json_escape(p.sig_name).c_str(),
        json_escape(p.sig_id).c_str(),
        json_escape(p.sig_engine).c_str(),
        json_escape(p.db_version).c_str());

    n += snprintf(buf + n, sizeof(buf) - (size_t)n,
        "\"file\":{\"path\":\"%s\",\"name\":\"%s\",\"type\":\"%s\","
        "\"size\":%llu,\"hash\":{\"sha256\":\"%s\"},\"in_whitelist\":%s}",
        json_escape(p.file_path).c_str(),
        json_escape(p.file_name).c_str(),
        json_escape(p.file_type).c_str(),
        (unsigned long long)p.file_size,
        json_escape(p.sha256).c_str(),
        p.in_whitelist ? "true" : "false");

    /* Optional process block */
    if (p.process_pid != 0 || !p.process_name.empty()) {
        n += snprintf(buf + n, sizeof(buf) - (size_t)n,
            ",\"process\":{\"pid\":%u,\"name\":\"%s\",\"executable\":\"%s\"}",
            p.process_pid,
            json_escape(p.process_name).c_str(),
            json_escape(p.process_exe).c_str());
    }

    snprintf(buf + n, sizeof(buf) - (size_t)n, "}");

    strncpy_s(out->payload_json, sizeof(out->payload_json), buf, _TRUNCATE);
}

/* ---- av:quarantine (S3.7.2) ------------------------------------------ */

void serialize_quarantine(const QuarantinePayload& p, akav_siem_event_t* out)
{
    fill_envelope(out, "av:quarantine");

    char buf[8192];
    snprintf(buf, sizeof(buf),
        "{\"quarantine\":{\"action\":\"%s\",\"vault_id\":\"%s\","
        "\"original_path\":\"%s\",\"restore_available\":%s},"
        "\"signature\":{\"name\":\"%s\",\"id\":\"%s\"},"
        "\"file\":{\"path\":\"%s\",\"name\":\"%s\",\"size\":%llu,"
        "\"hash\":{\"sha256\":\"%s\"}}}",
        json_escape(p.action).c_str(),
        json_escape(p.vault_id).c_str(),
        json_escape(p.original_path).c_str(),
        p.restore_available ? "true" : "false",
        json_escape(p.sig_name).c_str(),
        json_escape(p.sig_id).c_str(),
        json_escape(p.original_path).c_str(),
        json_escape(p.file_name).c_str(),
        (unsigned long long)p.file_size,
        json_escape(p.sha256).c_str());

    strncpy_s(out->payload_json, sizeof(out->payload_json), buf, _TRUNCATE);
}

/* ---- av:realtime_block (S3.7.3) -------------------------------------- */

void serialize_realtime_block(const RealtimeBlockPayload& p, akav_siem_event_t* out)
{
    fill_envelope(out, "av:realtime_block");

    char buf[8192];
    snprintf(buf, sizeof(buf),
        "{\"block\":{\"operation\":\"%s\",\"denied\":%s},"
        "\"signature\":{\"name\":\"%s\",\"id\":\"%s\"},"
        "\"file\":{\"path\":\"%s\",\"name\":\"%s\",\"size\":%llu,"
        "\"hash\":{\"sha256\":\"%s\"}},"
        "\"process\":{\"pid\":%u,\"name\":\"%s\",\"executable\":\"%s\"}}",
        json_escape(p.operation).c_str(),
        p.denied ? "true" : "false",
        json_escape(p.sig_name).c_str(),
        json_escape(p.sig_id).c_str(),
        json_escape(p.file_path).c_str(),
        json_escape(p.file_name).c_str(),
        (unsigned long long)p.file_size,
        json_escape(p.sha256).c_str(),
        p.process_pid,
        json_escape(p.process_name).c_str(),
        json_escape(p.process_exe).c_str());

    strncpy_s(out->payload_json, sizeof(out->payload_json), buf, _TRUNCATE);
}

/* ---- av:signature_update (S3.7.4) ------------------------------------ */

void serialize_signature_update(const SignatureUpdatePayload& p, akav_siem_event_t* out)
{
    fill_envelope(out, "av:signature_update");

    char buf[8192];
    snprintf(buf, sizeof(buf),
        "{\"update\":{\"previous_version\":\"%s\",\"new_version\":\"%s\","
        "\"signature_count\":%llu,\"delta_added\":%llu,\"delta_removed\":%llu,"
        "\"update_source\":\"%s\",\"verification\":\"%s\"}}",
        json_escape(p.previous_version).c_str(),
        json_escape(p.new_version).c_str(),
        (unsigned long long)p.signature_count,
        (unsigned long long)p.delta_added,
        (unsigned long long)p.delta_removed,
        json_escape(p.update_source).c_str(),
        json_escape(p.verification).c_str());

    strncpy_s(out->payload_json, sizeof(out->payload_json), buf, _TRUNCATE);
}

/* ---- av:scan_error (S3.7.5) ------------------------------------------ */

void serialize_scan_error(const ScanErrorPayload& p, akav_siem_event_t* out)
{
    fill_envelope(out, "av:scan_error");

    char buf[8192];
    snprintf(buf, sizeof(buf),
        "{\"error\":{\"reason\":\"%s\",\"detail\":\"%s\",\"stage\":\"%s\"},"
        "\"file\":{\"path\":\"%s\",\"name\":\"%s\",\"size\":%llu}}",
        json_escape(p.reason).c_str(),
        json_escape(p.detail).c_str(),
        json_escape(p.stage).c_str(),
        json_escape(p.file_path).c_str(),
        json_escape(p.file_name).c_str(),
        (unsigned long long)p.file_size);

    strncpy_s(out->payload_json, sizeof(out->payload_json), buf, _TRUNCATE);
}

} /* namespace akav */
