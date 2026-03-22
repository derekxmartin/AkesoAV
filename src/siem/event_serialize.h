/* event_serialize.h -- SIEM event serialization for all 5 event types.
 *
 * Builds akav_siem_event_t structs with UUID v4 event_id, ISO 8601
 * timestamp, hostname agent_id, and JSON payload per REQUIREMENTS.md S3.7.
 *
 * Event types:
 *   av:scan_result      (S3.7.1)
 *   av:quarantine        (S3.7.2)
 *   av:realtime_block    (S3.7.3)
 *   av:signature_update  (S3.7.4)
 *   av:scan_error        (S3.7.5)
 */

#ifndef AKAV_EVENT_SERIALIZE_H
#define AKAV_EVENT_SERIALIZE_H

#include "akesoav.h"
#include <string>

namespace akav {

/* ---- Payload input structs ------------------------------------------- */

struct ScanResultPayload {
    /* scan */
    std::string result;          /* malicious, suspicious, clean, error */
    std::string scanner_id;      /* akavscan, akesoav-service, realtime, edr_integrated */
    std::string scan_type;       /* on_demand, on_access, memory */
    double      heuristic_score; /* 0.0 - 1.0 */
    uint64_t    duration_ms;

    /* signature */
    std::string sig_name;
    std::string sig_id;
    std::string sig_engine;      /* hash_sha256, byte_stream, heuristic, ... */
    std::string db_version;

    /* file */
    std::string file_path;
    std::string file_name;
    std::string file_type;       /* PE32, ZIP, ... */
    uint64_t    file_size;
    std::string sha256;
    bool        in_whitelist;

    /* process (optional, on_access/memory only) */
    uint32_t    process_pid;
    std::string process_name;
    std::string process_exe;
};

struct QuarantinePayload {
    std::string action;          /* quarantined, restored, deleted */
    std::string vault_id;
    std::string original_path;
    bool        restore_available;
    std::string sig_name;
    std::string sig_id;
    std::string file_name;
    uint64_t    file_size;
    std::string sha256;
};

struct RealtimeBlockPayload {
    std::string operation;       /* file_create, file_write, ... */
    bool        denied;
    std::string sig_name;
    std::string sig_id;
    std::string file_path;
    std::string file_name;
    uint64_t    file_size;
    std::string sha256;
    uint32_t    process_pid;
    std::string process_name;
    std::string process_exe;
};

struct SignatureUpdatePayload {
    std::string previous_version;
    std::string new_version;
    uint64_t    signature_count;
    uint64_t    delta_added;
    uint64_t    delta_removed;
    std::string update_source;
    std::string verification;    /* rsa_verified, unsigned, ... */
};

struct ScanErrorPayload {
    std::string reason;          /* timeout, parser_crash, resource_limit */
    std::string detail;
    std::string stage;           /* pe_parser, zip_parser, ... */
    std::string file_path;
    std::string file_name;
    uint64_t    file_size;
};

/* ---- Serialization functions ----------------------------------------- */

/* Each function fills an akav_siem_event_t with the common envelope
 * (event_id, timestamp, source_type, agent_id) and the JSON payload. */

void serialize_scan_result(const ScanResultPayload& p, akav_siem_event_t* out);
void serialize_quarantine(const QuarantinePayload& p, akav_siem_event_t* out);
void serialize_realtime_block(const RealtimeBlockPayload& p, akav_siem_event_t* out);
void serialize_signature_update(const SignatureUpdatePayload& p, akav_siem_event_t* out);
void serialize_scan_error(const ScanErrorPayload& p, akav_siem_event_t* out);

/* ---- Utility --------------------------------------------------------- */

/* Generate a UUID v4 string (uses BCryptGenRandom). */
std::string generate_uuid_v4();

/* Get ISO 8601 timestamp with milliseconds: "2026-03-14T15:30:00.456Z" */
std::string iso8601_now();

/* Get local hostname. */
std::string get_hostname();

} /* namespace akav */

#endif /* AKAV_EVENT_SERIALIZE_H */
