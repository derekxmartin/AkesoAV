/* cron_parser.h -- Cron expression parser for scheduled scanning.
 *
 * Supports standard 5-field cron: minute hour day month weekday
 *   - Wildcards (*)
 *   - Lists (1,3,5)
 *   - Ranges (1-5)
 *   - Step values (star/15, 1-30/5)
 *
 * Example: "0 2 * * 0" = Sunday at 02:00
 */

#ifndef AKAV_CRON_PARSER_H
#define AKAV_CRON_PARSER_H

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>

namespace akav {

struct CronExpression {
    /* Bitmask arrays for each field. Bit N set = value N is valid. */
    uint64_t minutes;    /* 0-59 */
    uint64_t hours;      /* 0-23 */
    uint32_t days;       /* 1-31 (bit 0 unused) */
    uint16_t months;     /* 1-12 (bit 0 unused) */
    uint8_t  weekdays;   /* 0-6 (0=Sunday) */
    bool     valid;
};

/* Parse a cron expression string.
 * Returns a CronExpression with valid=true on success. */
CronExpression cron_parse(const std::string& expr);

/* Given a time_t, find the next time the cron expression matches.
 * Returns 0 on error (no match within 1 year). */
time_t cron_next(const CronExpression& cron, time_t after);

/* Format a time_t as a human-readable string (local time). */
std::string format_time(time_t t);

} /* namespace akav */

#endif /* AKAV_CRON_PARSER_H */
