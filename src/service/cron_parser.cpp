/* cron_parser.cpp -- Cron expression parser implementation.
 *
 * Parses standard 5-field cron expressions and computes next trigger time.
 */

#include "service/cron_parser.h"

#include <cstring>
#include <cstdio>
#include <sstream>

namespace akav {

/* ---- Field parsing helpers ------------------------------------------- */

/* Parse a single field into a bitmask.
 * min/max define the valid range (e.g. 0-59 for minutes). */
static uint64_t parse_field(const std::string& field, int min_val, int max_val)
{
    uint64_t mask = 0;

    /* Split by comma for lists */
    std::istringstream ss(field);
    std::string token;

    while (std::getline(ss, token, ',')) {
        /* Check for step: */
        int step = 1;
        auto slash_pos = token.find('/');
        if (slash_pos != std::string::npos) {
            step = atoi(token.substr(slash_pos + 1).c_str());
            if (step <= 0) step = 1;
            token = token.substr(0, slash_pos);
        }

        if (token == "*") {
            /* Wildcard with optional step */
            for (int i = min_val; i <= max_val; i += step)
                mask |= (1ULL << i);
        } else {
            /* Check for range */
            auto dash_pos = token.find('-');
            if (dash_pos != std::string::npos) {
                int start = atoi(token.substr(0, dash_pos).c_str());
                int end = atoi(token.substr(dash_pos + 1).c_str());
                if (start < min_val) start = min_val;
                if (end > max_val) end = max_val;
                for (int i = start; i <= end; i += step)
                    mask |= (1ULL << i);
            } else {
                /* Single value */
                int val = atoi(token.c_str());
                if (val >= min_val && val <= max_val)
                    mask |= (1ULL << val);
            }
        }
    }

    return mask;
}

/* ---- Public API ------------------------------------------------------ */

CronExpression cron_parse(const std::string& expr)
{
    CronExpression cron{};
    cron.valid = false;

    /* Split into 5 fields */
    std::istringstream ss(expr);
    std::string fields[5];
    for (int i = 0; i < 5; ++i) {
        if (!(ss >> fields[i]))
            return cron; /* Not enough fields */
    }

    cron.minutes  = parse_field(fields[0], 0, 59);
    cron.hours    = parse_field(fields[1], 0, 23);
    cron.days     = (uint32_t)parse_field(fields[2], 1, 31);
    cron.months   = (uint16_t)parse_field(fields[3], 1, 12);
    cron.weekdays = (uint8_t)parse_field(fields[4], 0, 6);

    /* Validate at least one bit set in each field */
    if (cron.minutes == 0 || cron.hours == 0 || cron.days == 0 ||
        cron.months == 0 || cron.weekdays == 0)
        return cron;

    cron.valid = true;
    return cron;
}

time_t cron_next(const CronExpression& cron, time_t after)
{
    if (!cron.valid)
        return 0;

    struct tm tm_buf;
    localtime_s(&tm_buf, &after);

    /* Start from the next minute */
    tm_buf.tm_sec = 0;
    tm_buf.tm_min++;
    if (tm_buf.tm_min >= 60) {
        tm_buf.tm_min = 0;
        tm_buf.tm_hour++;
    }

    /* Search up to 366 days ahead */
    for (int iterations = 0; iterations < 366 * 24 * 60; ++iterations) {
        /* Normalize the time */
        time_t candidate = mktime(&tm_buf);
        if (candidate == (time_t)-1)
            return 0;
        localtime_s(&tm_buf, &candidate);

        /* Check month (1-12, tm_mon is 0-11) */
        int month = tm_buf.tm_mon + 1;
        if (!(cron.months & (1 << month))) {
            /* Advance to next month */
            tm_buf.tm_mon++;
            tm_buf.tm_mday = 1;
            tm_buf.tm_hour = 0;
            tm_buf.tm_min = 0;
            continue;
        }

        /* Check day (1-31) */
        if (!(cron.days & (1U << tm_buf.tm_mday))) {
            /* Advance to next day */
            tm_buf.tm_mday++;
            tm_buf.tm_hour = 0;
            tm_buf.tm_min = 0;
            continue;
        }

        /* Check weekday (0-6, 0=Sunday) */
        if (!(cron.weekdays & (1 << tm_buf.tm_wday))) {
            /* Advance to next day */
            tm_buf.tm_mday++;
            tm_buf.tm_hour = 0;
            tm_buf.tm_min = 0;
            continue;
        }

        /* Check hour (0-23) */
        if (!(cron.hours & (1ULL << tm_buf.tm_hour))) {
            /* Advance to next hour */
            tm_buf.tm_hour++;
            tm_buf.tm_min = 0;
            continue;
        }

        /* Check minute (0-59) */
        if (!(cron.minutes & (1ULL << tm_buf.tm_min))) {
            /* Advance to next minute */
            tm_buf.tm_min++;
            continue;
        }

        /* All fields match */
        return candidate;
    }

    return 0; /* No match within search window */
}

std::string format_time(time_t t)
{
    struct tm tm_buf;
    localtime_s(&tm_buf, &t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}

} /* namespace akav */
