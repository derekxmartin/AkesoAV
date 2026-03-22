/* rule_evaluator.h -- YAML rule evaluator for AV+EDR detection rules.
 *
 * Loads Sigma-style YAML rules from av_enhanced_detection.yaml and
 * evaluates them against telemetry events. This is a lightweight
 * evaluator for the AkesoAV side of the integration — the full EDR
 * rule engine lives in the AkesoEDR project.
 *
 * The evaluator supports:
 *   - String equality (eq)
 *   - String set membership (in)
 *   - Numeric comparison (gt, gte, lt, lte)
 *   - Boolean equality (eq with true/false)
 *   - AND logic across all conditions in a rule
 */

#ifndef AKESOAV_RULE_EVALUATOR_H
#define AKESOAV_RULE_EVALUATOR_H

#include <string>
#include <vector>
#include <map>
#include <variant>

/* ── Telemetry event (combined EDR + AV fields) ───────────────── */

struct TelemetryEvent {
    /* EDR fields */
    std::string event_type;     /* file_create, process_create, thread_create */
    std::string process_name;   /* Name of the process */
    std::string parent_name;    /* Parent process name */
    std::string file_path;      /* File path involved */
    bool        remote;         /* For thread_create: remote injection? */

    /* AV fields (per §3.6) */
    bool        av_detected;
    std::string av_malware_name;
    std::string av_signature_id;
    std::string av_scanner_id;
    std::string av_file_type;
    double      av_heuristic_score;
    bool        av_scan_cached;
};

/* ── Rule structures ───────────────────────────────────────────── */

struct RuleCondition {
    std::string              field;
    std::string              op;      /* eq, in, gt, gte, lt, lte */
    /* Value can be string, double, or bool */
    std::variant<std::string, double, bool> value;
    std::vector<std::string> values;  /* For "in" operator */
};

struct DetectionRule {
    std::string                id;
    std::string                name;
    std::string                description;
    std::string                severity;   /* low, medium, high, critical */
    std::vector<std::string>   mitre;
    std::vector<RuleCondition> conditions;
    std::string                action;     /* alert, block, log */
    std::vector<std::string>   tags;
};

struct RuleMatch {
    std::string rule_id;
    std::string rule_name;
    std::string severity;
    std::string action;
};

/* ── Rule evaluator ────────────────────────────────────────────── */

class RuleEvaluator {
public:
    RuleEvaluator() = default;

    /* Load rules from a YAML file.
     * Returns true if at least one rule was loaded. */
    bool load_rules(const char* yaml_path);

    /* Load rules from a YAML string (for testing). */
    bool load_rules_from_string(const std::string& yaml_content);

    /* Evaluate all rules against an event.
     * Returns list of matching rules. */
    std::vector<RuleMatch> evaluate(const TelemetryEvent& event) const;

    /* Get loaded rules count. */
    size_t rule_count() const { return rules_.size(); }

    /* Get all loaded rules. */
    const std::vector<DetectionRule>& rules() const { return rules_; }

private:
    std::vector<DetectionRule> rules_;

    /* Parse a single YAML document into rules.
     * Uses a simple line-by-line parser (no external YAML library). */
    bool parse_yaml(const std::string& content);

    /* Evaluate a single condition against an event. */
    static bool evaluate_condition(const RuleCondition& cond,
                                   const TelemetryEvent& event);

    /* Get a field value from the event as a string. */
    static std::string get_string_field(const TelemetryEvent& event,
                                        const std::string& field);

    /* Get a field value from the event as a double. */
    static double get_double_field(const TelemetryEvent& event,
                                   const std::string& field);

    /* Get a field value from the event as a bool. */
    static bool get_bool_field(const TelemetryEvent& event,
                               const std::string& field);
};

#endif /* AKESOAV_RULE_EVALUATOR_H */
