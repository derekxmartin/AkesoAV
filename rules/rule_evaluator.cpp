/* rule_evaluator.cpp -- YAML rule evaluator implementation.
 *
 * Simple line-by-line YAML parser for the rule format defined in
 * av_enhanced_detection.yaml. No external YAML library dependency.
 */

#include "rule_evaluator.h"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>

/* ── String utilities ──────────────────────────────────────────── */

static std::string trim(const std::string& s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string unquote(const std::string& s)
{
    std::string t = trim(s);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"')
        return t.substr(1, t.size() - 2);
    if (t.size() >= 2 && t.front() == '\'' && t.back() == '\'')
        return t.substr(1, t.size() - 2);
    return t;
}

static std::string to_upper(const std::string& s)
{
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return (char)toupper(c); });
    return r;
}

static int indent_level(const std::string& line)
{
    int n = 0;
    for (char c : line) {
        if (c == ' ') n++;
        else break;
    }
    return n;
}

/* ── YAML parser ───────────────────────────────────────────────── */

bool RuleEvaluator::load_rules(const char* yaml_path)
{
    std::ifstream file(yaml_path);
    if (!file.is_open()) {
        fprintf(stderr, "[rule_evaluator] Cannot open '%s'\n", yaml_path);
        return false;
    }

    std::stringstream ss;
    ss << file.rdbuf();
    return parse_yaml(ss.str());
}

bool RuleEvaluator::load_rules_from_string(const std::string& yaml_content)
{
    return parse_yaml(yaml_content);
}

bool RuleEvaluator::parse_yaml(const std::string& content)
{
    rules_.clear();

    std::istringstream stream(content);
    std::string line;

    DetectionRule current;
    bool in_rule = false;
    bool in_conditions = false;
    bool in_mitre = false;
    bool in_tags = false;
    bool in_values = false;

    RuleCondition current_cond;

    auto finish_condition = [&]() {
        if (!current_cond.field.empty()) {
            current.conditions.push_back(current_cond);
            current_cond = {};
        }
    };

    auto finish_rule = [&]() {
        finish_condition();
        if (!current.id.empty()) {
            rules_.push_back(current);
        }
        current = {};
        in_conditions = false;
        in_mitre = false;
        in_tags = false;
        in_values = false;
    };

    while (std::getline(stream, line)) {
        /* Skip empty lines and comments */
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        /* Document separator — start of new rule */
        if (trimmed == "---") {
            if (in_rule)
                finish_rule();
            in_rule = false;
            continue;
        }

        int indent = indent_level(line);

        /* New rule starts with "- id:" */
        if (trimmed.substr(0, 5) == "- id:") {
            if (in_rule)
                finish_rule();
            in_rule = true;
            in_conditions = false;
            in_mitre = false;
            in_tags = false;
            in_values = false;
            current.id = unquote(trimmed.substr(5));
            continue;
        }

        if (!in_rule) continue;

        /* Top-level rule fields (indent 2) */
        if (indent == 2 || (indent >= 2 && !in_conditions && !in_mitre &&
                            !in_tags && !in_values)) {
            /* Close any open sub-context */
            if (in_values) {
                finish_condition();
                in_values = false;
            }

            /* Check for known top-level keys */
            if (trimmed.substr(0, 5) == "name:") {
                in_conditions = false; in_mitre = false; in_tags = false;
                current.name = unquote(trimmed.substr(5));
            } else if (trimmed.substr(0, 12) == "description:") {
                in_conditions = false; in_mitre = false; in_tags = false;
                std::string val = trim(trimmed.substr(12));
                if (val == ">" || val == "|") {
                    /* Multiline — collect until next key */
                    current.description = "";
                } else {
                    current.description = unquote(val);
                }
            } else if (trimmed.substr(0, 9) == "severity:") {
                in_conditions = false; in_mitre = false; in_tags = false;
                current.severity = unquote(trimmed.substr(9));
            } else if (trimmed.substr(0, 6) == "mitre:") {
                in_conditions = false; in_mitre = true; in_tags = false;
            } else if (trimmed.substr(0, 11) == "conditions:") {
                in_conditions = true; in_mitre = false; in_tags = false;
            } else if (trimmed.substr(0, 7) == "action:") {
                in_conditions = false; in_mitre = false; in_tags = false;
                finish_condition();
                current.action = unquote(trimmed.substr(7));
            } else if (trimmed.substr(0, 5) == "tags:") {
                in_conditions = false; in_mitre = false; in_tags = true;
                finish_condition();
            }
            continue;
        }

        /* MITRE list items */
        if (in_mitre && trimmed[0] == '-') {
            std::string val = trim(trimmed.substr(1));
            /* Remove inline comment */
            auto hash = val.find('#');
            if (hash != std::string::npos)
                val = trim(val.substr(0, hash));
            current.mitre.push_back(unquote(val));
            continue;
        }

        /* Tags list items */
        if (in_tags && trimmed[0] == '-') {
            current.tags.push_back(unquote(trim(trimmed.substr(1))));
            continue;
        }

        /* Conditions parsing */
        if (in_conditions) {
            /* New condition starts with "- field:" */
            if (trimmed.substr(0, 8) == "- field:") {
                finish_condition();
                in_values = false;
                current_cond.field = unquote(trimmed.substr(8));
                continue;
            }

            /* Condition sub-fields */
            if (trimmed.substr(0, 3) == "op:") {
                current_cond.op = unquote(trimmed.substr(3));
                continue;
            }

            if (trimmed.substr(0, 6) == "value:") {
                std::string val = trim(trimmed.substr(6));
                /* Determine type */
                if (val == "true") {
                    current_cond.value = true;
                } else if (val == "false") {
                    current_cond.value = false;
                } else {
                    /* Try as number */
                    char* end = nullptr;
                    double d = strtod(val.c_str(), &end);
                    if (end != val.c_str() && *end == '\0') {
                        current_cond.value = d;
                    } else {
                        current_cond.value = unquote(val);
                    }
                }
                continue;
            }

            if (trimmed.substr(0, 7) == "values:") {
                in_values = true;
                continue;
            }

            /* Values list items */
            if (in_values && trimmed[0] == '-') {
                current_cond.values.push_back(unquote(trim(trimmed.substr(1))));
                continue;
            }
        }
    }

    /* Finish last rule */
    if (in_rule)
        finish_rule();

    return !rules_.empty();
}

/* ── Evaluation ────────────────────────────────────────────────── */

std::vector<RuleMatch> RuleEvaluator::evaluate(const TelemetryEvent& event) const
{
    std::vector<RuleMatch> matches;

    for (const auto& rule : rules_) {
        bool all_match = true;

        for (const auto& cond : rule.conditions) {
            if (!evaluate_condition(cond, event)) {
                all_match = false;
                break;
            }
        }

        if (all_match) {
            RuleMatch m;
            m.rule_id = rule.id;
            m.rule_name = rule.name;
            m.severity = rule.severity;
            m.action = rule.action;
            matches.push_back(m);
        }
    }

    return matches;
}

/* ── Field accessors ───────────────────────────────────────────── */

std::string RuleEvaluator::get_string_field(const TelemetryEvent& event,
                                             const std::string& field)
{
    if (field == "event_type")       return event.event_type;
    if (field == "process_name")     return event.process_name;
    if (field == "parent_name")      return event.parent_name;
    if (field == "file_path")        return event.file_path;
    if (field == "av_malware_name")  return event.av_malware_name;
    if (field == "av_signature_id")  return event.av_signature_id;
    if (field == "av_scanner_id")    return event.av_scanner_id;
    if (field == "av_file_type")     return event.av_file_type;
    return "";
}

double RuleEvaluator::get_double_field(const TelemetryEvent& event,
                                        const std::string& field)
{
    if (field == "av_heuristic_score") return event.av_heuristic_score;
    return 0.0;
}

bool RuleEvaluator::get_bool_field(const TelemetryEvent& event,
                                    const std::string& field)
{
    if (field == "av_detected")    return event.av_detected;
    if (field == "av_scan_cached") return event.av_scan_cached;
    if (field == "remote")         return event.remote;
    return false;
}

/* ── Condition evaluation ──────────────────────────────────────── */

bool RuleEvaluator::evaluate_condition(const RuleCondition& cond,
                                        const TelemetryEvent& event)
{
    if (cond.op == "eq") {
        if (std::holds_alternative<bool>(cond.value)) {
            return get_bool_field(event, cond.field) == std::get<bool>(cond.value);
        }
        if (std::holds_alternative<double>(cond.value)) {
            return get_double_field(event, cond.field) == std::get<double>(cond.value);
        }
        /* String comparison */
        return get_string_field(event, cond.field) == std::get<std::string>(cond.value);
    }

    if (cond.op == "in") {
        /* Case-insensitive match for process names */
        std::string val = to_upper(get_string_field(event, cond.field));
        for (const auto& v : cond.values) {
            if (to_upper(v) == val)
                return true;
        }
        return false;
    }

    if (cond.op == "gt") {
        double field_val = get_double_field(event, cond.field);
        double cond_val = std::holds_alternative<double>(cond.value)
                          ? std::get<double>(cond.value) : 0.0;
        return field_val > cond_val;
    }

    if (cond.op == "gte") {
        double field_val = get_double_field(event, cond.field);
        double cond_val = std::holds_alternative<double>(cond.value)
                          ? std::get<double>(cond.value) : 0.0;
        return field_val >= cond_val;
    }

    if (cond.op == "lt") {
        double field_val = get_double_field(event, cond.field);
        double cond_val = std::holds_alternative<double>(cond.value)
                          ? std::get<double>(cond.value) : 0.0;
        return field_val < cond_val;
    }

    if (cond.op == "lte") {
        double field_val = get_double_field(event, cond.field);
        double cond_val = std::holds_alternative<double>(cond.value)
                          ? std::get<double>(cond.value) : 0.0;
        return field_val <= cond_val;
    }

    return false;
}
