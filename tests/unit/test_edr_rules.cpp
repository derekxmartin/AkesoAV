/* test_edr_rules.cpp -- Tests for EDR YAML detection rules.
 *
 * Tests:
 *   1. Load rules from YAML file
 *   2. Rule 1: Malware dropped by Office app → fires
 *   3. Rule 1: Clean file from Office → does NOT fire
 *   4. Rule 1: Malware from non-Office → does NOT fire
 *   5. Rule 2: Heuristic suspicious from browser → fires
 *   6. Rule 2: Low score from browser → does NOT fire
 *   7. Rule 2: High score from non-browser → does NOT fire
 *   8. Rule 3: AV match + process injection → fires
 *   9. Rule 3: AV match + local thread (not remote) → does NOT fire
 *  10. Rule 3: Clean process + remote thread → does NOT fire
 *  11. Rule 4: AV-detected file executed → fires
 *  12. Rule 5: Packed PE with high heuristic → fires
 *  13. No false positives: clean baseline event
 *  14. Multiple rules can match same event
 *  15. Load rules from string
 *  16. Case-insensitive process name matching
 */

#include <gtest/gtest.h>

#include "rule_evaluator.h"

#include <string>

/* ── Helpers ───────────────────────────────────────────────────── */

static TelemetryEvent make_event()
{
    TelemetryEvent e{};
    e.event_type = "";
    e.process_name = "";
    e.parent_name = "";
    e.file_path = "";
    e.remote = false;
    e.av_detected = false;
    e.av_malware_name = "";
    e.av_signature_id = "";
    e.av_scanner_id = "";
    e.av_file_type = "";
    e.av_heuristic_score = 0.0;
    e.av_scan_cached = false;
    return e;
}

/* Path to YAML rules file (relative to working dir = source root) */
static const char* RULES_PATH = "rules/av_enhanced_detection.yaml";

/* ── Test fixture ──────────────────────────────────────────────── */

class EdrRulesTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(eval_.load_rules(RULES_PATH))
            << "Failed to load rules from " << RULES_PATH;
    }

    RuleEvaluator eval_;
};

/* ── Rule loading ──────────────────────────────────────────────── */

TEST_F(EdrRulesTest, LoadRulesFromFile)
{
    EXPECT_GE(eval_.rule_count(), 5u);

    /* Verify expected rule IDs exist */
    bool found_001 = false, found_002 = false, found_003 = false;
    for (const auto& rule : eval_.rules()) {
        if (rule.id == "AV-EDR-001") found_001 = true;
        if (rule.id == "AV-EDR-002") found_002 = true;
        if (rule.id == "AV-EDR-003") found_003 = true;
    }
    EXPECT_TRUE(found_001) << "Missing AV-EDR-001";
    EXPECT_TRUE(found_002) << "Missing AV-EDR-002";
    EXPECT_TRUE(found_003) << "Missing AV-EDR-003";
}

TEST_F(EdrRulesTest, RuleMetadataCorrect)
{
    const auto& rules = eval_.rules();
    const DetectionRule* r001 = nullptr;
    for (const auto& r : rules) {
        if (r.id == "AV-EDR-001") r001 = &r;
    }
    ASSERT_NE(r001, nullptr);

    EXPECT_EQ(r001->name, "Malware dropped by Office application");
    EXPECT_EQ(r001->severity, "critical");
    EXPECT_EQ(r001->action, "alert");
    EXPECT_FALSE(r001->mitre.empty());
    EXPECT_FALSE(r001->tags.empty());
    EXPECT_GE(r001->conditions.size(), 3u);
}

/* ── Rule 1: Malware dropped by Office app ─────────────────────── */

TEST_F(EdrRulesTest, Rule1_MalwareFromOffice_Fires)
{
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "WINWORD.EXE";
    e.av_detected = true;
    e.av_malware_name = "Win32.Trojan.Emotet";
    e.file_path = "C:\\Users\\test\\AppData\\Local\\Temp\\payload.exe";

    auto matches = eval_.evaluate(e);
    bool fired = false;
    for (const auto& m : matches) {
        if (m.rule_id == "AV-EDR-001") fired = true;
    }
    EXPECT_TRUE(fired) << "AV-EDR-001 should fire for malware dropped by Word";
    if (fired) {
        for (const auto& m : matches) {
            if (m.rule_id == "AV-EDR-001") {
                EXPECT_EQ(m.severity, "critical");
                EXPECT_EQ(m.action, "alert");
            }
        }
    }
}

TEST_F(EdrRulesTest, Rule1_CleanFileFromOffice_NoFire)
{
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "EXCEL.EXE";
    e.av_detected = false;  /* Clean file */
    e.file_path = "C:\\Users\\test\\Documents\\report.xlsx";

    auto matches = eval_.evaluate(e);
    for (const auto& m : matches) {
        EXPECT_NE(m.rule_id, "AV-EDR-001")
            << "AV-EDR-001 should NOT fire for clean file from Office";
    }
}

TEST_F(EdrRulesTest, Rule1_MalwareFromNonOffice_NoFire)
{
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "cmd.exe";  /* Not an Office app */
    e.av_detected = true;

    auto matches = eval_.evaluate(e);
    for (const auto& m : matches) {
        EXPECT_NE(m.rule_id, "AV-EDR-001")
            << "AV-EDR-001 should NOT fire for malware from cmd.exe";
    }
}

/* ── Rule 2: Heuristic suspicious from browser ─────────────────── */

TEST_F(EdrRulesTest, Rule2_HighScoreFromBrowser_Fires)
{
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "chrome.exe";
    e.av_heuristic_score = 75.0;
    e.file_path = "C:\\Users\\test\\Downloads\\setup.exe";

    auto matches = eval_.evaluate(e);
    bool fired = false;
    for (const auto& m : matches) {
        if (m.rule_id == "AV-EDR-002") fired = true;
    }
    EXPECT_TRUE(fired) << "AV-EDR-002 should fire for heuristic score >50 from browser";
}

TEST_F(EdrRulesTest, Rule2_LowScoreFromBrowser_NoFire)
{
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "msedge.exe";
    e.av_heuristic_score = 30.0;  /* Below threshold */

    auto matches = eval_.evaluate(e);
    for (const auto& m : matches) {
        EXPECT_NE(m.rule_id, "AV-EDR-002")
            << "AV-EDR-002 should NOT fire for score=30";
    }
}

TEST_F(EdrRulesTest, Rule2_HighScoreFromNonBrowser_NoFire)
{
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "explorer.exe";  /* Not a browser */
    e.av_heuristic_score = 90.0;

    auto matches = eval_.evaluate(e);
    for (const auto& m : matches) {
        EXPECT_NE(m.rule_id, "AV-EDR-002")
            << "AV-EDR-002 should NOT fire for non-browser parent";
    }
}

/* ── Rule 3: AV match + process injection ──────────────────────── */

TEST_F(EdrRulesTest, Rule3_AVMatchWithInjection_Fires)
{
    auto e = make_event();
    e.event_type = "thread_create";
    e.remote = true;
    e.av_detected = true;
    e.av_malware_name = "Win32.Trojan.Cobalt";
    e.process_name = "svchost.exe";

    auto matches = eval_.evaluate(e);
    bool fired = false;
    for (const auto& m : matches) {
        if (m.rule_id == "AV-EDR-003") fired = true;
    }
    EXPECT_TRUE(fired) << "AV-EDR-003 should fire for AV match + remote thread";
}

TEST_F(EdrRulesTest, Rule3_AVMatchLocalThread_NoFire)
{
    auto e = make_event();
    e.event_type = "thread_create";
    e.remote = false;  /* Not remote */
    e.av_detected = true;

    auto matches = eval_.evaluate(e);
    for (const auto& m : matches) {
        EXPECT_NE(m.rule_id, "AV-EDR-003")
            << "AV-EDR-003 should NOT fire for local thread";
    }
}

TEST_F(EdrRulesTest, Rule3_CleanProcessRemoteThread_NoFire)
{
    auto e = make_event();
    e.event_type = "thread_create";
    e.remote = true;
    e.av_detected = false;  /* Clean */

    auto matches = eval_.evaluate(e);
    for (const auto& m : matches) {
        EXPECT_NE(m.rule_id, "AV-EDR-003")
            << "AV-EDR-003 should NOT fire for clean + remote thread";
    }
}

/* ── Rule 4: AV-detected file executed ─────────────────────────── */

TEST_F(EdrRulesTest, Rule4_AVDetectedExecuted_Fires)
{
    auto e = make_event();
    e.event_type = "process_create";
    e.av_detected = true;
    e.av_malware_name = "Win32.Backdoor.Shell";
    e.process_name = "payload.exe";

    auto matches = eval_.evaluate(e);
    bool fired = false;
    for (const auto& m : matches) {
        if (m.rule_id == "AV-EDR-004") fired = true;
    }
    EXPECT_TRUE(fired) << "AV-EDR-004 should fire for AV-detected process execution";
}

/* ── Rule 5: Packed PE with high heuristic ─────────────────────── */

TEST_F(EdrRulesTest, Rule5_PackedPEHighHeuristic_Fires)
{
    auto e = make_event();
    e.event_type = "file_create";
    e.av_heuristic_score = 85.0;
    e.av_file_type = "PE32";
    e.av_scanner_id = "heuristic";

    auto matches = eval_.evaluate(e);
    bool fired = false;
    for (const auto& m : matches) {
        if (m.rule_id == "AV-EDR-005") fired = true;
    }
    EXPECT_TRUE(fired) << "AV-EDR-005 should fire for packed PE with score>75";
}

/* ── No false positives: clean baseline ────────────────────────── */

TEST_F(EdrRulesTest, CleanBaselineNoFalsePositives)
{
    /* Normal file creation by explorer — no AV detection */
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "explorer.exe";
    e.file_path = "C:\\Users\\test\\Desktop\\document.docx";
    e.av_detected = false;
    e.av_heuristic_score = 0.0;

    auto matches = eval_.evaluate(e);
    EXPECT_TRUE(matches.empty())
        << "Expected no rule matches for clean baseline event, got "
        << matches.size() << " match(es)";
}

TEST_F(EdrRulesTest, CleanBaselineProcessCreate)
{
    auto e = make_event();
    e.event_type = "process_create";
    e.process_name = "notepad.exe";
    e.av_detected = false;
    e.av_heuristic_score = 0.0;

    auto matches = eval_.evaluate(e);
    EXPECT_TRUE(matches.empty());
}

TEST_F(EdrRulesTest, CleanBaselineThreadCreate)
{
    auto e = make_event();
    e.event_type = "thread_create";
    e.remote = false;
    e.av_detected = false;

    auto matches = eval_.evaluate(e);
    EXPECT_TRUE(matches.empty());
}

/* ── Multiple rules match ──────────────────────────────────────── */

TEST_F(EdrRulesTest, MultipleRulesCanMatch)
{
    /* AV-detected file from Office that also has high heuristic from browser
     * can't match both Rule 1 and Rule 2 (different parent types).
     * But Rule 4 (process_create + av_detected) should match its own event. */

    /* Let's make an event that matches Rule 5 (packed PE heuristic)
     * — it could also match others if conditions overlap */
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "chrome.exe";
    e.av_detected = true;
    e.av_heuristic_score = 85.0;
    e.av_file_type = "PE32";
    e.av_scanner_id = "heuristic";

    auto matches = eval_.evaluate(e);
    /* Should match: AV-EDR-002 (browser + score>50) and AV-EDR-005 (PE + score>75 + heuristic) */
    EXPECT_GE(matches.size(), 2u)
        << "Expected at least 2 rule matches for overlapping event";

    bool got_002 = false, got_005 = false;
    for (const auto& m : matches) {
        if (m.rule_id == "AV-EDR-002") got_002 = true;
        if (m.rule_id == "AV-EDR-005") got_005 = true;
    }
    EXPECT_TRUE(got_002);
    EXPECT_TRUE(got_005);
}

/* ── Case-insensitive process matching ─────────────────────────── */

TEST_F(EdrRulesTest, CaseInsensitiveProcessName)
{
    auto e = make_event();
    e.event_type = "file_create";
    e.parent_name = "winword.exe";  /* lowercase */
    e.av_detected = true;

    auto matches = eval_.evaluate(e);
    bool fired = false;
    for (const auto& m : matches) {
        if (m.rule_id == "AV-EDR-001") fired = true;
    }
    EXPECT_TRUE(fired) << "Should match case-insensitively";
}

/* ── Load from string ──────────────────────────────────────────── */

TEST(EdrRulesStringTest, LoadFromString)
{
    RuleEvaluator eval;
    std::string yaml = R"(
- id: TEST-001
  name: "Test rule"
  severity: high
  conditions:
    - field: event_type
      op: eq
      value: "test_event"
    - field: av_detected
      op: eq
      value: true
  action: alert
  tags:
    - test
)";

    ASSERT_TRUE(eval.load_rules_from_string(yaml));
    EXPECT_EQ(eval.rule_count(), 1u);

    auto e = make_event();
    e.event_type = "test_event";
    e.av_detected = true;

    auto matches = eval.evaluate(e);
    ASSERT_EQ(matches.size(), 1u);
    EXPECT_EQ(matches[0].rule_id, "TEST-001");
}
