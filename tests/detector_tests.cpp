#include "detector.h"

#ifdef USE_STANDALONE_TEST_RUNNER
#include <iostream>
#include <vector>
#include <functional>
#include <string>

struct TestCase {
    std::string suite;
    std::string name;
    std::function<void()> func;
};

static std::vector<TestCase>& get_tests() {
    static std::vector<TestCase> tests;
    return tests;
}

static int g_test_failures = 0;

#define TEST(Suite, Name) \
    void Suite##_##Name(); \
    static bool Suite##_##Name##_registered = []() { \
        get_tests().push_back({#Suite, #Name, Suite##_##Name}); \
        return true; \
    }(); \
    void Suite##_##Name()

#define EXPECT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "  FAILED: " << #cond << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
            g_test_failures++; \
        } \
    } while (0)

#define EXPECT_FALSE(cond) EXPECT_TRUE(!(cond))

#define EXPECT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            std::cerr << "  FAILED: " << #a << " == " << #b << " (got " << (a) << " vs " << (b) << ") at " \
                      << __FILE__ << ":" << __LINE__ << "\n"; \
            g_test_failures++; \
        } \
    } while (0)

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "  ASSERT FAILED: " << #cond << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
            g_test_failures++; \
            return; \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            std::cerr << "  ASSERT FAILED: " << #a << " == " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
            g_test_failures++; \
            return; \
        } \
    } while (0)

#else
#include <gtest/gtest.h>
#endif

#include <sstream>

// 1. IP Validation Tests
TEST(ValidationTest, IPv4Validation) {
    EXPECT_TRUE(authtrace::AuthDetector::is_valid_ipv4("192.168.1.1"));
    EXPECT_TRUE(authtrace::AuthDetector::is_valid_ipv4("10.0.0.1"));
    EXPECT_TRUE(authtrace::AuthDetector::is_valid_ipv4("255.255.255.255"));
    EXPECT_TRUE(authtrace::AuthDetector::is_valid_ipv4("0.0.0.0"));

    EXPECT_FALSE(authtrace::AuthDetector::is_valid_ipv4("256.0.0.1"));
    EXPECT_FALSE(authtrace::AuthDetector::is_valid_ipv4("192.168.01.1")); // Leading zero rejected
    EXPECT_FALSE(authtrace::AuthDetector::is_valid_ipv4("192.168.1"));     // Only 3 octets
    EXPECT_FALSE(authtrace::AuthDetector::is_valid_ipv4("192.168.1.1.1")); // 5 octets
    EXPECT_FALSE(authtrace::AuthDetector::is_valid_ipv4("invalid_ip"));
}

TEST(ValidationTest, IPv6Validation) {
    EXPECT_TRUE(authtrace::AuthDetector::is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    EXPECT_TRUE(authtrace::AuthDetector::is_valid_ipv6("2001:db8:85a3::8a2e:370:7334"));
    EXPECT_TRUE(authtrace::AuthDetector::is_valid_ipv6("::1"));
    EXPECT_TRUE(authtrace::AuthDetector::is_valid_ipv6("fe80::1"));

    EXPECT_FALSE(authtrace::AuthDetector::is_valid_ipv6("2001::85a3::7334")); // Multiple :: rejected
    EXPECT_FALSE(authtrace::AuthDetector::is_valid_ipv6("2001:xyz::1"));       // Non-hex characters
    EXPECT_FALSE(authtrace::AuthDetector::is_valid_ipv6(""));
}

// 2. Timestamp Parsing Tests
TEST(ValidationTest, TimestampParsing) {
    auto epoch1 = authtrace::AuthDetector::parse_iso8601_to_epoch("2026-10-25T10:00:00Z");
    ASSERT_TRUE(epoch1.has_value());
    EXPECT_EQ(authtrace::AuthDetector::epoch_to_iso8601(epoch1.value()), "2026-10-25T10:00:00Z");

    auto epoch_subsecond = authtrace::AuthDetector::parse_iso8601_to_epoch("2026-10-25T10:00:00.123Z");
    ASSERT_TRUE(epoch_subsecond.has_value());
    EXPECT_EQ(epoch1.value(), epoch_subsecond.value());

    EXPECT_FALSE(authtrace::AuthDetector::parse_iso8601_to_epoch("2026-10-25 10:00:00").has_value());
    EXPECT_FALSE(authtrace::AuthDetector::parse_iso8601_to_epoch("invalid-time").has_value());
    EXPECT_FALSE(authtrace::AuthDetector::parse_iso8601_to_epoch("2026-02-30T10:00:00Z").has_value()); // Invalid day
}

// 3. Four Failures Do NOT Trigger Alert
TEST(DetectionTest, FourFailuresDoNotTriggerAlert) {
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:10Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:30Z,192.168.1.10,admin,FAILURE\n";

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.stats.total_records, 4u);
    EXPECT_EQ(result.stats.failure_count, 4u);
    EXPECT_EQ(result.alerts.size(), 0u);
}

// 4. Five Failures Within 60 Seconds Trigger Alert
TEST(DetectionTest, FiveFailuresWithin60sTriggerAlert) {
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:10Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:30Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:40Z,192.168.1.10,admin,FAILURE\n";

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.stats.total_records, 5u);
    EXPECT_EQ(result.alerts.size(), 1u);

    const auto& alert = result.alerts[0];
    EXPECT_EQ(alert.rule_id, "BRUTE_FORCE_SUSPECTED");
    EXPECT_EQ(alert.severity, "HIGH");
    EXPECT_EQ(alert.source_ip, "192.168.1.10");
    EXPECT_EQ(alert.failed_attempts, 5u);
    EXPECT_EQ(alert.window_seconds, 60);
    EXPECT_EQ(alert.detection_timestamp, "2026-10-25T10:00:40Z");
    EXPECT_EQ(alert.window_start_timestamp, "2026-10-25T10:00:00Z");
}

// 5. Failures Outside 60-Second Window Expire Correctly
TEST(DetectionTest, FailuresOutsideWindowExpire) {
    // 5 failures spaced 20s apart (spanning 80s: 0s, 20s, 40s, 60s, 80s)
    // At t=80s, the failures at 0s and 20s expire, so at most 3-4 failures in any 60s window
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:40Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:01:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:01:20Z,192.168.1.10,admin,FAILURE\n";

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.stats.total_records, 5u);
    EXPECT_EQ(result.alerts.size(), 0u);
}

// 6. Exact 60-Second Boundary (Inclusive) Behavior
TEST(DetectionTest, Exact60SecondBoundaryBehavior) {
    // Exactly 60 seconds from first to fifth failure (10:00:00 to 10:01:00) -> Triggers alert (inclusive)
    std::string csv_inclusive =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:10Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:30Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:01:00Z,192.168.1.10,admin,FAILURE\n";

    std::istringstream stream1(csv_inclusive);
    authtrace::AuthDetector detector1;
    auto result1 = detector1.analyze_stream(stream1);
    EXPECT_EQ(result1.alerts.size(), 1u);

    // 61 seconds from first to fifth failure (10:00:00 to 10:01:01) -> First event expires, only 4 remain
    std::string csv_exclusive =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:10Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:30Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:01:01Z,192.168.1.10,admin,FAILURE\n";

    std::istringstream stream2(csv_exclusive);
    authtrace::AuthDetector detector2;
    auto result2 = detector2.analyze_stream(stream2);
    EXPECT_EQ(result2.alerts.size(), 0u);
}

// 7. Multiple Source IPs Analyzed Independently
TEST(DetectionTest, MultipleSourceIPsAnalyzedIndependently) {
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,10.0.0.1,alice,FAILURE\n"
        "2026-10-25T10:00:05Z,10.0.0.2,bob,FAILURE\n"
        "2026-10-25T10:00:10Z,10.0.0.1,alice,FAILURE\n"
        "2026-10-25T10:00:15Z,10.0.0.2,bob,FAILURE\n"
        "2026-10-25T10:00:20Z,10.0.0.1,alice,FAILURE\n"
        "2026-10-25T10:00:25Z,10.0.0.2,bob,FAILURE\n"
        "2026-10-25T10:00:30Z,10.0.0.1,alice,FAILURE\n"
        "2026-10-25T10:00:35Z,10.0.0.2,bob,FAILURE\n"
        "2026-10-25T10:00:45Z,10.0.0.2,bob,FAILURE\n"; // 10.0.0.2 reaches 5 failures

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.stats.unique_ips, 2u);
    EXPECT_EQ(result.alerts.size(), 1u);
    EXPECT_EQ(result.alerts[0].source_ip, "10.0.0.2");
}

// 8. Successful Logins Do Not Count as Failures
TEST(DetectionTest, SuccessfulLoginsDoNotCountAsFailures) {
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:10Z,192.168.1.10,admin,SUCCESS\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:25Z,192.168.1.10,admin,SUCCESS\n"
        "2026-10-25T10:00:30Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:40Z,192.168.1.10,admin,FAILURE\n";

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.stats.total_records, 6u);
    EXPECT_EQ(result.stats.success_count, 2u);
    EXPECT_EQ(result.stats.failure_count, 4u);
    EXPECT_EQ(result.alerts.size(), 0u);
}

// 9. Out-of-Order Events Sorted Chronologically
TEST(DetectionTest, OutOfOrderEventsSorted) {
    // 5 failures provided in non-chronological order in the CSV
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:40Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:10Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:30Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n";

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.alerts.size(), 1u);
    EXPECT_EQ(result.alerts[0].window_start_timestamp, "2026-10-25T10:00:00Z");
    EXPECT_EQ(result.alerts[0].detection_timestamp, "2026-10-25T10:00:40Z");
}

// 10. Alert Suppression Prevents Redundant Alerts For Same Incident
TEST(DetectionTest, AlertSuppressionForSameEpisode) {
    // 7 failures from same IP in short succession
    // Fails 1..5 trigger Alert 1. Fails 6 and 7 must be suppressed.
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:05Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:10Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:15Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n" // Alert #1 triggers here
        "2026-10-25T10:00:25Z,192.168.1.10,admin,FAILURE\n" // Suppressed
        "2026-10-25T10:00:30Z,192.168.1.10,admin,FAILURE\n"; // Suppressed

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.stats.failure_count, 7u);
    EXPECT_EQ(result.alerts.size(), 1u); // Exactly 1 alert, no duplicates
}

// 11. Alert Reset After Episode Cooldown
TEST(DetectionTest, AlertResetAfterCooldown) {
    // Episode 1: 5 failures at t=0..40s (triggers Alert #1)
    // Cooldown: 120 seconds of silence (all old failures expire)
    // Episode 2: 5 failures at t=160..200s (triggers Alert #2)
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:10Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:30Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:00:40Z,192.168.1.10,admin,FAILURE\n" // Alert #1
        "2026-10-25T10:02:40Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:02:50Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:03:00Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:03:10Z,192.168.1.10,admin,FAILURE\n"
        "2026-10-25T10:03:20Z,192.168.1.10,admin,FAILURE\n"; // Alert #2

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.alerts.size(), 2u);
}

// 12. Malformed Input Handling
TEST(DetectionTest, MalformedInputGracefullyHandled) {
    std::string csv_data =
        "timestamp,source_ip,username,status\n"
        "2026-10-25T10:00:00Z,192.168.1.10,admin,FAILURE\n"
        "malformed_line_with_no_commas\n"
        "2026-10-25T10:00:10Z,not_an_ip,admin,FAILURE\n"
        "2026-10-25T10:00:20Z,192.168.1.10,,FAILURE\n" // Empty username
        "2026-10-25T10:00:30Z,192.168.1.10,admin,UNKNOWN_STATUS\n"
        "\n" // Blank line
        "2026-10-25T10:00:40Z,192.168.1.10,admin,SUCCESS\n";

    std::istringstream stream(csv_data);
    authtrace::AuthDetector detector;
    auto result = detector.analyze_stream(stream);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.stats.total_records, 6u);
    EXPECT_EQ(result.stats.valid_records, 2u);
    EXPECT_EQ(result.stats.invalid_records, 4u);
    EXPECT_EQ(result.warnings.size(), 4u);
}

#ifdef USE_STANDALONE_TEST_RUNNER
int main() {
    std::cout << "Running AuthTrace Unit Tests (Standalone Test Runner)...\n";
    int passed = 0;
    for (const auto& test : get_tests()) {
        int failures_before = g_test_failures;
        std::cout << "[ RUN      ] " << test.suite << "." << test.name << "\n";
        test.func();
        if (g_test_failures == failures_before) {
            std::cout << "[       OK ] " << test.suite << "." << test.name << "\n";
            passed++;
        } else {
            std::cout << "[  FAILED  ] " << test.suite << "." << test.name << "\n";
        }
    }

    std::cout << "\n==================================================\n";
    std::cout << "Test Summary: " << passed << " passed, "
              << (get_tests().size() - passed) << " failed out of "
              << get_tests().size() << " tests.\n";
    std::cout << "==================================================\n";

    return (g_test_failures == 0) ? 0 : 1;
}
#endif
