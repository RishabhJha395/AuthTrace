#pragma once

#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <cstdint>
#include <optional>
#include <istream>
#include <nlohmann/json.hpp>

namespace authtrace {

enum class AuthStatus {
    SUCCESS,
    FAILURE,
    INVALID
};

struct AuthEvent {
    std::string timestamp_str;
    int64_t timestamp_epoch_sec = 0;
    std::string source_ip;
    std::string username;
    AuthStatus status = AuthStatus::INVALID;
    size_t line_number = 0;
};

struct Alert {
    std::string rule_id;
    std::string severity;
    std::string source_ip;
    size_t failed_attempts = 0;
    int64_t window_seconds = 0;
    std::string detection_timestamp;
    std::string window_start_timestamp;
    std::string message;
};

struct AnalysisStats {
    size_t total_records = 0;
    size_t valid_records = 0;
    size_t invalid_records = 0;
    size_t success_count = 0;
    size_t failure_count = 0;
    size_t unique_ips = 0;
    size_t alert_count = 0;
    double processing_time_ms = 0.0;
};

struct AnalysisResult {
    bool success = true;
    std::string error_message;
    AnalysisStats stats;
    std::vector<Alert> alerts;
    std::vector<std::string> warnings;

    // Convert result to nlohmann::json representation
    nlohmann::json to_json() const;
};

struct DetectorConfig {
    size_t failure_threshold = 5;       // Minimum failures to trigger alert
    int64_t window_seconds = 60;        // Rolling time window in seconds
    size_t max_warnings = 100;          // Maximum validation warnings retained
};

class AuthDetector {
public:
    explicit AuthDetector(DetectorConfig config = DetectorConfig{});

    // Parse and analyze input stream containing CSV records
    AnalysisResult analyze_stream(std::istream& input_stream);

    // Parse and analyze CSV file from disk
    AnalysisResult analyze_file(const std::string& file_path);

    // Analyze a pre-parsed and validated list of events
    AnalysisResult analyze_events(std::vector<AuthEvent>& events,
                                 size_t total_records,
                                 size_t invalid_records,
                                 std::vector<std::string> warnings);

    // Validation and conversion helpers
    static bool is_valid_ipv4(const std::string& ip);
    static bool is_valid_ipv6(const std::string& ip);
    static bool is_valid_ip(const std::string& ip);
    static std::optional<int64_t> parse_iso8601_to_epoch(const std::string& ts_str);
    static std::string epoch_to_iso8601(int64_t epoch_sec);
    static AuthStatus parse_status(const std::string& status_str);
    static std::string status_to_string(AuthStatus status);

private:
    DetectorConfig config_;

    // Per-IP state tracking for the sliding window
    struct IpTracker {
        std::deque<int64_t> failure_timestamps;
        bool in_alert_state = false;
    };
};

} // namespace authtrace
