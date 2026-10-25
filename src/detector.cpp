#include "detector.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <unordered_set>
#include <iomanip>
#include <cctype>

namespace authtrace {

namespace {

// Trim leading and trailing whitespace, carriage returns, and newlines
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// Case-insensitive comparison for ASCII strings
bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

// Split a CSV row while respecting quoted fields
std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string current;
    bool in_quotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') {
            if (in_quotes && i + 1 < line.size() && line[i + 1] == '"') {
                // Escaped double quote ("")
                current += '"';
                ++i;
            } else {
                in_quotes = !in_quotes;
            }
        } else if (c == ',' && !in_quotes) {
            fields.push_back(trim(current));
            current.clear();
        } else {
            current += c;
        }
    }
    fields.push_back(trim(current));
    return fields;
}

// Howard Hinnant's civil date algorithm to compute days since 1970-01-01
int64_t days_from_civil(int y, unsigned m, unsigned d) noexcept {
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

// Reverse civil date algorithm: epoch days to YYYY-MM-DD
void civil_from_days(int64_t z, int& y, unsigned& m, unsigned& d) noexcept {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int y_tmp = static_cast<int>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y = y_tmp + (m <= 2);
}

bool is_leap_year(int y) {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

unsigned days_in_month(int y, unsigned m) {
    static const unsigned dpm[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m < 1 || m > 12) return 0;
    if (m == 2 && is_leap_year(y)) return 29;
    return dpm[m - 1];
}

} // anonymous namespace

AuthDetector::AuthDetector(DetectorConfig config)
    : config_(config) {}

bool AuthDetector::is_valid_ipv4(const std::string& ip) {
    if (ip.empty() || ip.size() > 15) {
        return false;
    }

    size_t start = 0;
    int octet_count = 0;

    for (size_t i = 0; i <= ip.size(); ++i) {
        if (i == ip.size() || ip[i] == '.') {
            if (i == start) {
                return false; // Empty octet
            }
            size_t len = i - start;
            if (len > 3) {
                return false;
            }

            int val = 0;
            for (size_t j = start; j < i; ++j) {
                if (!std::isdigit(static_cast<unsigned char>(ip[j]))) {
                    return false;
                }
                val = val * 10 + (ip[j] - '0');
            }

            // Prohibit leading zeros unless octet is "0"
            if (len > 1 && ip[start] == '0') {
                return false;
            }

            if (val < 0 || val > 255) {
                return false;
            }

            octet_count++;
            start = i + 1;
        }
    }

    return octet_count == 4;
}

bool AuthDetector::is_valid_ipv6(const std::string& ip) {
    if (ip.empty() || ip.size() > 39 || ip.size() < 2) {
        return false;
    }

    // Check for multiple "::"
    size_t double_colon = ip.find("::");
    if (double_colon != std::string::npos) {
        if (ip.find("::", double_colon + 2) != std::string::npos) {
            return false; // Multiple double colons not allowed
        }
    }

    std::vector<std::string> parts;
    std::string cur;

    for (size_t i = 0; i < ip.size(); ++i) {
        if (ip[i] == ':') {
            if (i + 1 < ip.size() && ip[i + 1] == ':') {
                parts.push_back(cur);
                cur.clear();
                parts.push_back("::");
                ++i;
            } else {
                parts.push_back(cur);
                cur.clear();
            }
        } else {
            cur += ip[i];
        }
    }
    parts.push_back(cur);

    int group_count = 0;
    bool has_double_colon = false;

    for (const auto& part : parts) {
        if (part == "::") {
            has_double_colon = true;
            continue;
        }
        if (part.empty()) {
            continue;
        }
        if (part.size() > 4) {
            return false;
        }
        for (char c : part) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) {
                return false;
            }
        }
        group_count++;
    }

    if (has_double_colon) {
        return group_count < 8;
    }
    return group_count == 8;
}

bool AuthDetector::is_valid_ip(const std::string& ip) {
    return is_valid_ipv4(ip) || is_valid_ipv6(ip);
}

std::optional<int64_t> AuthDetector::parse_iso8601_to_epoch(const std::string& ts_str) {
    std::string s = trim(ts_str);
    if (s.empty()) {
        return std::nullopt;
    }

    // Minimum format: YYYY-MM-DDTHH:MM:SSZ (20 characters)
    if (s.size() < 20) {
        return std::nullopt;
    }

    // Check separators
    if (s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't') || s[13] != ':' || s[16] != ':') {
        return std::nullopt;
    }

    auto parse_digits = [](const std::string& str, size_t pos, size_t count) -> std::optional<int> {
        int val = 0;
        for (size_t i = 0; i < count; ++i) {
            char c = str[pos + i];
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                return std::nullopt;
            }
            val = val * 10 + (c - '0');
        }
        return val;
    };

    auto year = parse_digits(s, 0, 4);
    auto month = parse_digits(s, 5, 2);
    auto day = parse_digits(s, 8, 2);
    auto hour = parse_digits(s, 11, 2);
    auto minute = parse_digits(s, 14, 2);
    auto second = parse_digits(s, 17, 2);

    if (!year || !month || !day || !hour || !minute || !second) {
        return std::nullopt;
    }

    if (*year < 1970 || *year > 2099) return std::nullopt;
    if (*month < 1 || *month > 12) return std::nullopt;
    if (*day < 1 || static_cast<unsigned>(*day) > days_in_month(*year, static_cast<unsigned>(*month))) return std::nullopt;
    if (*hour < 0 || *hour > 23) return std::nullopt;
    if (*minute < 0 || *minute > 59) return std::nullopt;
    if (*second < 0 || *second > 59) return std::nullopt;

    // Verify trailing UTC identifier 'Z' or '+00:00'
    size_t end_idx = 19;
    if (s[end_idx] == '.') {
        // Skip fractional seconds (.123)
        ++end_idx;
        while (end_idx < s.size() && std::isdigit(static_cast<unsigned char>(s[end_idx]))) {
            ++end_idx;
        }
    }

    if (end_idx < s.size()) {
        std::string tz_suffix = s.substr(end_idx);
        if (tz_suffix != "Z" && tz_suffix != "z" && tz_suffix != "+00:00" && tz_suffix != "-00:00") {
            return std::nullopt; // Only UTC is accepted
        }
    } else {
        return std::nullopt;
    }

    int64_t days = days_from_civil(*year, static_cast<unsigned>(*month), static_cast<unsigned>(*day));
    int64_t epoch_sec = days * 86400 + (*hour) * 3600 + (*minute) * 60 + (*second);
    return epoch_sec;
}

std::string AuthDetector::epoch_to_iso8601(int64_t epoch_sec) {
    int64_t days = epoch_sec / 86400;
    int64_t rem_sec = epoch_sec % 86400;
    if (rem_sec < 0) {
        rem_sec += 86400;
        days -= 1;
    }

    int year = 0;
    unsigned month = 0;
    unsigned day = 0;
    civil_from_days(days, year, month, day);

    int hour = static_cast<int>(rem_sec / 3600);
    rem_sec %= 3600;
    int minute = static_cast<int>(rem_sec / 60);
    int second = static_cast<int>(rem_sec % 60);

    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << year << '-'
        << std::setw(2) << month << '-'
        << std::setw(2) << day << 'T'
        << std::setw(2) << hour << ':'
        << std::setw(2) << minute << ':'
        << std::setw(2) << second << 'Z';
    return oss.str();
}

AuthStatus AuthDetector::parse_status(const std::string& status_str) {
    std::string s = trim(status_str);
    if (iequals(s, "SUCCESS")) {
        return AuthStatus::SUCCESS;
    }
    if (iequals(s, "FAILURE")) {
        return AuthStatus::FAILURE;
    }
    return AuthStatus::INVALID;
}

std::string AuthDetector::status_to_string(AuthStatus status) {
    switch (status) {
        case AuthStatus::SUCCESS: return "SUCCESS";
        case AuthStatus::FAILURE: return "FAILURE";
        default: return "INVALID";
    }
}

AnalysisResult AuthDetector::analyze_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        AnalysisResult res;
        res.success = false;
        res.error_message = "Cannot open file: " + file_path;
        return res;
    }
    return analyze_stream(file);
}

AnalysisResult AuthDetector::analyze_stream(std::istream& input_stream) {
    std::string line;
    size_t line_number = 0;
    bool header_found = false;

    std::vector<AuthEvent> valid_events;
    std::vector<std::string> warnings;
    size_t total_records = 0;
    size_t invalid_records = 0;

    auto add_warning = [&](const std::string& msg) {
        if (warnings.size() < config_.max_warnings) {
            warnings.push_back(msg);
        }
    };

    while (std::getline(input_stream, line)) {
        line_number++;
        std::string trimmed_line = trim(line);
        if (trimmed_line.empty()) {
            continue; // Ignore blank lines
        }

        if (!header_found) {
            // Validate header row
            std::vector<std::string> header_cols = parse_csv_line(trimmed_line);
            if (header_cols.size() != 4 ||
                !iequals(header_cols[0], "timestamp") ||
                !iequals(header_cols[1], "source_ip") ||
                !iequals(header_cols[2], "username") ||
                !iequals(header_cols[3], "status")) {
                AnalysisResult err_res;
                err_res.success = false;
                err_res.error_message = "Invalid CSV header on line " + std::to_string(line_number) +
                    ". Expected: timestamp,source_ip,username,status";
                return err_res;
            }
            header_found = true;
            continue;
        }

        total_records++;
        std::vector<std::string> fields = parse_csv_line(trimmed_line);
        if (fields.size() != 4) {
            invalid_records++;
            add_warning("Line " + std::to_string(line_number) + ": Expected 4 columns, found " +
                        std::to_string(fields.size()));
            continue;
        }

        const std::string& ts_str = fields[0];
        const std::string& ip_str = fields[1];
        const std::string& username_str = fields[2];
        const std::string& status_str = fields[3];

        // 1. Validate Timestamp
        auto epoch_opt = parse_iso8601_to_epoch(ts_str);
        if (!epoch_opt.has_value()) {
            invalid_records++;
            add_warning("Line " + std::to_string(line_number) + ": Invalid ISO-8601 UTC timestamp '" +
                        ts_str + "'");
            continue;
        }

        // 2. Validate Source IP
        if (!is_valid_ip(ip_str)) {
            invalid_records++;
            add_warning("Line " + std::to_string(line_number) + ": Invalid IP address '" +
                        ip_str + "'");
            continue;
        }

        // 3. Validate Username
        if (username_str.empty()) {
            invalid_records++;
            add_warning("Line " + std::to_string(line_number) + ": Username cannot be empty");
            continue;
        }

        // 4. Validate Status
        AuthStatus st = parse_status(status_str);
        if (st == AuthStatus::INVALID) {
            invalid_records++;
            add_warning("Line " + std::to_string(line_number) + ": Invalid status '" +
                        status_str + "' (expected SUCCESS or FAILURE)");
            continue;
        }

        // Record is fully valid
        AuthEvent ev;
        ev.timestamp_str = ts_str;
        ev.timestamp_epoch_sec = epoch_opt.value();
        ev.source_ip = ip_str;
        ev.username = username_str;
        ev.status = st;
        ev.line_number = line_number;
        valid_events.push_back(std::move(ev));
    }

    if (!header_found) {
        AnalysisResult empty_res;
        empty_res.success = false;
        empty_res.error_message = "Empty file: no CSV header or authentication records found";
        return empty_res;
    }

    return analyze_events(valid_events, total_records, invalid_records, std::move(warnings));
}

AnalysisResult AuthDetector::analyze_events(std::vector<AuthEvent>& events,
                                           size_t total_records,
                                           size_t invalid_records,
                                           std::vector<std::string> warnings) {
    auto start_time = std::chrono::high_resolution_clock::now();

    AnalysisResult result;
    result.success = true;
    result.warnings = std::move(warnings);
    result.stats.total_records = total_records;
    result.stats.valid_records = events.size();
    result.stats.invalid_records = invalid_records;

    // 1. Sort records chronologically (stable sort preserves original file order for ties)
    std::stable_sort(events.begin(), events.end(),
        [](const AuthEvent& a, const AuthEvent& b) {
            return a.timestamp_epoch_sec < b.timestamp_epoch_sec;
        });

    std::unordered_set<std::string> unique_ips;
    std::unordered_map<std::string, IpTracker> trackers;

    // 2. Sliding window detection loop
    for (const auto& ev : events) {
        unique_ips.insert(ev.source_ip);

        if (ev.status == AuthStatus::SUCCESS) {
            result.stats.success_count++;
            // Successful logins are recorded but do not contribute to brute-force failure counts
            continue;
        }

        if (ev.status == AuthStatus::FAILURE) {
            result.stats.failure_count++;
            auto& tracker = trackers[ev.source_ip];

            // Slide window: remove timestamps older than (current_time - window_seconds)
            // Inclusive boundary: timestamps where (current_time - old_time <= window_seconds) are kept
            while (!tracker.failure_timestamps.empty() &&
                   (ev.timestamp_epoch_sec - tracker.failure_timestamps.front()) > config_.window_seconds) {
                tracker.failure_timestamps.pop_front();
            }

            // Reset alert suppression state if failures subsided below threshold
            if (tracker.in_alert_state &&
                tracker.failure_timestamps.size() < config_.failure_threshold) {
                tracker.in_alert_state = false;
            }

            // Add the new failure timestamp to the sliding window deque
            tracker.failure_timestamps.push_back(ev.timestamp_epoch_sec);

            // Check if current window size meets or exceeds detection threshold
            if (tracker.failure_timestamps.size() >= config_.failure_threshold) {
                if (!tracker.in_alert_state) {
                    // First time crossing the threshold for this episode: emit alert
                    tracker.in_alert_state = true;

                    Alert alert;
                    alert.rule_id = "BRUTE_FORCE_SUSPECTED";
                    alert.severity = "HIGH";
                    alert.source_ip = ev.source_ip;
                    alert.failed_attempts = tracker.failure_timestamps.size();
                    alert.window_seconds = config_.window_seconds;
                    alert.detection_timestamp = ev.timestamp_str;
                    alert.window_start_timestamp = epoch_to_iso8601(tracker.failure_timestamps.front());
                    alert.message = std::to_string(tracker.failure_timestamps.size()) +
                                    " failed login attempts detected within a rolling " +
                                    std::to_string(config_.window_seconds) + "-second window.";

                    result.alerts.push_back(std::move(alert));
                }
                // If tracker.in_alert_state is already true, suppress redundant alerts for the ongoing burst
            }
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end_time - start_time;

    result.stats.unique_ips = unique_ips.size();
    result.stats.alert_count = result.alerts.size();
    result.stats.processing_time_ms = elapsed.count();

    return result;
}

nlohmann::json AnalysisResult::to_json() const {
    nlohmann::json j;
    if (!success) {
        j["success"] = false;
        j["error"] = error_message;
        return j;
    }

    j["summary"] = {
        {"total_records", stats.total_records},
        {"valid_records", stats.valid_records},
        {"invalid_records", stats.invalid_records},
        {"success_count", stats.success_count},
        {"failure_count", stats.failure_count},
        {"unique_ips", stats.unique_ips},
        {"alert_count", stats.alert_count},
        {"processing_time_ms", stats.processing_time_ms}
    };

    nlohmann::json alerts_array = nlohmann::json::array();
    for (const auto& a : alerts) {
        alerts_array.push_back({
            {"rule_id", a.rule_id},
            {"severity", a.severity},
            {"source_ip", a.source_ip},
            {"failed_attempts", a.failed_attempts},
            {"window_seconds", a.window_seconds},
            {"detection_timestamp", a.detection_timestamp},
            {"window_start_timestamp", a.window_start_timestamp},
            {"message", a.message}
        });
    }
    j["alerts"] = alerts_array;
    j["warnings"] = warnings;

    return j;
}

} // namespace authtrace
