#include "detector.h"

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <iomanip>

namespace {

void print_usage(const char* prog_name) {
    std::cout << "AuthTrace — C++17 Authentication Log Security Analyzer (v1.0.0)\n\n"
              << "Usage:\n"
              << "  " << prog_name << " analyze <file_path> [--json]\n"
              << "  " << prog_name << " --help\n"
              << "  " << prog_name << " --version\n\n"
              << "Commands:\n"
              << "  analyze <file_path>   Analyze an authentication log CSV for brute-force patterns\n\n"
              << "Options:\n"
              << "  --json                Output results in JSON format to stdout\n"
              << "  -h, --help            Show this help message and exit\n"
              << "  -v, --version         Show version information\n\n"
              << "Example:\n"
              << "  " << prog_name << " analyze examples/sample_auth_logs.csv\n"
              << "  " << prog_name << " analyze examples/sample_auth_logs.csv --json\n";
}

void print_version() {
    std::cout << "AuthTrace version 1.0.0 (C++17)\n"
              << "Rule-based authentication security log analyzer\n";
}

void print_human_report(const std::string& file_path, const authtrace::AnalysisResult& res) {
    const auto& s = res.stats;

    std::cout << "\n================================================================================\n"
              << " AuthTrace — Authentication Log Security Report\n"
              << "================================================================================\n"
              << "Target File        : " << file_path << "\n"
              << "Total Records      : " << s.total_records << "\n"
              << "Valid Records      : " << s.valid_records << "\n"
              << "Invalid Records    : " << s.invalid_records << "\n"
              << "Success Logins     : " << s.success_count << "\n"
              << "Failed Logins      : " << s.failure_count << "\n"
              << "Unique Source IPs  : " << s.unique_ips << "\n"
              << "Detection Alerts   : " << s.alert_count << "\n"
              << "Analysis Duration  : " << std::fixed << std::setprecision(3) << s.processing_time_ms << " ms\n";

    std::cout << "\n--------------------------------------------------------------------------------\n"
              << " DETECTED SECURITY ALERTS (" << res.alerts.size() << ")\n"
              << "--------------------------------------------------------------------------------\n";

    if (res.alerts.empty()) {
        std::cout << "  No suspicious authentication activity detected.\n";
    } else {
        for (size_t i = 0; i < res.alerts.size(); ++i) {
            const auto& a = res.alerts[i];
            std::cout << "  [" << a.severity << "] Alert #" << (i + 1) << " — " << a.rule_id << "\n"
                      << "    Source IP       : " << a.source_ip << "\n"
                      << "    Failed Attempts : " << a.failed_attempts << " within " << a.window_seconds << "s\n"
                      << "    Detection Time  : " << a.detection_timestamp << "\n"
                      << "    Window Start    : " << a.window_start_timestamp << "\n"
                      << "    Description     : " << a.message << "\n\n";
        }
    }

    if (!res.warnings.empty()) {
        std::cout << "--------------------------------------------------------------------------------\n"
                  << " VALIDATION WARNINGS (" << res.warnings.size() << ")\n"
                  << "--------------------------------------------------------------------------------\n";
        for (const auto& w : res.warnings) {
            std::cout << "  " << w << "\n";
        }
    }

    std::cout << "================================================================================\n\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "--help" || command == "-h" || command == "help") {
        print_usage(argv[0]);
        return 0;
    }

    if (command == "--version" || command == "-v" || command == "version") {
        print_version();
        return 0;
    }

    if (command == "analyze") {
        std::string file_path;
        bool json_output = false;

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--json") {
                json_output = true;
            } else if (file_path.empty()) {
                file_path = arg;
            } else {
                std::cerr << "Error: Unexpected argument '" << arg << "'. Use --help for usage.\n";
                return 1;
            }
        }

        if (file_path.empty()) {
            std::cerr << "Error: Missing CSV file path for 'analyze' command.\n"
                      << "Usage: " << argv[0] << " analyze <file_path> [--json]\n";
            return 1;
        }

        std::error_code ec;
        if (!std::filesystem::exists(file_path, ec)) {
            if (json_output) {
                nlohmann::json err;
                err["success"] = false;
                err["error"] = "File not found: " + file_path;
                std::cout << err.dump(2) << "\n";
            } else {
                std::cerr << "Error: File not found: " << file_path << "\n";
            }
            return 1;
        }

        authtrace::AuthDetector detector;
        authtrace::AnalysisResult result = detector.analyze_file(file_path);

        if (!result.success) {
            if (json_output) {
                std::cout << result.to_json().dump(2) << "\n";
            } else {
                std::cerr << "Error: " << result.error_message << "\n";
            }
            return 1;
        }

        if (json_output) {
            std::cout << result.to_json().dump(2) << "\n";
        } else {
            print_human_report(file_path, result);
        }

        return 0;
    }

    std::cerr << "Error: Unknown command '" << command << "'.\n"
              << "Run '" << argv[0] << " --help' for available commands.\n";
    return 1;
}
