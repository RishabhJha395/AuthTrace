# AuthTrace — C++17 Security Log Analyzer

AuthTrace is a high-performance, rule-based authentication log analyzer written in modern C++17. It ingests authentication event logs, validates records against security standards, and detects suspicious login patterns such as brute-force attacks using an in-memory sliding-window algorithm.

---

## Table of Contents

- [Overview](#overview)
- [Detection Rule & Logic](#detection-rule--logic)
- [Algorithm & Data Structures](#algorithm--data-structures)
- [Complexity Analysis](#complexity-analysis)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Running AuthTrace](#running-authtrace)
- [Sample Outputs](#sample-outputs)
- [Running Unit Tests](#running-unit-tests)
- [Security & Limitations](#security--limitations)
- [License](#license)

---

## Overview

In modern cybersecurity operations, authentication logs are the first line of visibility into credential abuse and brute-force attacks. AuthTrace processes authentication CSV streams or files, validates timestamps and IP addresses, sorts records chronologically, and detects repeated failed authentication attempts within a rolling time window.

### Key Capabilities

- **Strict Validation**: Validates ISO-8601 UTC timestamps, IPv4 / IPv6 addresses, usernames, and authentication statuses (`SUCCESS` or `FAILURE`).
- **Resilient Parsing**: Skips malformed rows with descriptive, bounded warnings without terminating analysis of valid events.
- **Chronological Sorting**: Uses stable sorting to ensure out-of-order log entries are evaluated in true chronological sequence.
- **Sliding-Window Detection**: Tracks failed attempts per IP with an inclusive 60-second window.
- **Incident Alert Suppression**: Emits an alert upon first crossing the threshold and suppresses redundant duplicate alerts during the ongoing incident until the episode subsides.
- **Dual Output Modes**: Supports human-readable terminal reports and machine-readable JSON via `nlohmann/json`.

---

## Detection Rule & Logic

### Primary Rule: `BRUTE_FORCE_SUSPECTED`

| Parameter | Specification |
|---|---|
| **Rule ID** | `BRUTE_FORCE_SUSPECTED` |
| **Severity** | `HIGH` |
| **Default Threshold** | $\ge 5$ failed login attempts from the same source IP |
| **Time Window** | 60 seconds (inclusive: $t_{\text{current}} - t_{\text{old}} \le 60\text{s}$) |
| **Target Event** | `FAILURE` status only (`SUCCESS` events do not increment failure count) |

### Boundary Behavior

The 60-second window is **inclusive**:
- If failure #1 occurs at `10:00:00` ($t=0$) and failure #5 occurs at `10:01:00` ($t=60$), $60 - 0 = 60 \le 60$. All 5 events are within the 60-second window, and an alert is triggered.
- If failure #5 occurs at `10:01:01` ($t=61$), $61 - 0 = 61 > 60$. The first event expires from the window, leaving only 4 failures. No alert is triggered.

### Duplicate-Alert Suppression & Reset

When an attacker launches a burst of login attempts:
1. When the source IP reaches 5 failures in 60s, AuthTrace emits an alert and marks the IP's tracking state as `in_alert_state = true`.
2. As subsequent failures arrive during the same ongoing incident (e.g. attempts 6, 7, 8 within the active burst), they are counted in overall statistics, but duplicate alerts are suppressed.
3. Once the burst subsides and the rolling window drops below the threshold ($< 5$ failures in 60s), `in_alert_state` resets to `false`. A subsequent burst from that IP will then trigger a new alert.

---

## Algorithm & Data Structures

```
                 Incoming Auth Events (CSV)
                            │
                            ▼
              ┌───────────────────────────┐
              │ CSV Parser & Field Check  │
              │ (Timestamps, IPv4/v6)     │
              └─────────────┬─────────────┘
                            │ Valid Records
                            ▼
              ┌───────────────────────────┐
              │    std::stable_sort()     │
              │  (Chronological by epoch) │
              └─────────────┬─────────────┘
                            │
                            ▼
           ┌─────────────────────────────────┐
           │      AuthDetector Engine        │
           │                                 │
           │  std::unordered_map<IP, State>  │
           │  ┌───────────────────────────┐  │
           │  │ IP: 203.0.113.42          │  │
           │  │ Deque: [t0, t1, t2, t3, t4│  │  ──> Alert: BRUTE_FORCE_SUSPECTED
           │  │ State: in_alert = true    │  │
           │  └───────────────────────────┘  │
           └─────────────────────────────────┘
```

### Why `std::unordered_map`?

Per-IP tracking requires constant-time lookups as each log record is processed. `std::unordered_map` provides average $O(1)$ complexity for looking up and inserting IP tracking states.

### Why `std::deque`?

A double-ended queue (`std::deque`) represents the sliding time window:
- When a failure arrives, its epoch timestamp is pushed to the back ($O(1)$).
- Expired timestamps older than 60 seconds are popped from the front ($O(1)$ amortized).
- Unlike a vector, popping from the front of a deque does not require shifting elements in memory.

---

## Complexity Analysis

| Operation | Time Complexity | Space Complexity | Explanation |
|---|---|---|---|
| **CSV Parsing & Validation** | $O(N)$ | $O(N)$ | Scans each line of $N$ log entries once. |
| **Chronological Sorting** | $O(N \log N)$ | $O(N)$ | `std::stable_sort` on valid events preserves relative order of simultaneous events. |
| **Sliding Window Detection** | $O(N)$ | $O(U \times K)$ | Each failure event is pushed to a deque once and popped at most once. $U$ is unique IPs, $K \le 60$ failures in window. |
| **Total** | **$O(N \log N)$** | **$O(N)$** | Overall runtime is dominated by sorting, keeping memory strictly bounded by log size. |

---

## Project Structure

```text
authtrace/
├── src/
│   ├── main.cpp              # CLI interface and report formatting
│   ├── detector.cpp          # CSV parsing, IP/timestamp validation, sliding window engine
│   └── detector.h            # Data structures, configuration, and interface declarations
├── tests/
│   └── detector_tests.cpp    # Unit test suite (GoogleTest + Standalone runner support)
├── examples/
│   └── sample_auth_logs.csv  # Synthetic authentication dataset for testing
├── CMakeLists.txt            # CMake configuration with FetchContent for dependencies
├── .gitignore                # Clean gitignore excluding build artifacts
├── LICENSE                   # MIT License
└── README.md                 # Complete documentation and usage guide
```

---

## Prerequisites

- **C++ Compiler**: Supporting C++17 or later:
  - GCC 9+ (Linux)
  - Clang 10+ (macOS / Linux)
  - MSVC 2019+ / Visual Studio 16.0+ (Windows)
- **CMake**: Version 3.14 or later
- **Git**: For automatic dependency retrieval via CMake `FetchContent` (nlohmann/json and GoogleTest)

---

## Build Instructions

### 1. Configure and Build with CMake

```bash
# Generate build configuration
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build the executable and test suite
cmake --build build --config Release
```

Dependencies (`nlohmann/json` and `GoogleTest`) are automatically fetched and configured via CMake `FetchContent`. If `nlohmann/json` or `GoogleTest` is already installed on your system, CMake will detect and use the local installation.

The compiled binary will be placed at:
- Linux / macOS: `build/authtrace`
- Windows: `build/Release/authtrace.exe` or `build/authtrace.exe`

---

## Running AuthTrace

### Command-Line Interface

```bash
# Show usage and available options
./build/authtrace --help

# Show version
./build/authtrace --version

# Analyze a log file (Default human-readable terminal report)
./build/authtrace analyze examples/sample_auth_logs.csv

# Analyze a log file and output machine-readable JSON
./build/authtrace analyze examples/sample_auth_logs.csv --json
```

---

## Sample Outputs

### Human-Readable Terminal Report

```text
================================================================================
 AuthTrace — Authentication Log Security Report
================================================================================
Target File        : examples/sample_auth_logs.csv
Total Records      : 13
Valid Records      : 12
Invalid Records    : 1
Success Logins     : 4
Failed Logins      : 8
Unique Source IPs  : 4
Detection Alerts   : 1
Analysis Duration  : 0.082 ms

--------------------------------------------------------------------------------
 DETECTED SECURITY ALERTS (1)
--------------------------------------------------------------------------------
  [HIGH] Alert #1 — BRUTE_FORCE_SUSPECTED
    Source IP       : 203.0.113.42
    Failed Attempts : 5 within 60s
    Detection Time  : 2026-10-25T09:00:48Z
    Window Start    : 2026-10-25T09:00:00Z
    Description     : 5 failed login attempts detected within a rolling 60-second window.

--------------------------------------------------------------------------------
 VALIDATION WARNINGS (1)
--------------------------------------------------------------------------------
  Line 14: Invalid status 'UNKNOWN_STATUS' (expected SUCCESS or FAILURE)
================================================================================
```

### JSON Output (`--json`)

```json
{
  "alerts": [
    {
      "detection_timestamp": "2026-10-25T09:00:48Z",
      "failed_attempts": 5,
      "message": "5 failed login attempts detected within a rolling 60-second window.",
      "rule_id": "BRUTE_FORCE_SUSPECTED",
      "severity": "HIGH",
      "source_ip": "203.0.113.42",
      "window_seconds": 60,
      "window_start_timestamp": "2026-10-25T09:00:00Z"
    }
  ],
  "summary": {
    "alert_count": 1,
    "failure_count": 8,
    "invalid_records": 1,
    "processing_time_ms": 0.082,
    "success_count": 4,
    "total_records": 13,
    "unique_ips": 4,
    "valid_records": 12
  },
  "warnings": [
    "Line 14: Invalid status 'UNKNOWN_STATUS' (expected SUCCESS or FAILURE)"
  ]
}
```

---

## Running Unit Tests

### Option A: Using CTest (Standard CMake)

```bash
ctest --test-dir build --output-on-failure
```

### Option B: Running the GoogleTest Executable Directly

```bash
# Linux / macOS
./build/detector_tests

# Windows
./build/Release/detector_tests.exe
```

### Option C: Standalone Test Compilation (Without CMake / GoogleTest)

If building in an environment without CMake or GoogleTest, compile the standalone runner directly:

```bash
g++ -std=c++17 -DUSE_STANDALONE_TEST_RUNNER src/detector.cpp tests/detector_tests.cpp -Isrc -o test_runner
./test_runner
```

### Test Coverage

The test suite covers:
1. **IPv4 Validation**: Standard notation, leading zero rejection, out-of-bounds octets.
2. **IPv6 Validation**: Standard 8-group notation, `::` compression, invalid characters.
3. **ISO-8601 UTC Timestamps**: Valid date/time parsing, leap years, subsecond stripping, timezone validation.
4. **Threshold Triggering**: 5 failures within 60s fire an alert; 4 failures do not.
5. **Sliding Window Expiration**: Failures outside the 60s window are pruned.
6. **Boundary Accuracy**: Exactly 60s difference is inclusive; 61s difference expires the oldest attempt.
7. **Multi-IP Isolation**: Tracking states for separate IPs do not interfere.
8. **Success Event Handling**: Successful logins do not count towards brute-force failures.
9. **Event Sorting**: Out-of-order log entries are evaluated chronologically.
10. **Duplicate-Alert Suppression**: Ongoing incident failures do not trigger repetitive alerts.
11. **Incident Reset**: Alerts reset once the failure rate subsides below the threshold.
12. **Malformed Input**: Gracefully skips malformed lines, records warnings, and completes analysis.

---

## Security & Limitations

- **Stateless & In-Memory**: AuthTrace processes logs in-memory and never executes input files or writes unvalidated user content to disk.
- **Rule-Based Scope**: AuthTrace is a lightweight log analyzer designed to flag suspicious patterns. It does not block traffic, interact with firewalls, or verify account compromise.
- **NAT / Shared IPs (False Positives)**: Multiple distinct users behind an egress proxy, CGNAT, or VPN gateway share a single public IP. Concurrent legitimate login mistakes could trigger an alert.
- **Distributed / Slow Attacks (False Negatives)**: Low-and-slow attacks (e.g. 1 attempt every 2 minutes) or distributed botnet attacks across rotating IPs bypass single-IP rolling 60-second thresholds.

---

## License

This project is licensed under the [MIT License](LICENSE).
