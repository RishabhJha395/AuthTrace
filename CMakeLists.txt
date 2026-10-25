cmake_minimum_required(VERSION 3.14)
project(AuthTrace VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warning flags
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

include(FetchContent)

# 1. Dependency: nlohmann/json
find_package(nlohmann_json 3.10 QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann/json not found locally; acquiring via FetchContent...")
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# 2. Core Static Library
add_library(authtrace_core STATIC
    src/detector.cpp
    src/detector.h
)

target_include_directories(authtrace_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(authtrace_core PUBLIC
    nlohmann_json::nlohmann_json
)

# 3. CLI Executable
add_executable(authtrace
    src/main.cpp
)

target_link_libraries(authtrace PRIVATE
    authtrace_core
)

# 4. GoogleTest Unit Tests
option(BUILD_TESTS "Build GoogleTest unit test suite" ON)

if(BUILD_TESTS)
    enable_testing()

    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        message(STATUS "GoogleTest not found locally; acquiring via FetchContent...")
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.14.0
        )
        # Prevent overriding compiler/linker runtime settings on Windows MSVC
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()

    add_executable(detector_tests
        tests/detector_tests.cpp
    )

    target_link_libraries(detector_tests PRIVATE
        authtrace_core
        GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(detector_tests)
endif()
