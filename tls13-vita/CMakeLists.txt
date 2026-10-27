cmake_minimum_required(VERSION 3.16)

project(vitals C)

option(VITALS_BUILD_HOST_TESTS "Build host unit tests" OFF)
option(VITALS_BUILD_VITA_PROVIDER "Build the browser's Vita provider" OFF)
option(VITALS_BUILD_TRANSPORT_TESTS "Build host tests with the real TLS engine" OFF)
# A few tests place memory at fixed low addresses (the Vita's 32-bit pointers), which only Linux
# allows; elsewhere they are left out
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(VITALS_FIXED_ADDRESS_TESTS ON)
else()
    set(VITALS_FIXED_ADDRESS_TESTS OFF)
endif()
option(VITALS_ENABLE_SANITIZERS "Enable host sanitizers" OFF)
set(VITALS_DEBUG 0 CACHE STRING
    "Provider debug output on the console: 0 none, 1 summaries and failures, 2 everything")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
    message(FATAL_ERROR "VITALS_DEBUG must be 0, 1 or 2")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../dependencies.cmake")
# The release version from ../VERSION, which the providers carry in their module headers
include("${CMAKE_CURRENT_LIST_DIR}/../version.cmake")
if(VITALS_BUILD_VITA_PROVIDER OR VITALS_BUILD_TRANSPORT_TESTS)
    vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
endif()

if(VITALS_ENABLE_SANITIZERS)
    if(VITALS_BUILD_VITA_PROVIDER OR NOT CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR "Sanitizers require a supported native host compiler")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

add_library(vitals_core STATIC
    src/cert_policy.c
    src/error_map.c
    src/host_map.c
    src/module_gate.c
    src/path.c
    src/redirect_list.c
    src/registry.c
)

target_include_directories(vitals_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(vitals_core PUBLIC c_std_11)

target_compile_options(vitals_core PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wstrict-prototypes
)

if(VITALS_BUILD_HOST_TESTS)
    enable_testing()

    add_executable(vitals_tests
        tests/test_main.c
    )

    target_link_libraries(vitals_tests PRIVATE vitals_core)
    target_compile_features(vitals_tests PRIVATE c_std_11)
    target_compile_options(vitals_tests PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wstrict-prototypes
    )

    add_test(NAME vitals_core COMMAND vitals_tests)
    add_executable(vitals_registry_lifetime_tests tests/test_registry_lifetime.c)
    target_link_libraries(vitals_registry_lifetime_tests PRIVATE vitals_core)
    target_compile_options(vitals_registry_lifetime_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME vitals_registry_lifetime COMMAND vitals_registry_lifetime_tests)
    add_executable(vitals_cert_policy_tests tests/test_cert_policy.c)
    target_link_libraries(vitals_cert_policy_tests PRIVATE vitals_core)
    target_compile_options(vitals_cert_policy_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME vitals_cert_policy COMMAND vitals_cert_policy_tests)
    add_executable(vitals_browser_path_tests tests/test_browser_paths.c)
    target_link_libraries(vitals_browser_path_tests PRIVATE vitals_core)
    target_compile_options(vitals_browser_path_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME vitals_browser_paths COMMAND vitals_browser_path_tests)
    # The firmware identities: 3.60's and 3.65's kernel and WebKit
    add_executable(vitals_firmware_profile_tests tests/test_firmware_profiles.c)
    target_link_libraries(vitals_firmware_profile_tests PRIVATE vitals_core)
    target_compile_options(vitals_firmware_profile_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME vitals_firmware_profiles COMMAND vitals_firmware_profile_tests)
    add_executable(vitals_host_map_tests tests/test_host_map.c)
    target_link_libraries(vitals_host_map_tests PRIVATE vitals_core)
    target_compile_options(vitals_host_map_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME vitals_host_map COMMAND vitals_host_map_tests)
    # The provider's redirect hooks, with portable stand-ins for the Vita file functions and taiHEN
    add_subdirectory(tests/runtime)
endif()

if(VITALS_BUILD_VITA_PROVIDER OR VITALS_BUILD_TRANSPORT_TESTS)
    add_subdirectory(crypto)
endif()

if(VITALS_BUILD_TRANSPORT_TESTS)
    enable_testing()
    add_subdirectory(tests/transport)
    add_subdirectory(tests/browser)
    add_subdirectory(tests/debug)
endif()

if(VITALS_BUILD_VITA_PROVIDER)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Generic")
        message(FATAL_ERROR "VITALS_BUILD_VITA_PROVIDER requires the VitaSDK toolchain")
    endif()
    add_subdirectory(browser)
endif()
