cmake_minimum_required(VERSION 3.16)
# Host tests of the code every Vita module shares: the core library (core.cmake), the CA store's
# scanner shared with the PS3, and the user-mode runtime (runtime/), built for this machine with
# AddressSanitizer and UBSan; `make test` runs them
project(vitals_common_tests C)

option(VITALS_ENABLE_SANITIZERS "Build the tests with AddressSanitizer and UBSan" ON)
if(VITALS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
enable_testing()
include(core.cmake)

add_executable(vitals_tests tests/test_main.c)
target_link_libraries(vitals_tests PRIVATE vitals_core)
target_compile_features(vitals_tests PRIVATE c_std_11)
target_compile_options(vitals_tests PRIVATE -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow
    -Wstrict-prototypes)
add_test(NAME vitals_core COMMAND vitals_tests)

# Each test of the core library: name, then its source
function(core_test name source)
    add_executable(${name}_tests ${source})
    target_link_libraries(${name}_tests PRIVATE vitals_core)
    target_compile_options(${name}_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME ${name} COMMAND ${name}_tests)
endfunction()
core_test(vitals_registry_lifetime tests/test_registry_lifetime.c)
core_test(vitals_cert_policy tests/test_cert_policy.c)
core_test(vitals_browser_paths tests/test_browser_paths.c)
# The firmware identities: 3.60's and 3.65's kernel and WebKit
core_test(vitals_firmware_profiles tests/test_firmware_profiles.c)
core_test(vitals_host_map tests/test_host_map.c)
# The CA store's scanner, shared with the PS3's libssl (../../shared/src/ca_scan.c)
add_executable(vitals_ca_scan_tests ../../shared/tests/test_ca_scan.c ../../shared/src/ca_scan.c)
target_link_libraries(vitals_ca_scan_tests PRIVATE vitals_core)
target_compile_options(vitals_ca_scan_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_ca_scan COMMAND vitals_ca_scan_tests)
# The user-mode runtime, with portable stand-ins for the Vita's memory and threads
add_subdirectory(tests/runtime)
