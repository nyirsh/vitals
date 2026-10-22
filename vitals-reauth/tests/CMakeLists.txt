cmake_minimum_required(VERSION 3.16)
# Host test of the module against stand-ins for taiHEN (include/), built for this machine;
# `make test` runs it
project(vitals_reauth_tests C)
set(CMAKE_C_STANDARD 11)

option(VITALS_ENABLE_SANITIZERS "Build the tests with AddressSanitizer and UBSan" ON)
if(VITALS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
enable_testing()

# test_reauth.c includes the module's main.c, so the module is compiled exactly as the test sees it,
# with the list reader it shares with the HTTP provider
set(TLS13_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../tls13-vita)
add_executable(vitals_reauth_module_tests test_reauth.c ${TLS13_DIR}/src/host_map.c
    ${TLS13_DIR}/src/redirect_list.c)
target_include_directories(vitals_reauth_module_tests PRIVATE include ${TLS13_DIR}/include)
target_compile_options(vitals_reauth_module_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_reauth_module COMMAND vitals_reauth_module_tests)
