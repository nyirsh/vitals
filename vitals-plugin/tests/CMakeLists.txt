cmake_minimum_required(VERSION 3.16)
# Host tests of the kernel plugin: its routing, injection and module checks, run against mocks of
# the Vita kernel (include/) on the build machine; `make test` runs them
project(vitals_plugin_tests C)
set(CMAKE_C_STANDARD 11)

set(PLUGIN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(TLS13_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../tls13-vita)

option(VITALS_ENABLE_SANITIZERS "Build the tests with AddressSanitizer and UBSan" ON)
if(VITALS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
enable_testing()

# The plugin builds against tls13-vita's shared headers and core code, and so do its tests
file(GLOB core_sources ${TLS13_DIR}/src/*.c)
add_library(vitals_core STATIC ${core_sources})
target_include_directories(vitals_core PUBLIC ${TLS13_DIR}/include)

# Each test: name, test source, plugin source under test, and any more plugin sources it needs
function(plugin_test name test_source plugin_source)
    set(sources ${PLUGIN_DIR}/${plugin_source})
    foreach(extra ${ARGN})
        list(APPEND sources ${PLUGIN_DIR}/${extra})
    endforeach()
    add_executable(${name}_tests ${test_source} ${sources})
    target_include_directories(${name}_tests PRIVATE include ${PLUGIN_DIR})
    target_link_libraries(${name}_tests PRIVATE vitals_core)
    target_compile_options(${name}_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME ${name} COMMAND ${name}_tests)
endfunction()

plugin_test(vitals_kernel_route test_route.c post_start.c)
plugin_test(vitals_hook_guard test_hook_guard.c hook_guard.c)
plugin_test(vitals_native_module_api test_native_module_api.c native_module_api.c)
plugin_test(vitals_post_start test_post_start.c post_start.c)
plugin_test(vitals_reauth test_reauth.c reauth.c)
# DNS for every process: redirects for hosts on the list, and logging with debug output on
plugin_test(vitals_dns_watch test_dns_watch.c dns_watch.c dns_message.c)
# As the debug builds are, so the query log is tested too
target_compile_definitions(vitals_dns_watch_tests PRIVATE VITALS_DEBUG=1)
# Reading the redirect list for games, which may not open it themselves
plugin_test(vitals_redirects test_redirects.c redirects.c)
# The production loader path: name lookups on a dedicated native stack
plugin_test(vitals_production_context test_production_context.c tls13_loader.c)
