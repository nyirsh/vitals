add_executable(vitals_browser_quiet_output_tests test_quiet_output.c ../../browser/quiet_output.c)
target_compile_options(vitals_browser_quiet_output_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_browser_quiet_output COMMAND vitals_browser_quiet_output_tests)

# The other browser tests place memory at fixed low addresses, as the Vita's 32-bit pointers
# need, which only Linux allows
if(NOT VITALS_FIXED_ADDRESS_TESTS)
    return()
endif()

add_executable(vitals_browser_config_tests test_config.c ../../browser/config.c)
target_link_libraries(vitals_browser_config_tests PRIVATE vitals_core)
target_compile_options(vitals_browser_config_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_browser_config COMMAND vitals_browser_config_tests)

add_executable(vitals_browser_backend_tests test_backend.c ../../browser/backend.c
    ../../browser/config.c ../../provider/ca_file.c ../../provider/ca_index.c ../../provider/platform_shims.c)
target_include_directories(vitals_browser_backend_tests PRIVATE ../../browser ../../provider)
target_link_libraries(vitals_browser_backend_tests PRIVATE vitals_core mbedtls vitals_vita_mock)
target_compile_options(vitals_browser_backend_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(vitals_browser_backend_tests PRIVATE -no-pie)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME vitals_browser_loopback COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_browser_loopback.py" $<TARGET_FILE:vitals_browser_backend_tests>)
set_tests_properties(vitals_browser_loopback PROPERTIES TIMEOUT 120)

add_executable(vitals_browser_memory_tests test_backend.c memory_tracker.c ../../browser/backend.c
    ../../browser/config.c ../../provider/ca_file.c ../../provider/ca_index.c ../../provider/platform_shims.c)
target_include_directories(vitals_browser_memory_tests PRIVATE ../../browser ../../provider)
target_link_libraries(vitals_browser_memory_tests PRIVATE vitals_core mbedtls vitals_vita_mock)
target_compile_definitions(vitals_browser_memory_tests PRIVATE
    VITALS_BROWSER_MEMORY_TEST=1)
target_compile_options(vitals_browser_memory_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(vitals_browser_memory_tests PRIVATE -no-pie -Wl,--wrap=malloc -Wl,--wrap=calloc
    -Wl,--wrap=realloc -Wl,--wrap=free)
add_test(NAME vitals_browser_memory COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_browser_loopback.py" $<TARGET_FILE:vitals_browser_memory_tests>
    --scenario memory-full-ca)
set_tests_properties(vitals_browser_memory PROPERTIES TIMEOUT 120)

add_executable(vitals_browser_lazy_ca_tests test_lazy_ca.c ../../browser/backend.c
    ../../browser/config.c ../../provider/ca_file.c ../../provider/ca_index.c ../../provider/platform_shims.c)
target_include_directories(vitals_browser_lazy_ca_tests PRIVATE ../../browser ../../provider)
target_link_libraries(vitals_browser_lazy_ca_tests PRIVATE vitals_core mbedtls vitals_vita_mock)
target_compile_options(vitals_browser_lazy_ca_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(vitals_browser_lazy_ca_tests PRIVATE -no-pie -Wl,--wrap=vitals_ca_index_build)
foreach(scenario IN ITEMS init legacy failure)
    add_test(NAME vitals_browser_lazy_ca_${scenario} COMMAND vitals_browser_lazy_ca_tests ${scenario})
endforeach()

add_executable(vitals_browser_module_tests test_module.c ../../browser/module.c
    ../../browser/webkit_callback.c)
target_include_directories(vitals_browser_module_tests PRIVATE ../../browser ../../provider ../transport/include)
target_link_libraries(vitals_browser_module_tests PRIVATE vitals_core)
target_compile_definitions(vitals_browser_module_tests PRIVATE VITALS_HOST_MODULE_TEST=1)
target_compile_options(vitals_browser_module_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid bad-args bad-id bad-name bad-size bad-path bad-site-0 bad-site-1 bad-site-2 bad-site-3 bad-site-4 bad-site-5 hook-0 hook-1 hook-2 hook-3
    bad-buffer bad-arg-size bad-version bad-reserved bad-negative-id bad-address bad-text-memsz bad-data-filesz bad-data-memsz init-fail)
    add_test(NAME vitals_browser_module_${scenario} COMMAND vitals_browser_module_tests ${scenario})
endforeach()
