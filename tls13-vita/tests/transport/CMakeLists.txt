find_package(Threads REQUIRED)
add_library(vitals_vita_mock STATIC vita_mock.c)
target_include_directories(vitals_vita_mock PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(vitals_vita_mock PUBLIC Threads::Threads)
add_executable(vitals_crypto_platform_tests test_crypto_platform.c ../../provider/platform_shims.c)
target_include_directories(vitals_crypto_platform_tests PRIVATE ../../provider)
target_link_libraries(vitals_crypto_platform_tests PRIVATE mbedtls vitals_vita_mock)
target_compile_options(vitals_crypto_platform_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_crypto_platform COMMAND vitals_crypto_platform_tests)
set_tests_properties(vitals_crypto_platform PROPERTIES TIMEOUT 20)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

# A self-signed server certificate trusted by exact match (ca_index.c), with real certificates
add_executable(vitals_exact_trust_tests test_exact_trust.c ../../provider/ca_index.c ../../provider/platform_shims.c)
target_include_directories(vitals_exact_trust_tests PRIVATE ../../provider ../../include)
target_link_libraries(vitals_exact_trust_tests PRIVATE mbedtls vitals_vita_mock)
target_compile_options(vitals_exact_trust_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_exact_trust
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_exact_trust.py"
            $<TARGET_FILE:vitals_exact_trust_tests>)
set_tests_properties(vitals_exact_trust PROPERTIES TIMEOUT 120)
