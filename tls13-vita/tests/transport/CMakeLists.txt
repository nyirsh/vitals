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
# The loopback test places memory at fixed low addresses, as the Vita's 32-bit pointers need,
# which only Linux allows
if(VITALS_FIXED_ADDRESS_TESTS)
add_executable(vitals_transport_tests
    ../../provider/ca_file.c
    ../../provider/ca_index.c
    test_transport.c
    taihen_mock.c
    ../../provider/cert_hooks.c
    ../../provider/platform_shims.c
    ../../provider/private_mapping.c
    ../../provider/transport.c
    ../../provider/trust_store.c
    ../../provider/vita_net.c
)
target_include_directories(vitals_transport_tests PRIVATE ../../provider)
target_compile_options(vitals_transport_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(vitals_transport_tests PRIVATE -no-pie)
target_link_libraries(vitals_transport_tests PRIVATE vitals_core mbedtls vitals_vita_mock)
add_test(NAME vitals_transport_loopback
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_loopback.py"
            $<TARGET_FILE:vitals_transport_tests>)
set_tests_properties(vitals_transport_loopback PROPERTIES TIMEOUT 120)
endif()

# Game certificates (sceHttpsLoadCert), checked with roots from the bundled store
add_executable(vitals_game_ca_tests test_game_ca.c ../../provider/platform_shims.c)
target_include_directories(vitals_game_ca_tests PRIVATE ../../provider)
target_link_libraries(vitals_game_ca_tests PRIVATE vitals_core mbedtls vitals_vita_mock)
target_compile_options(vitals_game_ca_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_game_ca COMMAND vitals_game_ca_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../vitals-app/assets/certs.cer")
set_tests_properties(vitals_game_ca PROPERTIES TIMEOUT 30)

# A self-signed server certificate trusted by exact match (ca_index.c), with real certificates
add_executable(vitals_exact_trust_tests test_exact_trust.c ../../provider/ca_index.c ../../provider/platform_shims.c)
target_include_directories(vitals_exact_trust_tests PRIVATE ../../provider ../../include)
target_link_libraries(vitals_exact_trust_tests PRIVATE mbedtls vitals_vita_mock)
target_compile_options(vitals_exact_trust_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_exact_trust
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_exact_trust.py"
            $<TARGET_FILE:vitals_exact_trust_tests>)
set_tests_properties(vitals_exact_trust PROPERTIES TIMEOUT 120)

add_executable(vitals_trust_store_tests
    ../../provider/ca_file.c
    ../../provider/ca_index.c
    test_trust_store.c ../../provider/platform_shims.c ../../provider/trust_store.c)
target_include_directories(vitals_trust_store_tests PRIVATE ../../provider ../../include)
target_link_libraries(vitals_trust_store_tests PRIVATE mbedtls vitals_vita_mock)
target_compile_options(vitals_trust_store_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_trust_store COMMAND vitals_trust_store_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../vitals-app/assets/certs.cer")
set_tests_properties(vitals_trust_store PROPERTIES TIMEOUT 30)
