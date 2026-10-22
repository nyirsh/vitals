cmake_minimum_required(VERSION 3.16)
# Host tests of the app's C code: install options, config.txt editing and the OpenSSL locking
# adapter, built for this machine; `make test` runs them, then the Python tests next to them
project(vitals_app_tests C)
set(CMAKE_C_STANDARD 11)

set(APP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

option(VITALS_ENABLE_SANITIZERS "Build the tests with AddressSanitizer and UBSan" ON)
if(VITALS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
add_compile_options(-Wall -Wextra -Werror -UNDEBUG)
include(${APP_DIR}/../version.cmake)
add_compile_definitions(VITALS_VERSION="${VITALS_VERSION}")
enable_testing()

add_executable(vitals_app_options_tests test_options.c ${APP_DIR}/options.c)
target_include_directories(vitals_app_options_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_options COMMAND vitals_app_options_tests)

add_executable(vitals_app_config_edit_tests test_config_edit.c ${APP_DIR}/config_edit.c)
target_include_directories(vitals_app_config_edit_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_config_edit COMMAND vitals_app_config_edit_tests)

# The installer's file operations, on a console mapped onto a temporary folder (vita_files.c)
add_executable(vitals_app_install_files_tests test_install_files.c vita_files.c ${APP_DIR}/install.c
    ${APP_DIR}/options.c ${APP_DIR}/config_edit.c)
target_include_directories(vitals_app_install_files_tests PRIVATE include ${APP_DIR})
add_test(NAME vitals_app_install_files COMMAND vitals_app_install_files_tests)

# The locking adapter only needs OpenSSL's headers; Homebrew's default OpenSSL on macOS, the
# system's on Linux (libssl-dev)
find_path(OPENSSL_HEADERS openssl/crypto.h
    HINTS /opt/homebrew/opt/openssl/include /usr/local/opt/openssl/include)
if(OPENSSL_HEADERS)
    find_package(Threads REQUIRED)
    add_executable(vitals_app_crypto_lock_tests fixtures/crypto_lock/test_lock.c)
    target_include_directories(vitals_app_crypto_lock_tests PRIVATE fixtures/crypto_lock ${OPENSSL_HEADERS})
    target_link_libraries(vitals_app_crypto_lock_tests PRIVATE Threads::Threads)
    add_test(NAME vitals_app_crypto_lock COMMAND vitals_app_crypto_lock_tests)
else()
    # Reported as skipped rather than left out, so a missing dependency stays visible
    add_test(NAME vitals_app_crypto_lock
        COMMAND sh -c "echo 'OpenSSL development headers not found (libssl-dev, or brew install openssl)'; exit 77")
    set_tests_properties(vitals_app_crypto_lock PROPERTIES SKIP_RETURN_CODE 77)
endif()
