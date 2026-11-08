cmake_minimum_required(VERSION 3.16)
# Host tests of the app's C code, as the Vita's vitals-app/tests: the connection test's rules and
# its BrowserLeaks parser, boot_plugins.txt's editing, Mozilla's part of the CA store and the
# changelog's layout, built for this machine with AddressSanitizer and UBSan; `make test` runs them,
# then the Python tests next to them
project(vitals_app_tests C)
set(CMAKE_C_STANDARD 11)

set(APP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

# The app's curl on Mbed TLS (../curl, ../crypto), as the PS3 builds it, for the shared download's
# tests (test_release_fetch.py): added before this folder's warnings and sanitizers, which aren't
# theirs
set(VITALS_SSL ${APP_DIR}/../vitals-ssl)
include(${APP_DIR}/../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
set(VITALS_PSA_USER_CONFIG "${APP_DIR}/crypto/psa_user_config.h")
add_subdirectory(${VITALS_SSL}/crypto mbedtls)
add_subdirectory(${APP_DIR}/curl curl)

option(VITALS_ENABLE_SANITIZERS "Build the tests with AddressSanitizer and UBSan" ON)
if(VITALS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
add_compile_options(-Wall -Wextra -Werror -UNDEBUG)
include(${APP_DIR}/../../version.cmake)
# The changelog, input and redirect list code shared with the Vita's app, which the app's headers include
set(SHARED ${APP_DIR}/../../shared)
include_directories(${SHARED}/app ${SHARED}/include)
add_compile_definitions(VITALS_VERSION="${VITALS_VERSION}")
enable_testing()

# The connection test's rules: how each result is judged and shown, the timeouts it retries, and
# the TLS report's parser
add_executable(vitals_app_check_model_tests test_check_model.c ${APP_DIR}/src/check_model.c ${SHARED}/app/model.c)
target_include_directories(vitals_app_check_model_tests PRIVATE ${APP_DIR}/src ${APP_DIR}/../common)
add_test(NAME vitals_app_check_model COMMAND vitals_app_check_model_tests)

# The connection test's run (shared with the Vita's tests), over a console that answers from a script
add_executable(vitals_app_check_run_tests ${SHARED}/app/tests/test_check_run.c ${SHARED}/app/check_run.c
    ${SHARED}/app/model.c ${SHARED}/src/redirect_list.c ${SHARED}/src/host_map.c)
target_include_directories(vitals_app_check_run_tests PRIVATE ${APP_DIR}/src ${APP_DIR}/../common)
add_test(NAME vitals_app_check_run COMMAND vitals_app_check_run_tests)

# The certificate update's checks and download (shared with the Vita's tests), with curl's bundle as
# the app carries it, on the app's Mbed TLS with this machine's mutexes, entropy and time
add_executable(vitals_app_ca_update_tests ${SHARED}/app/tests/test_ca_update.c ${SHARED}/app/ca_update.c
    ${SHARED}/src/store_certs.c ${APP_DIR}/../tests/host/crypto_platform_posix.c ${VITALS_SSL}/src/platform/gmtime.c)
target_include_directories(vitals_app_ca_update_tests PRIVATE ${APP_DIR}/src ${APP_DIR}/../common
    ${VITALS_SSL}/src/platform)
target_compile_definitions(vitals_app_ca_update_tests PRIVATE VITALS_TEST_BUNDLE="${APP_DIR}/assets/mozilla-certs.pem"
    VITALS_TEST_CRYPTO_PLATFORM=1 VITALS_MBEDTLS_PLATFORM=1)
target_link_libraries(vitals_app_ca_update_tests PRIVATE mbedx509 tfpsacrypto Threads::Threads)
add_test(NAME vitals_app_ca_update COMMAND vitals_app_ca_update_tests)

# The connection test's lifecycle (shared with the Vita's tests): its thread, cancelling and saving
find_package(Threads REQUIRED)
add_executable(vitals_app_check_service_tests ${SHARED}/app/tests/test_check_service.c ${SHARED}/app/check_service.c)
target_include_directories(vitals_app_check_service_tests PRIVATE ${APP_DIR}/src ${APP_DIR}/../common)
target_link_libraries(vitals_app_check_service_tests PRIVATE Threads::Threads)
add_test(NAME vitals_app_check_service COMMAND vitals_app_check_service_tests)

# The connection test's saved report (shared with the Vita's tests), with the PS3's results
add_executable(vitals_app_check_report_tests ${SHARED}/app/tests/test_check_report.c ${SHARED}/app/check_report.c
    ${SHARED}/app/model.c ${APP_DIR}/src/check_model.c)
target_include_directories(vitals_app_check_report_tests PRIVATE ${APP_DIR}/src ${APP_DIR}/../common)
add_test(NAME vitals_app_check_report COMMAND vitals_app_check_report_tests)

# boot_plugins.txt's editing, which install.c writes over the console's own list
add_executable(vitals_app_boot_plugins_tests test_boot_plugins.c ${APP_DIR}/src/boot_plugins.c)
target_include_directories(vitals_app_boot_plugins_tests PRIVATE ${APP_DIR}/src)
add_test(NAME vitals_app_boot_plugins COMMAND vitals_app_boot_plugins_tests)

# The changelog's layout, and the CHANGELOG.md the app carries, the repository's (shared with the Vita's tests)
add_executable(vitals_app_changelog_tests ${SHARED}/app/tests/test_changelog.c ${SHARED}/app/changelog.c)
target_include_directories(vitals_app_changelog_tests PRIVATE ${APP_DIR}/src)
target_compile_definitions(vitals_app_changelog_tests PRIVATE
    VITALS_CHANGELOG_FILE="${APP_DIR}/../../CHANGELOG.md")
add_test(NAME vitals_app_changelog COMMAND vitals_app_changelog_tests)

# The Options' switches on flag files, HTTP's three states among them (shared with the Vita's tests)
add_executable(vitals_app_switches_tests ${SHARED}/app/tests/test_switches.c ${SHARED}/app/switches.c)
add_test(NAME vitals_app_switches COMMAND vitals_app_switches_tests)

# The release number in GitHub's and GitLab's release responses, for the new-release notice (shared
# with the Vita's tests)
add_executable(vitals_app_release_version_tests ${SHARED}/app/tests/test_release_version.c ${SHARED}/app/release_version.c)
add_test(NAME vitals_app_release_version COMMAND vitals_app_release_version_tests)

# Mozilla's certificates without Sony's, which install.c writes into system/mozilla-certs.pem
# (shared with the Vita's app: ../../../shared/src/store_certs.c)
add_executable(vitals_app_store_certs_tests ${SHARED}/tests/test_store_certs.c ${SHARED}/src/store_certs.c)
target_include_directories(vitals_app_store_certs_tests PRIVATE ${SHARED}/include)
add_test(NAME vitals_app_store_certs COMMAND vitals_app_store_certs_tests)

# The shared download (../../../shared/app/download.c) and the release check's fetch on curl's Mbed
# TLS backend, the PS3's, with this machine's mutexes, entropy and time (../../tests/host): run by
# test_release_fetch.py against local HTTPS servers, as the Vita's tests run it on OpenSSL
find_package(Threads REQUIRED)
add_executable(vitals_app_release_fetch_mbedtls ${SHARED}/app/tests/release_fetch_cli.c ${SHARED}/app/download.c
    ${SHARED}/app/release_fetch.c ${SHARED}/app/release_version.c
    ${APP_DIR}/../tests/host/crypto_platform_posix.c ${VITALS_SSL}/src/platform/gmtime.c)
target_include_directories(vitals_app_release_fetch_mbedtls PRIVATE ${VITALS_SSL}/src/platform)
target_compile_definitions(vitals_app_release_fetch_mbedtls PRIVATE VITALS_MBEDTLS_PLATFORM=1)
target_link_libraries(vitals_app_release_fetch_mbedtls PRIVATE libcurl_static mbedtls mbedx509 tfpsacrypto
    Threads::Threads)
