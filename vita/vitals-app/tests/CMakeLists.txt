cmake_minimum_required(VERSION 3.16)
# Host tests of the app's C code: install options, config.txt editing, the connection test and the
# certificate update, built for this machine; `make test` runs them, then the Python tests next to them
project(vitals_app_tests C)
set(CMAKE_C_STANDARD 11)

set(APP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
# The app shared with the PS3's (../../shared/app), whose headers include the Vita's own vitals_paths.h
# and check_result.h from this app's folder, which each test adds
set(SHARED_APP ${APP_DIR}/../../shared/app)
include_directories(AFTER ${SHARED_APP})
# vitals/path.h: where the kernel plugin and the installer keep vitals' modules
include_directories(AFTER ${APP_DIR}/../common/include)

# Mbed TLS on this machine, as vitals-ssl builds it but with the host's defaults
# (../../../shared/tests/psa_host_config.h), and the app's curl on it (../../../shared/curl), for the
# certificate update's test and the shared download's: added before this folder's warnings and
# sanitizers, which aren't theirs
include(${APP_DIR}/../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
set(VITALS_PSA_USER_CONFIG "${APP_DIR}/../../shared/tests/psa_host_config.h")
add_subdirectory(${APP_DIR}/../vitals-ssl/crypto mbedtls)
add_subdirectory(${APP_DIR}/../../shared/curl curl)

option(VITALS_ENABLE_SANITIZERS "Build the tests with AddressSanitizer and UBSan" ON)
if(VITALS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
add_compile_options(-Wall -Wextra -Werror -UNDEBUG)
include(${APP_DIR}/../../version.cmake)
add_compile_definitions(VITALS_VERSION="${VITALS_VERSION}")
enable_testing()
# zlib reads the compressed module headers (module_version.c)
find_package(ZLIB REQUIRED)

add_executable(vitals_app_options_tests test_options.c ${APP_DIR}/options.c)
target_include_directories(vitals_app_options_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_options COMMAND vitals_app_options_tests)

# The connection test's rules: the badssl.com battery and how each of its results is judged, with the
# model shared with the PS3 (the endpoints, the battery, the TLS report's parser)
add_executable(vitals_app_check_model_tests test_check_model.c ${APP_DIR}/check_model.c ${SHARED_APP}/model.c)
target_include_directories(vitals_app_check_model_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_check_model COMMAND vitals_app_check_model_tests)

# The connection test's run (shared with the PS3's tests), over a console that answers from a script
add_executable(vitals_app_check_run_tests ${SHARED_APP}/tests/test_check_run.c ${SHARED_APP}/check_run.c
    ${SHARED_APP}/model.c ${APP_DIR}/check_model.c ${APP_DIR}/../../shared/src/redirect_list.c ${APP_DIR}/../../shared/src/host_map.c)
target_include_directories(vitals_app_check_run_tests PRIVATE ${APP_DIR} ${APP_DIR}/../../shared/include)
add_test(NAME vitals_app_check_run COMMAND vitals_app_check_run_tests)

# The certificate update's checks and download (shared with the PS3's tests), with curl's bundle as the
# app carries it
add_executable(vitals_app_ca_update_tests ${SHARED_APP}/tests/test_ca_update.c ${SHARED_APP}/ca_update.c
    ${APP_DIR}/../../shared/src/store_certs.c)
target_include_directories(vitals_app_ca_update_tests PRIVATE ${APP_DIR} ${APP_DIR}/../../shared/include)
target_compile_definitions(vitals_app_ca_update_tests PRIVATE VITALS_TEST_BUNDLE="${APP_DIR}/assets/mozilla-certs.pem")
target_link_libraries(vitals_app_ca_update_tests PRIVATE mbedx509 tfpsacrypto)
add_test(NAME vitals_app_ca_update COMMAND vitals_app_ca_update_tests)

# The connection test's lifecycle (shared with the PS3's tests): its thread, cancelling and saving
find_package(Threads REQUIRED)
add_executable(vitals_app_check_service_tests ${SHARED_APP}/tests/test_check_service.c ${SHARED_APP}/check_service.c)
target_include_directories(vitals_app_check_service_tests PRIVATE ${APP_DIR} ${APP_DIR}/../../shared/include)
target_link_libraries(vitals_app_check_service_tests PRIVATE Threads::Threads)
add_test(NAME vitals_app_check_service COMMAND vitals_app_check_service_tests)

# The connection test's saved report (shared with the PS3's tests), with the Vita's results
add_executable(vitals_app_check_report_tests ${SHARED_APP}/tests/test_check_report.c ${SHARED_APP}/check_report.c
    ${SHARED_APP}/model.c ${APP_DIR}/check_model.c)
target_include_directories(vitals_app_check_report_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_check_report COMMAND vitals_app_check_report_tests)

# The changelog's layout, and the CHANGELOG.md the app carries (the repository's)
add_executable(vitals_app_changelog_tests ${SHARED_APP}/tests/test_changelog.c ${SHARED_APP}/changelog.c)
target_include_directories(vitals_app_changelog_tests PRIVATE ${APP_DIR})
target_compile_definitions(vitals_app_changelog_tests PRIVATE
    VITALS_CHANGELOG_FILE="${APP_DIR}/../../CHANGELOG.md")
add_test(NAME vitals_app_changelog COMMAND vitals_app_changelog_tests)

# The Options' switches on flag files, HTTP's three states among them (shared with the PS3's tests)
add_executable(vitals_app_switches_tests ${SHARED_APP}/tests/test_switches.c ${SHARED_APP}/switches.c)
add_test(NAME vitals_app_switches COMMAND vitals_app_switches_tests)

# Mozilla's part of the certificate store without Sony's, as both consoles' apps write it (shared with
# the PS3's tests)
add_executable(vitals_app_store_certs_tests ${APP_DIR}/../../shared/tests/test_store_certs.c
    ${APP_DIR}/../../shared/src/store_certs.c)
target_include_directories(vitals_app_store_certs_tests PRIVATE ${APP_DIR}/../../shared/include)
add_test(NAME vitals_app_store_certs COMMAND vitals_app_store_certs_tests)

add_executable(vitals_app_config_edit_tests test_config_edit.c ${APP_DIR}/config_edit.c)
target_include_directories(vitals_app_config_edit_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_config_edit COMMAND vitals_app_config_edit_tests)

# The installer's file operations, on a console mapped onto a temporary folder (vita_files.c)
add_executable(vitals_app_install_files_tests test_install_files.c vita_files.c ${APP_DIR}/install.c
    ${APP_DIR}/options.c ${APP_DIR}/config_edit.c ${APP_DIR}/module_version.c)
target_include_directories(vitals_app_install_files_tests PRIVATE include ${APP_DIR} ${APP_DIR}/../../shared/include)
target_link_libraries(vitals_app_install_files_tests PRIVATE ZLIB::ZLIB)
add_test(NAME vitals_app_install_files COMMAND vitals_app_install_files_tests)

# Reading a module's version from its file header, which the app shows for the installed plugin
add_executable(vitals_app_module_version_tests test_module_version.c vita_files.c ${APP_DIR}/module_version.c)
target_include_directories(vitals_app_module_version_tests PRIVATE include ${APP_DIR})
target_link_libraries(vitals_app_module_version_tests PRIVATE ZLIB::ZLIB)
add_test(NAME vitals_app_module_version COMMAND vitals_app_module_version_tests)

# The release number in GitHub's and GitLab's release responses, for the new-version notice
add_executable(vitals_app_release_version_tests ${SHARED_APP}/tests/test_release_version.c ${SHARED_APP}/release_version.c)
add_test(NAME vitals_app_release_version COMMAND vitals_app_release_version_tests)

# The shared download (../../../shared/app/download.c) and the release check's fetch on the app's
# curl and Mbed TLS, run by test_version_check.py against local HTTPS servers, as the PS3's tests run it
find_package(Threads REQUIRED)
add_executable(vitals_app_release_fetch_mbedtls ${SHARED_APP}/tests/release_fetch_cli.c ${SHARED_APP}/download.c
    ${SHARED_APP}/release_fetch.c ${SHARED_APP}/release_version.c)
target_link_libraries(vitals_app_release_fetch_mbedtls PRIVATE libcurl_static mbedtls mbedx509 tfpsacrypto
    Threads::Threads)
