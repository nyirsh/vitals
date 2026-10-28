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
# zlib reads the compressed module headers (module_version.c)
find_package(ZLIB REQUIRED)

add_executable(vitals_app_options_tests test_options.c ${APP_DIR}/options.c)
target_include_directories(vitals_app_options_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_options COMMAND vitals_app_options_tests)

# The connection test's rules: the badssl.com battery and how each of its results is judged
add_executable(vitals_app_check_model_tests test_check_model.c ${APP_DIR}/model.c)
target_include_directories(vitals_app_check_model_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_check_model COMMAND vitals_app_check_model_tests)

# The changelog's layout, and the CHANGELOG.md the app carries
add_executable(vitals_app_changelog_tests test_changelog.c ${APP_DIR}/changelog.c)
target_include_directories(vitals_app_changelog_tests PRIVATE ${APP_DIR})
target_compile_definitions(vitals_app_changelog_tests PRIVATE
    VITALS_CHANGELOG_FILE="${APP_DIR}/../CHANGELOG.md")
add_test(NAME vitals_app_changelog COMMAND vitals_app_changelog_tests)

add_executable(vitals_app_config_edit_tests test_config_edit.c ${APP_DIR}/config_edit.c)
target_include_directories(vitals_app_config_edit_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_config_edit COMMAND vitals_app_config_edit_tests)

# The installer's file operations, on a console mapped onto a temporary folder (vita_files.c)
add_executable(vitals_app_install_files_tests test_install_files.c vita_files.c ${APP_DIR}/install.c
    ${APP_DIR}/options.c ${APP_DIR}/config_edit.c ${APP_DIR}/module_version.c)
target_include_directories(vitals_app_install_files_tests PRIVATE include ${APP_DIR})
target_link_libraries(vitals_app_install_files_tests PRIVATE ZLIB::ZLIB)
add_test(NAME vitals_app_install_files COMMAND vitals_app_install_files_tests)

# Reading a module's version from its file header, which the app shows for the installed plugin
add_executable(vitals_app_module_version_tests test_module_version.c vita_files.c ${APP_DIR}/module_version.c)
target_include_directories(vitals_app_module_version_tests PRIVATE include ${APP_DIR})
target_link_libraries(vitals_app_module_version_tests PRIVATE ZLIB::ZLIB)
add_test(NAME vitals_app_module_version COMMAND vitals_app_module_version_tests)

# The release number in GitHub's and GitLab's release responses, for the new-version notice
add_executable(vitals_app_release_version_tests test_release_version.c ${APP_DIR}/release_version.c)
target_include_directories(vitals_app_release_version_tests PRIVATE ${APP_DIR})
add_test(NAME vitals_app_release_version COMMAND vitals_app_release_version_tests)

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
