cmake_minimum_required(VERSION 3.16)
# Host tests of the app's C code, as the Vita's vitals-app/tests: the connection test's rules and
# its BrowserLeaks parser, boot_plugins.txt's editing, the custom certificates' merge and the
# changelog's layout, built for this machine with AddressSanitizer and UBSan; `make test` runs them,
# then the Python tests next to them
project(vitals_app_tests C)
set(CMAKE_C_STANDARD 11)

set(APP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

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

# The release number in GitHub's and GitLab's release responses, for the new-release notice (shared
# with the Vita's tests)
add_executable(vitals_app_release_version_tests ${SHARED}/app/tests/test_release_version.c ${SHARED}/app/release_version.c)
add_test(NAME vitals_app_release_version COMMAND vitals_app_release_version_tests)

# The user's certificates after Mozilla's, which install.c writes into system/cacert.pem
add_executable(vitals_app_custom_certs_tests test_custom_certs.c ${APP_DIR}/src/custom_certs.c)
target_include_directories(vitals_app_custom_certs_tests PRIVATE ${APP_DIR}/src ${APP_DIR}/../common)
add_test(NAME vitals_app_custom_certs COMMAND vitals_app_custom_certs_tests)
