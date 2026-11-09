# The vitals app: one .self and a .pkg carrying vitals' modules (the Makefile's app target stages them
# in STAGING: USRDIR's libssl builds, the boot plugin, Mozilla's bundle, the changelog, the third-party
# notices and licenses, and PIC1.PNG)
cmake_minimum_required(VERSION 3.20)
project(vitals-app C)

include(ps3-self)

# VERSION's number (version.cmake, the Vita's): VITALS_VERSION ("1.5") and VITALS_APP_VERSION, the
# package's ##.## ("01.05"), PARAM.SFO's APP_VER
include(${CMAKE_CURRENT_SOURCE_DIR}/../../version.cmake)
set(VITALS_TITLE_ID "VTLS00001")
set(VITALS_CONTENT_ID "UP0001-${VITALS_TITLE_ID}_00-VITALSTLSTOOLKIT")
set(STAGING "${CMAKE_CURRENT_BINARY_DIR}/pkg_files" CACHE PATH "The .pkg's other files, as the Makefile stages them")

# The app's downloads go through curl on Mbed TLS (../../shared/curl, the Vita's too), the same Mbed TLS as vitals' libssl,
# built with the app's crypto options (crypto/psa_user_config.h)
include(${CMAKE_CURRENT_SOURCE_DIR}/../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
set(VITALS_PSA_USER_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/crypto/psa_user_config.h")
add_subdirectory(../vitals-ssl/crypto "${CMAKE_CURRENT_BINARY_DIR}/mbedtls")
add_subdirectory(../../shared/curl "${CMAKE_CURRENT_BINARY_DIR}/curl")

add_executable(vitals-app
	# The app itself, the same on the Vita (../../shared/app)
	../../shared/app/app.c
	../../shared/app/ui.c
	../../shared/app/font.c
	../../shared/app/changelog.c
	../../shared/app/switches.c
	../../shared/app/check_run.c
	../../shared/app/check_service.c
	../../shared/app/check_report.c
	../../shared/app/input.c
	../../shared/app/release_version.c
	../../shared/app/release_check.c
	../../shared/app/release_fetch.c
	../../shared/app/download.c
	../../shared/app/ca_update.c
	../../shared/app/installed.c
	# The PS3's part of it (console.h, platform.h, check.h)
	src/main.c
	src/console_ps3.c
	src/firmware.c
	src/app_log.c
	src/platform_ps3.c
	src/files_ps3.c
	src/font_ps3.c
	src/check.c
	src/check_model.c
	../../shared/app/model.c
	src/http.c
	src/install.c
	../../shared/src/store_certs.c
	src/boot_plugins.c
	# Mbed TLS's mutexes, entropy and time on the PS3, as vitals' libssl has them
	../vitals-ssl/src/platform/crypto_platform.c
	../vitals-ssl/src/platform/gmtime.c
	# The host redirect list's parser, shared with the Vita, as vitals' libhttp reads the list
	../../shared/src/host_map.c
	../../shared/src/redirect_list.c)
# With the app and the redirect list code shared with the Vita (../../shared)
target_include_directories(vitals-app PRIVATE src ../common ../../shared/include ../../shared/app
	../vitals-ssl/src/platform)
target_compile_features(vitals-app PRIVATE c_std_11)
# Optimised: the PPU is in order, and the screens are drawn and scaled to 1080p in software
target_compile_options(vitals-app PRIVATE -O2 -Wall -Wextra -Werror)
target_compile_definitions(vitals-app PRIVATE VITALS_VERSION="${VITALS_VERSION}" VITALS_TITLE_ID="${VITALS_TITLE_ID}"
	VITALS_LOG_NAME="vitals-app" VITALS_LOG_APP)
target_link_libraries(vitals-app PRIVATE
	libcurl_static mbedtls mbedx509 tfpsacrypto
	http_stub ssl_stub rtc_stub netctl_stub net_stub fontFT_stub font_stub fs_stub sysmodule_stub io_stub
	gcm_sys rsx io sysutil rt lv2 m)

ps3_add_self(vitals-app)
configure_file(pkg/sfo.xml.in "${CMAKE_CURRENT_BINARY_DIR}/sfo.xml" @ONLY)
ps3_add_pkg(vitals-app
	TITLE "vitals"
	CONTENTID "${VITALS_CONTENT_ID}"
	ICON "${CMAKE_CURRENT_SOURCE_DIR}/pkg/ICON0.PNG"
	SFOXML "${CMAKE_CURRENT_BINARY_DIR}/sfo.xml"
	PKGFILES "${STAGING}")
