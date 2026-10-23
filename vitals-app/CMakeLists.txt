cmake_minimum_required(VERSION 3.16)
project(vitals_app C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

# App metadata; the version is set in ../VERSION
set(VITALS_TITLE_ID "VITALS001")
set(VITALS_TITLE "vitals")
include(../version.cmake)

# The kernel plugin, TLS providers and PSN redirect this VPK installs, built by ../vitals-plugin,
# ../tls13-vita and ../vitals-reauth
set(VITALS_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../build")
set(VITALS_KERNEL_MODULE "${VITALS_BUILD_DIR}/vitals-plugin/vitals.skprx")
set(VITALS_HTTP_PROVIDER "${VITALS_BUILD_DIR}/tls13-vita/provider/vitals_http.suprx")
set(VITALS_BROWSER_PROVIDER "${VITALS_BUILD_DIR}/tls13-vita/browser/vitals.suprx")
set(VITALS_REAUTH_MODULE "${VITALS_BUILD_DIR}/vitals-reauth/vitals-reauth.suprx")
foreach(module VITALS_KERNEL_MODULE VITALS_HTTP_PROVIDER VITALS_BROWSER_PROVIDER VITALS_REAUTH_MODULE)
    if(NOT EXISTS "${${module}}")
        message(FATAL_ERROR "${${module}} is missing; build ../vitals-plugin, ../tls13-vita and ../vitals-reauth first (make does this)")
    endif()
endforeach()
# The debug builds of the providers and redirect (levels 1 and 2), which the app switches to;
# they go in debug/<level>/ next to the release modules
set(debug_entries)
foreach(level 1 2)
    foreach(module tls13-vita-debug${level}/provider/vitals_http.suprx tls13-vita-debug${level}/browser/vitals.suprx
            vitals-reauth-debug${level}/vitals-reauth.suprx)
        if(NOT EXISTS "${VITALS_BUILD_DIR}/${module}")
            message(FATAL_ERROR "${VITALS_BUILD_DIR}/${module} is missing; build every debug level first (make does this)")
        endif()
        get_filename_component(name "${module}" NAME)
        list(APPEND debug_entries "${VITALS_BUILD_DIR}/${module}" "debug/${level}/${name}")
    endforeach()
endforeach()

# libcurl, used to download the latest Mozilla CA bundle
add_subdirectory(curl)

add_executable(vitals-app
    main.c
    install.c
    module_version.c
    config_edit.c
    check.c
    ui.c
    certificates.c
    crypto_lock_vita.c
    options.c
    font.c
    font_vita.c
    input.c
    model.c
    probe.c
)
target_compile_options(vitals-app PRIVATE -Wall -Wextra -Werror -O2 -std=gnu11)
target_compile_definitions(vitals-app PRIVATE VITALS_VERSION="${VITALS_VERSION}")
# OpenSSL's locking goes through the Vita's native locks (crypto_lock_vita.c)
foreach(function CRYPTO_THREAD_lock_new CRYPTO_THREAD_read_lock CRYPTO_THREAD_write_lock
        CRYPTO_THREAD_unlock CRYPTO_THREAD_lock_free CRYPTO_atomic_add)
    target_link_options(vitals-app PRIVATE "-Wl,--wrap=${function}")
endforeach()
target_link_libraries(vitals-app PRIVATE libcurl_static
    ssl crypto pthread z zstd m
    ScePvf_stub SceHttp_stub SceSsl_stub SceNet_stub SceNetCtl_stub
    SceSysmodule_stub SceDisplay_stub SceCtrl_stub ScePower_stub SceVshBridge_stub SceRtc_stub
    SceLibKernel_stub SceIofilemgr_stub SceKernelThreadMgr_stub SceKernelModulemgr_stub
    SceSysmem_stub SceProcessmgr_stub)

# UNSAFE: installing needs system access (firmware version, vs0 and ur0 writes, reboot)
vita_create_self(eboot.bin vitals-app UNSAFE)

# The third-party notices ship with the licenses they refer to, next to the README
file(GLOB license_files "${CMAKE_CURRENT_SOURCE_DIR}/../licenses/*.txt")
set(license_entries)
foreach(license ${license_files})
    get_filename_component(name "${license}" NAME)
    list(APPEND license_entries "${license}" "licenses/${name}")
endforeach()

vita_create_vpk(vitals-app.vpk ${VITALS_TITLE_ID} eboot.bin
    VERSION ${VITALS_APP_VERSION}
    NAME ${VITALS_TITLE}
    FILE sce_sys/icon0.png sce_sys/icon0.png
         sce_sys/livearea/contents/bg.png sce_sys/livearea/contents/bg.png
         sce_sys/livearea/contents/template.xml sce_sys/livearea/contents/template.xml
         ${VITALS_KERNEL_MODULE} vitals.skprx
         assets/compat.suprx compat.suprx
         assets/lhttp.suprx lhttp.suprx
         assets/lssl.suprx lssl.suprx
         ${VITALS_HTTP_PROVIDER} vitals_http.suprx
         ${VITALS_BROWSER_PROVIDER} vitals.suprx
         ${VITALS_REAUTH_MODULE} vitals-reauth.suprx
         ${debug_entries}
         ../README.md README.md
         ../THIRD_PARTY_NOTICES.md THIRD_PARTY_NOTICES.md
         ${license_entries}
         assets/sony-certs.pem sony-certs.pem
         assets/mozilla-certs.pem mozilla-certs.pem
         assets/certificate-sources.json certificate-sources.json
         assets/certs.cer certs.cer
         assets/redirects.txt redirects.txt
)
