cmake_minimum_required(VERSION 3.20)
project(vitals-ps3-plugin C ASM)

include(ps3-self)
# vitals_add_prx: the module laid out as a console loads it (cmake/vitals.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/vitals.cmake)
# VERSION's number, for the boot popup's title (version.cmake, the Vita's)
include(${CMAKE_CURRENT_SOURCE_DIR}/../../version.cmake)

# The debug log, a build per level as libssl's and libhttp's (src/boot.c says what each logs)
set(VITALS_DEBUG 0 CACHE STRING "Log in vitals.log: 0 none, 1 what happened at boot, 2 also addresses, codes and times")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
	message(FATAL_ERROR "VITALS_DEBUG is 0, 1 or 2")
endif()

# vitals' TLS for the XMB itself (src/xmb.c), off: vitals' libssl in the XMB, even unused, takes the
# system down when a game starts. For working on it only (make plugin XMB=1); the
# dry runs below build it too
option(VITALS_XMB "Put vitals' libssl in the XMB's own SSL-C's place" OFF)
# The XMB's own TLS checked and vitals' libssl loaded into it, nothing written (src/xmb.c): for a
# first boot with it (make plugin XMB_DRY_RUN=1)
option(VITALS_XMB_DRY_RUN "Check the XMB and load vitals' libssl into it, without patching it" OFF)
set(VITALS_BOOT_DEFINITIONS VITALS_DEBUG=${VITALS_DEBUG} VITALS_VERSION="${VITALS_VERSION}")
if(VITALS_XMB_DRY_RUN)
	list(APPEND VITALS_BOOT_DEFINITIONS VITALS_XMB_DRY_RUN)
endif()
# The dry run, with vitals' libssl left loaded in the XMB: what its memory alone does (make plugin
# XMB_DRY_RUN=keep)
option(VITALS_XMB_KEEP_LOADED "With VITALS_XMB_DRY_RUN, leave vitals' libssl loaded in the XMB" OFF)
if(VITALS_XMB_KEEP_LOADED)
	list(APPEND VITALS_BOOT_DEFINITIONS VITALS_XMB_KEEP_LOADED)
endif()
# Nothing loaded into the XMB at all, only its free memory watched: what launching an app takes
# with Sony's TLS alone (make plugin XMB_DRY_RUN=watch)
option(VITALS_XMB_WATCH_ONLY "Load nothing into the XMB, only watch its free memory" OFF)
if(VITALS_XMB_WATCH_ONLY)
	list(APPEND VITALS_BOOT_DEFINITIONS VITALS_XMB_WATCH_ONLY VITALS_XMB_KEEP_LOADED)
endif()
set(VITALS_BOOT_SOURCES src/boot.c ../../shared/src/host_map.c)
if(VITALS_XMB OR VITALS_XMB_DRY_RUN)
	list(APPEND VITALS_BOOT_DEFINITIONS VITALS_XMB)
	list(APPEND VITALS_BOOT_SOURCES src/xmb.c src/xmb_bridge.S)
endif()

# The boot plugin Cobra loads into the XMB: redirects Sony's libssl to vitals' (src/boot.c), and
# gives the XMB vitals' TLS (src/xmb.c, src/xmb_bridge.S)
# With the redirect list's parser, for the boot notification's count (../../shared/src/host_map.c)
add_executable(vitals_boot ${VITALS_BOOT_SOURCES})
target_include_directories(vitals_boot PRIVATE ../common ../../shared/include)
target_compile_options(vitals_boot PRIVATE -Os -Wall -Wextra -Werror)
target_compile_definitions(vitals_boot PRIVATE ${VITALS_BOOT_DEFINITIONS})

vitals_add_prx(vitals_boot
    NAME vitals_boot
    VERSION 1.0
    OUTPUT_NAME vitals_boot.prx
    SIGN)

# The same plugin staying loaded once started, for checking that the loader takes it (see boot.c)
add_executable(vitals_boot_stay ${VITALS_BOOT_SOURCES})
target_include_directories(vitals_boot_stay PRIVATE ../common ../../shared/include)
target_compile_definitions(vitals_boot_stay PRIVATE VITALS_BOOT_STAY ${VITALS_BOOT_DEFINITIONS})
target_compile_options(vitals_boot_stay PRIVATE -Os -Wall -Wextra -Werror)
vitals_add_prx(vitals_boot_stay
    NAME vitals_boot
    VERSION 1.0
    OUTPUT_NAME vitals_boot_stay.prx
    SIGN)
