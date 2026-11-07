cmake_minimum_required(VERSION 3.20)
project(vitals-ps3-ssl C ASM)

# PS3DK's CMake support (the vitals-ps3-sdk image): ps3_add_prx links the module and turns it into a PRX
include(ps3-self)
# vitals_add_prx: the module laid out as a console loads it (cmake/vitals.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/vitals.cmake)

# TLS is Mbed TLS 4.2 with TF-PSA-Crypto, patched as vitals' (crypto/)
include(${CMAKE_CURRENT_SOURCE_DIR}/../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(crypto)

# The debug log (0, 1 or 2: src/vs.h says what each logs), and whether to connect without libhttp's certificate check,
# which can't be called until the certificate functions are written (for trying the rest)
set(VITALS_DEBUG 0 CACHE STRING "Log on the TTY and in vitals.log: 0 none, 1 calls and connections, 2 also reads, writes and HTTP headers")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
	message(FATAL_ERROR "VITALS_DEBUG is 0, 1 or 2")
endif()
option(VITALS_SSL_UNVERIFIED "Connect without checking the server's certificate (testing only)" OFF)

# The library (src/core.c), connections (src/connection.c), on the platform layer (src/platform/);
# the functions not written yet say they were called (src/spike.c)
add_executable(libssl
	src/core.c
	src/ca_store.c
	src/sha1.c
	src/certificate.c
	src/connection.c
	src/public.c
	src/spike.c
	src/exports.S
	src/platform/crypto_platform.c
	src/platform/gmtime.c
	src/platform/libc.c
	src/platform/platform_ps3.c
	src/platform/pool.c)
target_compile_definitions(libssl PRIVATE VITALS_DEBUG=${VITALS_DEBUG})
if(VITALS_SSL_UNVERIFIED)
	target_compile_definitions(libssl PRIVATE VITALS_SSL_UNVERIFIED=1)
	message(WARNING "VITALS_SSL_UNVERIFIED: servers' certificates aren't checked")
endif()
target_include_directories(libssl PRIVATE src src/platform ../common)
target_compile_options(libssl PRIVATE -Os -Wall -Wextra -Werror -ffunction-sections -fdata-sections)
# No libc of its own: what Mbed TLS needs from one is liblv2's (src/platform/libc.c), as Sony's
# libssl, so anything else it reaches for fails the link
target_link_options(libssl PRIVATE -nodefaultlibs -Wl,--gc-sections
	# Where each function lands, for reading a crash's address (build/vitals-ssl/libssl.map)
	"-Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/libssl.map")
target_link_libraries(libssl PRIVATE mbedtls mbedx509 tfpsacrypto
	"${PS3DK}/ppu/lib/liblv2_stub.a" "${PS3DK}/ppu/lib/libnet_stub.a"
	"${PS3DK}/ppu/lib/libfs_stub.a" gcc)

# The module info as Sony's: cellSsl_Library 1.1, attributes 0x0006
vitals_add_prx(libssl
	NAME cellSsl_Library
	VERSION 1.1
	ATTRIBUTES 0x0006
	OUTPUT_NAME libssl.prx
	SIGN)
