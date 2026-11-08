cmake_minimum_required(VERSION 3.20)
project(vitals-ps3-http C ASM)

# PS3DK's CMake support (the vitals-ps3-sdk image): ps3_add_prx links the module and turns it into a PRX
include(ps3-self)
# vitals_add_prx: the module laid out as a console loads it (cmake/vitals.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/vitals.cmake)

# The debug log (0, 1 or 2: src/vh.h says what each logs)
set(VITALS_DEBUG 0 CACHE STRING "Log in vitals.log: 0 none, 1 calls, connections and handshakes, 2 also getters, reads and headers")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
	message(FATAL_ERROR "VITALS_DEBUG is 0, 1 or 2")
endif()

# The library's part of the default User-Agent, after "PS3Application " (make http USER_AGENT=...;
# useragent.txt on the console overrides it), with the Vita's vitals-http's rules for it
set(VITALS_HTTP_USER_AGENT "libhttp/4.9.3-000 (CellOS)" CACHE STRING "The default User-Agent's part after PS3Application")
string(LENGTH "${VITALS_HTTP_USER_AGENT}" VITALS_HTTP_USER_AGENT_LENGTH)
if(VITALS_HTTP_USER_AGENT_LENGTH EQUAL 0 OR VITALS_HTTP_USER_AGENT_LENGTH GREATER 127
   OR NOT VITALS_HTTP_USER_AGENT MATCHES "^[ -~]+$" OR VITALS_HTTP_USER_AGENT MATCHES "[\"\\#$;`']")
	message(FATAL_ERROR "VITALS_HTTP_USER_AGENT must be 1..127 printable ASCII characters, without \" \\ # $ ; ` '")
endif()

# libssl as Sony's libhttp imports it, by NID (cellssl_imports.yml, tools/gen_ssl_imports.py): with
# vitals installed, vitals' libssl answers
ps3_prx_stub_library(vitals_cellssl_stub EXPORTS cellssl_imports.yml)

# libhttp rewritten (README, plan step 5): init and end (src/core.c), clients (src/client.c),
# transactions (src/transaction.c), https through libssl (src/tls.c), header lists (src/headers.c), on the platform
# layer (src/platform/); the functions not written yet still say they were called (src/spike.c).
# Sony's two libraries are exported as Sony lays them out (src/exports.S)
add_executable(libhttp
	src/core.c
	src/client.c
	src/headers.c
	src/transaction.c
	src/tls.c
	src/proxy.c
	src/cookie.c
	src/md5.c
	src/auth.c
	src/cache.c
	src/inflate.c
	src/unnamed.c
	src/util.c
	src/redirect.c
	../../shared/src/host_map.c
	../../shared/src/redirect_list.c
	src/spike.c
	src/libc.c
	src/platform/platform_ps3.c
	src/exports.S)
target_include_directories(libhttp PRIVATE src ../common ../../shared/include)
target_compile_definitions(libhttp PRIVATE VITALS_DEBUG=${VITALS_DEBUG} VH_DEFAULT_SUFFIX="${VITALS_HTTP_USER_AGENT}")
# The release (../../VERSION) in the module's marker (common/vitals_marker.h)
include(${CMAKE_CURRENT_SOURCE_DIR}/../../version.cmake)
target_compile_definitions(libhttp PRIVATE VITALS_VERSION="${VITALS_VERSION}")
target_compile_options(libhttp PRIVATE -Os -Wall -Wextra -Werror -ffunction-sections -fdata-sections)
target_link_options(libhttp PRIVATE -nodefaultlibs -Wl,--gc-sections
	"-Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/libhttp.map")
target_link_libraries(libhttp PRIVATE vitals_cellssl_stub "${PS3DK}/ppu/lib/liblv2_stub.a" "${PS3DK}/ppu/lib/libnet_stub.a"
	"${PS3DK}/ppu/lib/libfs_stub.a" gcc)

# The module info as Sony's: cellHttp_Library 1.1, attributes 0x0006
vitals_add_prx(libhttp
	NAME cellHttp_Library
	VERSION 1.1
	ATTRIBUTES 0x0006
	OUTPUT_NAME libhttp.prx
	SIGN)
