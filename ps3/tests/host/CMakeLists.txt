cmake_minimum_required(VERSION 3.20)
project(vitals_ps3_ssl_tests C)

# vitals' libssl built for this machine, with the host's platform (this folder's *_posix.c in place
# of vitals-ssl/src/platform/'s console ones; gmtime.c is the console's own), and the same Mbed TLS,
# called as Sony's libhttp calls it, against server.py (run_tests.py):
#   cmake -S tests/host -B build/tests-host && cmake --build build/tests-host && ctest --test-dir build/tests-host
set(SSL ${CMAKE_CURRENT_SOURCE_DIR}/../../vitals-ssl)
# What both consoles share (the repository's shared/)
set(SHARED ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared)
include(${CMAKE_CURRENT_SOURCE_DIR}/../../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(${SSL}/crypto crypto)

find_package(Threads REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()

add_executable(vitals_ssl_tests
	${SSL}/src/core.c
	${SSL}/src/ca_store.c
	${SSL}/src/sha1.c
	${SSL}/src/certificate.c
	${SSL}/src/connection.c
	${SSL}/src/public.c
	${SSL}/src/platform/gmtime.c
	platform_posix.c
	pool_posix.c
	crypto_platform_posix.c
	test_main.c)
# include/ first: its vitals_log.h in place of the console's
target_include_directories(vitals_ssl_tests BEFORE PRIVATE include)
target_include_directories(vitals_ssl_tests PRIVATE ${SSL}/src ${SSL}/src/platform)
# With the debug log compiled in, so its lines run too
target_compile_definitions(vitals_ssl_tests PRIVATE VITALS_DEBUG=2)
target_compile_options(vitals_ssl_tests PRIVATE -std=gnu11 -g -Wall -Wextra -Werror
	-fsanitize=address,undefined -fno-omit-frame-pointer)
target_link_options(vitals_ssl_tests PRIVATE -fsanitize=address,undefined)
target_link_libraries(vitals_ssl_tests PRIVATE mbedtls mbedx509 tfpsacrypto Threads::Threads)

add_test(NAME vitals_ssl
	COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py $<TARGET_FILE:vitals_ssl_tests>)
set_tests_properties(vitals_ssl PROPERTIES TIMEOUT 180)

# The libhttp probe (tests/http-probe) on this machine, against vitals' libhttp and libssl built
# for it with AddressSanitizer (tests/host/http): its lines diffed against Sony's, as an RPCS3 run's
# are (tools/http_probe.sh host). The probe and libhttp include PS3DK's cell/http and cell/ssl
# headers: `make test` copies them out of the SDK image into build/ps3dk-include (MIT, PS3DK's
# LICENSE), and without them this test isn't built
set(VITALS_PS3DK_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ps3dk-include CACHE PATH "PS3DK's cell/http and cell/ssl headers")
if(EXISTS ${VITALS_PS3DK_INCLUDE}/cell/http.h)
	set(HTTP ${CMAKE_CURRENT_SOURCE_DIR}/../../vitals-http)
	set(PROBE ${CMAKE_CURRENT_SOURCE_DIR}/../http-probe)
	add_executable(vitals_http_probe
		${HTTP}/src/core.c
		${HTTP}/src/client.c
		${HTTP}/src/headers.c
		${HTTP}/src/transaction.c
		${HTTP}/src/tls.c
		${HTTP}/src/proxy.c
		${HTTP}/src/cookie.c
		${HTTP}/src/md5.c
		${HTTP}/src/auth.c
		${HTTP}/src/cache.c
		${HTTP}/src/inflate.c
		${HTTP}/src/unnamed.c
		${HTTP}/src/util.c
		${HTTP}/src/redirect.c
		${SHARED}/src/host_map.c
		${SHARED}/src/redirect_list.c
		${PROBE}/source/main.c
		${PROBE}/source/util.c
		${PROBE}/source/cookie.c
		${PROBE}/source/transaction.c
		${PROBE}/source/auth.c
		${PROBE}/source/proxy.c
		${PROBE}/source/unnamed.c
		${PROBE}/source/additions.c
		http/platform_http_posix.c
		http/probe_host.c
		${SSL}/src/core.c
		${SSL}/src/ca_store.c
		${SSL}/src/sha1.c
		${SSL}/src/certificate.c
		${SSL}/src/connection.c
		${SSL}/src/public.c
		${SSL}/src/platform/gmtime.c
		platform_posix.c
		pool_posix.c
		crypto_platform_posix.c)
	set_source_files_properties(${PROBE}/source/main.c PROPERTIES COMPILE_DEFINITIONS main=vitals_probe_main)
	# The probe's sources: http/include's stand-ins, then PS3DK's headers
	set_source_files_properties(
		${PROBE}/source/main.c ${PROBE}/source/util.c ${PROBE}/source/cookie.c ${PROBE}/source/transaction.c
		${PROBE}/source/auth.c ${PROBE}/source/proxy.c ${PROBE}/source/unnamed.c ${PROBE}/source/additions.c
		http/probe_host.c
		PROPERTIES INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/http/include;${VITALS_PS3DK_INCLUDE}"
		COMPILE_OPTIONS "-Wno-error")
	set_source_files_properties(
		${HTTP}/src/core.c ${HTTP}/src/client.c ${HTTP}/src/headers.c ${HTTP}/src/transaction.c ${HTTP}/src/tls.c
		${HTTP}/src/proxy.c ${HTTP}/src/cookie.c ${HTTP}/src/md5.c ${HTTP}/src/auth.c ${HTTP}/src/cache.c
		${HTTP}/src/inflate.c ${HTTP}/src/unnamed.c ${HTTP}/src/util.c ${HTTP}/src/redirect.c
		${SHARED}/src/host_map.c ${SHARED}/src/redirect_list.c http/platform_http_posix.c
		PROPERTIES INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include;${HTTP}/src;${HTTP}/../common;${SHARED}/include;${CMAKE_CURRENT_SOURCE_DIR}/http/include;${VITALS_PS3DK_INCLUDE}")
	set_source_files_properties(
		${SSL}/src/core.c ${SSL}/src/ca_store.c ${SSL}/src/sha1.c ${SSL}/src/certificate.c ${SSL}/src/connection.c
		${SSL}/src/public.c ${SSL}/src/platform/gmtime.c platform_posix.c pool_posix.c crypto_platform_posix.c
		PROPERTIES INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include;${SSL}/src;${SSL}/src/platform")
	target_compile_definitions(vitals_http_probe PRIVATE VITALS_DEBUG=2)
	target_compile_options(vitals_http_probe PRIVATE -std=gnu11 -g -Wall -Wextra -Werror
		-fsanitize=address,undefined -fno-omit-frame-pointer)
	target_link_options(vitals_http_probe PRIVATE -fsanitize=address,undefined)
	target_link_libraries(vitals_http_probe PRIVATE mbedtls mbedx509 tfpsacrypto Threads::Threads)
	add_test(NAME vitals_http_probe
		COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/http_probe.sh host $<TARGET_FILE:vitals_http_probe>)
	set_tests_properties(vitals_http_probe PROPERTIES TIMEOUT 300)
else()
	message(STATUS "No PS3DK headers in ${VITALS_PS3DK_INCLUDE}: the libhttp probe's host run isn't built")
endif()

# The DNS rules (vitals-dns/src/dns_rules.c, on the shared dns_message.c and redirect list
# parser): what the kernel plugin applies to every process's DNS, run here first
set(DNS ${CMAKE_CURRENT_SOURCE_DIR}/../../vitals-dns)
set(COMMON ${CMAKE_CURRENT_SOURCE_DIR}/../../common)
add_executable(vitals_dns_rules_tests
	dns/test_dns_rules.c
	${DNS}/src/dns_rules.c
	${SHARED}/dns/dns_message.c
	${SHARED}/src/host_map.c
	${SHARED}/src/redirect_list.c)
target_include_directories(vitals_dns_rules_tests PRIVATE ${DNS}/src ${SHARED}/dns ${SHARED}/include ${COMMON})
target_compile_options(vitals_dns_rules_tests PRIVATE -std=gnu11 -g -Wall -Wextra -Werror -UNDEBUG
	-fsanitize=address,undefined -fno-omit-frame-pointer)
target_link_options(vitals_dns_rules_tests PRIVATE -fsanitize=address,undefined)
add_test(NAME vitals_dns_rules COMMAND vitals_dns_rules_tests)
