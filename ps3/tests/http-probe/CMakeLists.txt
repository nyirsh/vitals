# The libhttp probe (source/main.c): Sony's libhttp's behaviour, line by line, to diff vitals' against
cmake_minimum_required(VERSION 3.20)
project(vitals-ps3-http-probe C)

include(ps3-self)

# cellHttp by NID, all 181 (tools/gen_http_imports.py): PS3DK's http_stub lacks some
ps3_prx_stub_library(probe_cellhttp_stub EXPORTS cellhttp_imports.yml)

add_executable(http-probe source/main.c source/util.c source/cookie.c source/transaction.c source/auth.c source/proxy.c source/unnamed.c source/additions.c)
target_compile_options(http-probe PRIVATE -Wall -Wextra)
target_link_libraries(http-probe PRIVATE probe_cellhttp_stub http_util_stub ssl_stub net_stub fs_stub sysmodule_stub c_stub sysutil rt lv2 m)
ps3_add_self(http-probe)
