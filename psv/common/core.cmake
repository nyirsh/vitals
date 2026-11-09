# vitals' core library (src/, with the redirect lists shared with the PS3 in ../../shared): the
# module, provider and certificate paths, the certificate policy, the error mapping and the module
# registry, for every build that includes this file (vitals-browser and common's own tests);
# defined once per CMake build
if(TARGET vitals_core)
    return()
endif()
set(VITALS_COMMON_DIR ${CMAKE_CURRENT_LIST_DIR})
add_library(vitals_core STATIC
    ${CMAKE_CURRENT_LIST_DIR}/src/cert_policy.c
    ${CMAKE_CURRENT_LIST_DIR}/src/error_map.c
    ${CMAKE_CURRENT_LIST_DIR}/../../shared/src/host_map.c
    ${CMAKE_CURRENT_LIST_DIR}/src/module_gate.c
    ${CMAKE_CURRENT_LIST_DIR}/src/path.c
    ${CMAKE_CURRENT_LIST_DIR}/../../shared/src/redirect_list.c
    ${CMAKE_CURRENT_LIST_DIR}/src/registry.c
)
target_include_directories(vitals_core
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/../../shared/include
)
target_compile_features(vitals_core PUBLIC c_std_11)
target_compile_options(vitals_core PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wstrict-prototypes
)
