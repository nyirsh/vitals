# vitals_add_prx(target <ps3_add_prx arguments>): PS3DK's ps3_add_prx with vitals' linker script
# (vitals-prx.ld: code and data in separate segments, with the flags Sony's modules have), then
# tools/ps3_hw_layout.py (Sony's ELF flags, and a check of the two segments) and both containers
# made again from the result: <stem>.sprx (real-signed) and <stem>.fake.sprx. A console's kernel
# refuses PS3DK's own layout, a single segment that can be written and executed.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VITALS_PRX_LINKER_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/vitals-prx.ld")

function(vitals_add_prx target)
    cmake_parse_arguments(_VAP "" "OUTPUT_NAME" "" ${ARGN})
    # ps3_add_prx then leaves the link to this function
    set(_PS3_PRX_SKIP_LINK_FLAGS TRUE)
    target_link_options(${target} PRIVATE
        "-specs=${PS3DK}/ppu/lib/lv2-prx.specs"
        "-nostartfiles"
        "-Wl,-q"
        "-Wl,-T,${VITALS_PRX_LINKER_SCRIPT}")
    target_link_libraries(${target} PRIVATE "${PS3DK}/ppu/lib/lv2-prx-crt.o")
    set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS "${VITALS_PRX_LINKER_SCRIPT}")
    ps3_add_prx(${target} OUTPUT_NAME ${_VAP_OUTPUT_NAME} ${_VAP_UNPARSED_ARGUMENTS})

    get_filename_component(_stem "${_VAP_OUTPUT_NAME}" NAME_WE)
    set(_prx "${CMAKE_CURRENT_BINARY_DIR}/${_VAP_OUTPUT_NAME}")
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tools/ps3_hw_layout.py" "${_prx}"
        COMMAND "${PS3_TOOL_make_sprx}" "${_prx}" "${CMAKE_CURRENT_BINARY_DIR}/${_stem}.sprx"
        COMMAND "${PS3_TOOL_fself}" "${_prx}" "${CMAKE_CURRENT_BINARY_DIR}/${_stem}.fake.sprx"
        COMMENT "vitals: ${_VAP_OUTPUT_NAME} checked and signed again"
        VERBATIM)
endfunction()
