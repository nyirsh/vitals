# Applies PATCH_FILE to the extracted Mbed TLS sources (the current directory), once: a tree whose
# library/ssl_tls.c already has PATCH_MARKER is left as it is
if(NOT DEFINED PATCH_FILE OR NOT DEFINED PATCH_MARKER)
    message(FATAL_ERROR "PATCH_FILE and PATCH_MARKER must be set")
endif()
file(READ library/ssl_tls.c sources)
string(FIND "${sources}" "${PATCH_MARKER}" applied)
if(applied EQUAL -1)
    execute_process(COMMAND patch -p1 --forward -i "${PATCH_FILE}" RESULT_VARIABLE result)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Patching Mbed TLS failed (${result})")
    endif()
endif()
