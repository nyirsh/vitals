# Applies offer-unknown-ciphersuites.patch to the extracted Mbed TLS sources (the current directory),
# once: a tree that already has it is left as it is
if(NOT DEFINED PATCH_FILE)
    message(FATAL_ERROR "PATCH_FILE is not set")
endif()
file(READ library/ssl_tls.c sources)
string(FIND "${sources}" "mbedtls_ssl_conf_offer_unknown_ciphersuites" applied)
if(applied EQUAL -1)
    execute_process(COMMAND patch -p1 --forward -i "${PATCH_FILE}" RESULT_VARIABLE result)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Patching Mbed TLS failed (${result})")
    endif()
endif()
