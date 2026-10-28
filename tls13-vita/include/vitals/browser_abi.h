#ifndef VITALS_BROWSER_ABI_H
#define VITALS_BROWSER_ABI_H

#include <stddef.h>
#include <stdint.h>

#define VITALS_BROWSER_START_MAGIC UINT32_C(0x42544c53)
#define VITALS_BROWSER_START_VERSION UINT32_C(1)
#define VITALS_BROWSER_CONNECT_OFFSET ((size_t)0xa5ece)
#define VITALS_BROWSER_CLOSE_OFFSET ((size_t)0xa36ba)
#define VITALS_BROWSER_PENDING_OFFSET ((size_t)0xa6240)
#define VITALS_BROWSER_CHECK_OFFSET ((size_t)0xa354c)
#define VITALS_BROWSER_TIMELEFT_OFFSET ((size_t)0x93f18)
#define VITALS_BROWSER_WAIT_OFFSET ((size_t)0x97e82)

#define VITALS_CURL_EASY_OFFSET ((size_t)0)
#define VITALS_CURL_HOST_OFFSET ((size_t)136)
#define VITALS_CURL_SOCKET_OFFSET ((size_t)320)
#define VITALS_CURL_RECV_OFFSET ((size_t)340)
#define VITALS_CURL_SEND_OFFSET ((size_t)348)
#define VITALS_CURL_SSL_OFFSET ((size_t)356)
#define VITALS_CURL_SSL_STRIDE ((size_t)24)
#define VITALS_CURL_SSL_STATE_OFFSET ((size_t)4)
#define VITALS_CURL_SSL_CONTEXT_OFFSET ((size_t)8)
#define VITALS_CURL_SSL_HANDLE_OFFSET ((size_t)12)
#define VITALS_CURL_SSL_CONNECTING_OFFSET ((size_t)20)

#define VITALS_CURL_VERSION_OFFSET ((size_t)636)
#define VITALS_CURL_VERIFY_RESULT_OFFSET ((size_t)640)
#define VITALS_CURL_VERIFY_PEER_OFFSET ((size_t)644)
#define VITALS_CURL_VERIFY_HOST_OFFSET ((size_t)645)
#define VITALS_CURL_CTX_CALLBACK_OFFSET ((size_t)680)
#define VITALS_CURL_CTX_CALLBACK_DATA_OFFSET ((size_t)684)
#define VITALS_CURL_CERTINFO_OFFSET ((size_t)689)
#define VITALS_CURL_CAPATH_OFFSET ((size_t)896)
#define VITALS_CURL_CAFILE_OFFSET ((size_t)900)
#define VITALS_CURL_CIPHERS_OFFSET ((size_t)904)
#define VITALS_CURL_CRL_OFFSET ((size_t)920)
#define VITALS_CURL_ISSUER_OFFSET ((size_t)924)

#define VITALS_CURLE_OK 0
#define VITALS_CURLE_NOT_BUILT_IN 4
#define VITALS_CURLE_OUT_OF_MEMORY 27
#define VITALS_CURLE_OPERATION_TIMEDOUT 28
#define VITALS_CURLE_SSL_CONNECT_ERROR 35
#define VITALS_CURLE_ABORTED_BY_CALLBACK 42
#define VITALS_CURLE_BAD_FUNCTION_ARGUMENT 43
#define VITALS_CURLE_PEER_FAILED_VERIFICATION 51
#define VITALS_CURLE_SEND_ERROR 55
#define VITALS_CURLE_RECV_ERROR 56
#define VITALS_CURLE_SSL_CACERT 60
#define VITALS_CURLE_SSL_CACERT_BADFILE 77
#define VITALS_CURLE_AGAIN 81

typedef struct VitalsBrowserStartArgs {
    uint32_t magic;
    uint32_t version;
    int32_t compat_modid;
    uint32_t reserved;
} VitalsBrowserStartArgs;

typedef struct VitalsBrowserOptions {
    void *easy;
    int socket;
    const char *hostname;
    const char *ca_file;
    uint32_t tls12_suites;
    uint8_t verify_peer;
    uint8_t verify_host;
} VitalsBrowserOptions;

typedef int (*VitalsBrowserContextCallbackValidator)(const void *callback,
    const void *userdata);

enum {
    VITALS_BROWSER_CONFIG_OK = 0,
    VITALS_BROWSER_CONFIG_LEGACY = 1,
    VITALS_BROWSER_CONFIG_INVALID = -1,
    VITALS_BROWSER_RSA_GCM128 = 1,
    VITALS_BROWSER_RSA_GCM256 = 2,
    VITALS_BROWSER_ECDSA_GCM128 = 4,
    VITALS_BROWSER_ECDSA_GCM256 = 8
};

/* The connection's host when it asks for no peer or no host verification; NULL otherwise */
const char *vitals_browser_unverified_host(const void *connection);
int vitals_browser_read_options(const void *connection, unsigned int socket_index,
    const char *browser_default_ciphers,
    VitalsBrowserContextCallbackValidator callback_validator,
    VitalsBrowserOptions *options);

#endif
