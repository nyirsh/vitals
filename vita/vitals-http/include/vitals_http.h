#ifndef VITALS_HTTP_H
#define VITALS_HTTP_H

/* vitals-http's own exports, beside Sony's sceHttp API, in its library VitalsHttp
 * (vitals_http_api.yml.in). Sony's libhttp has none of them, nor do earlier builds of vitals-http:
 * an app finds one at run time (taiHEN's taiGetModuleExportFunc on "SceLibHttp" with these NIDs)
 * and calls it only when it's there, rather than importing it, as a call through an import the
 * loader left unresolved crashes the process */

#define VITALS_HTTP_LIBRARY_NID 0x56485450u
#define VITALS_HTTP_GET_URL_NID 0x5B1F3A6Du
#define VITALS_HTTP_GET_CIPHER_NID 0x7C2E41A9u

#ifdef __cplusplus
extern "C" {
#endif

/* The URL the request goes to, as vitals-http sends it: after the host redirects
 * (ux0:data/vitals/redirects.txt), so a redirected request names the new host. Into url (size
 * bytes, NUL-terminated), and its size with the NUL into *required; with no url or too small a one
 * only *required, and SCE_HTTP_ERROR_OUT_OF_SIZE. 0, or SCE_HTTP_ERROR_BEFORE_INIT,
 * SCE_HTTP_ERROR_INVALID_ID, SCE_HTTP_ERROR_INVALID_VALUE (no required) */
int vitalsHttpGetUrl(int reqId, char *url, unsigned int size, unsigned int *required);

/* The cipher suite of the connection the request last went out on, as Mbed TLS names it, into cipher
 * (size bytes, NUL-terminated): empty before it's sent, over plain HTTP and on Sony's libssl. 0, or
 * SCE_HTTP_ERROR_BEFORE_INIT, SCE_HTTP_ERROR_INVALID_ID, SCE_HTTP_ERROR_INVALID_VALUE (no cipher or
 * size), SCE_HTTP_ERROR_OUT_OF_SIZE */
int vitalsHttpGetCipher(int reqId, char *cipher, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif
