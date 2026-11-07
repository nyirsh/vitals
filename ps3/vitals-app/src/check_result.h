#ifndef VITALS_PS3_CHECK_RESULT_H
#define VITALS_PS3_CHECK_RESULT_H

#include <stdint.h>

/* What a PS3 request records besides the shared CheckResult's fields (shared/app/model.h): the
 * certificate check's flags when libhttp's check refused the server (CELL_HTTPS_VERIFY_ERROR_*), and
 * what the connection used, Sony's CELL_SSL_VERSION (0 TLS, 1 SSL 3.0, -1 none) and the cipher's name,
 * which http_protocol_name names */
#define CHECK_RESULT_CONSOLE \
	uint32_t verify_error; \
	int ssl_version; \
	char cipher[64];

#endif
