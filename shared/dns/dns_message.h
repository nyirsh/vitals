#ifndef VITALS_DNS_MESSAGE_H
#define VITALS_DNS_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

/* Reading and writing the few DNS messages the kernel's DNS redirect needs; no system calls */

#define VITALS_DNS_MESSAGE_MAX 512u
#define VITALS_DNS_HOST_MAX 254u
#define VITALS_DNS_TYPE_A 1u
/* The most addresses kept from one answer */
#define VITALS_DNS_ADDRESSES_MAX 4u

typedef struct VitalsDnsAddress
{
    unsigned char octets[4];
} VitalsDnsAddress;

/* A standard query's 12-byte header (QR clear, opcode 0): exactly one question, no answers or
 * authority records, and at most one additional record (resolvers often add one) */
int vitals_dns_query_header(const unsigned char *header);
/* The first question's host name in a standard DNS query, and its type; 0 when message is one */
int vitals_dns_query_name(const unsigned char *message, size_t length, char *name, size_t size, unsigned *type);
/* Rewrites query (a standard query, as vitals_dns_query_name accepts) to ask for name (dotted,
 * length characters) instead, keeping its header, type, class and any additional record; returns
 * the new query's size, or 0 when name is not a valid host name or output is too small */
size_t vitals_dns_rename_query(const unsigned char *query, size_t length, const char *name, size_t name_length,
                               unsigned char *output, size_t capacity);
/* Reads the A records of an answer to query id, wherever they sit in a CNAME chain, keeping up to
 * capacity of them and the lowest TTL; returns how many there are (0 for an error or no records),
 * or -1 when message is not a well-formed answer to that query */
int vitals_dns_answer_addresses(const unsigned char *message, size_t length, uint16_t id,
                                VitalsDnsAddress *addresses, unsigned capacity, uint32_t *ttl);
/* Rewrites a server's answer to query id for the A records of asked (compared without case) into
 * an answer for name: its question asks for name, and its answers are only the given addresses.
 * With no addresses, the server's error code is kept. Returns the new answer's size, or 0 when
 * response is not that answer, name is not a valid host name or output is too small */
size_t vitals_dns_rewrite_answer(const unsigned char *response, size_t length, uint16_t id, const char *asked,
                                 const char *name, const VitalsDnsAddress *addresses, unsigned count, uint32_t ttl,
                                 unsigned char *output, size_t capacity);
/* Reads a dotted IPv4 address ("10.0.0.5"); 1 when name is one */
int vitals_dns_parse_address(const char *name, size_t length, VitalsDnsAddress *address);

#endif
