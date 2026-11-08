#include "ca_index.h"
#include "diagnostics.h"
#include "vitals/ca_scan.h"

#include <mbedtls/platform.h>
#include <psp2/io/fcntl.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE_SIZE (4 * 1024 * 1024)
/* A read of the bundle at a time: through the kernel, each is a system call, so few */
#define CHUNK_SIZE 4096u
_Static_assert(VITALS_CA_INDEX_MAX_BLOCK == VITALS_CA_SCAN_BLOCK, "the index reads back what the scanner found");

/* Hash of a distinguished name that agrees for names Mbed TLS considers equal (string values
 * compare case-insensitively)
 * Used only to pre-select candidates; Mbed TLS still performs the real name comparison */
static uint32_t hash_name(const mbedtls_x509_name *name) {
    uint32_t hash = 2166136261u;
    for (; name != NULL; name = name->next) {
        for (size_t i = 0; i < name->oid.len; ++i) hash = (hash ^ name->oid.p[i]) * 16777619u;
        hash = (hash ^ 0xFFu) * 16777619u;
        for (size_t i = 0; i < name->val.len; ++i) {
            unsigned char c = name->val.p[i];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
            hash = (hash ^ c) * 16777619u;
        }
        hash = (hash ^ 0xFEu) * 16777619u;
    }
    return hash;
}

/* A block of the store (vitals/ca_scan.h): indexed when it's a certificate */
static int add_entry(void *context, const unsigned char *block, size_t block_length, uint32_t start,
    uint32_t end) {
    VitalsCaIndex *index = context;
    mbedtls_x509_crt crt;
    if (index->count >= VITALS_CA_INDEX_MAX_ENTRIES) return 0;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse(&crt, block, block_length + 1) == 0 && crt.raw.p != NULL) {
        VitalsCaEntry *entry = &index->entries[index->count++];
        entry->name_hash = hash_name(&crt.subject);
        entry->offset = start;
        entry->length = end - start;
    }
    mbedtls_x509_crt_free(&crt);
    return 0;
}

int vitals_ca_file_read(void *path, uint32_t offset, void *buffer, uint32_t size) {
    SceUID fd = sceIoOpen((const char *)path, SCE_O_RDONLY, 0);
    int result;
    uint32_t done = 0;
    if (fd < 0) return fd;
    result = sceIoLseek(fd, offset, SCE_SEEK_SET) < 0 ? -1 : 0;
    while (result == 0 && done < size) {
        int count = sceIoRead(fd, (unsigned char *)buffer + done, (SceSize)(size - done));
        if (count < 0) result = count;
        if (count <= 0) break;
        done += (uint32_t)count;
    }
    (void)sceIoClose(fd);
    return result < 0 ? result : (int)done;
}

int vitals_ca_index_read(const VitalsCaIndex *index, uint32_t offset, void *buffer, uint32_t size) {
    uint32_t done = 0;
    while (done < size) {
        int count = index->read(index->context, offset + done, (unsigned char *)buffer + done, size - done);
        if (count <= 0) return -1;
        done += (uint32_t)count;
    }
    return 0;
}

int vitals_ca_index_build(VitalsCaIndex *index, VitalsCaRead read, void *context) {
    VitalsCaScanner *scanner = NULL;
    int result = MBEDTLS_ERR_X509_FILE_IO_ERROR;

    if (index == NULL || read == NULL) return result;
    memset(index, 0, sizeof(*index));

    /* The blocks, through the scanner both consoles' libssl use (../../../shared/src/ca_scan.c) */
    scanner = malloc(VITALS_CA_SCANNER_SIZE(CHUNK_SIZE));
    index->entries = calloc(VITALS_CA_INDEX_MAX_ENTRIES, sizeof(*index->entries));
    if (scanner == NULL || index->entries == NULL) {
        result = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto cleanup;
    }
    scanner->chunk_size = CHUNK_SIZE;
    if (vitals_ca_scan(scanner, MAX_FILE_SIZE, read, context, add_entry, index) != 0) goto cleanup;

    VITALS_LOG("event=ca.index entries=%u", (unsigned int)index->count);
    if (index->count == 0) {
        result = MBEDTLS_ERR_X509_INVALID_FORMAT;
        goto cleanup;
    }
    index->read = read;
    index->context = context;
    result = 0;

cleanup:
    free(scanner);
    if (result != 0) vitals_ca_index_free(index);
    return result;
}

void vitals_ca_index_free(VitalsCaIndex *index) {
    if (index == NULL) return;
    free(index->entries);
    memset(index, 0, sizeof(*index));
}

int vitals_ca_index_find(void *context, const mbedtls_x509_crt *child,
    mbedtls_x509_crt **candidates) {
    const VitalsCaIndex *index = context;
    mbedtls_x509_crt *head = NULL;
    unsigned char *block = NULL;
    uint32_t hash;
    int result = 0;

    if (candidates == NULL) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    *candidates = NULL;
    if (index == NULL || index->entries == NULL || index->read == NULL || child == NULL) return 0;

    hash = hash_name(&child->issuer);
    for (size_t i = 0; i < index->count; ++i) {
        const VitalsCaEntry *entry = &index->entries[i];
        size_t consumed = entry->length;
        if (entry->name_hash != hash || entry->length >= VITALS_CA_INDEX_MAX_BLOCK) continue;
        if (head == NULL) {
            head = mbedtls_calloc(1, sizeof(*head));
            block = malloc(VITALS_CA_INDEX_MAX_BLOCK + 2u);
            if (head == NULL || block == NULL) {
                result = MBEDTLS_ERR_X509_ALLOC_FAILED;
                goto cleanup;
            }
            mbedtls_x509_crt_init(head);
        }
        if (vitals_ca_index_read(index, entry->offset, block, entry->length) != 0) continue;
        block[consumed++] = '\n';
        block[consumed++] = '\0';
        (void)mbedtls_x509_crt_parse(head, block, consumed);
    }

cleanup:
    free(block);
    if (result != 0 || head == NULL || head->raw.p == NULL) {
        if (head != NULL) {
            mbedtls_x509_crt_free(head);
            mbedtls_free(head);
        }
        return result;
    }
    *candidates = head;
    return 0;
}

int vitals_ca_trusts_exact(mbedtls_x509_crt_ca_cb_t find, void *context,
    const mbedtls_x509_crt *certificate) {
    mbedtls_x509_crt *candidates = NULL;
    int trusted = 0;

    if (find == NULL || certificate == NULL || certificate->raw.p == NULL ||
        certificate->issuer_raw.len != certificate->subject_raw.len ||
        memcmp(certificate->issuer_raw.p, certificate->subject_raw.p, certificate->subject_raw.len) != 0)
        return 0;
    /* Its issuer is itself, so the trusted certificates with its subject include any copy of it */
    if (find(context, certificate, &candidates) == 0) {
        for (const mbedtls_x509_crt *candidate = candidates; candidate != NULL; candidate = candidate->next) {
            if (candidate->raw.len == certificate->raw.len &&
                memcmp(candidate->raw.p, certificate->raw.p, certificate->raw.len) == 0) {
                trusted = 1;
                break;
            }
        }
    }
    if (candidates != NULL) {
        mbedtls_x509_crt_free(candidates);
        mbedtls_free(candidates);
    }
    return trusted;
}
