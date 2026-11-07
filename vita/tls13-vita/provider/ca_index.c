#include "ca_index.h"
#include "diagnostics.h"

#include <mbedtls/platform.h>
#include <psp2/io/fcntl.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE_SIZE (4 * 1024 * 1024)
#define LINE_CAPACITY 160u
/* A read of the bundle at a time: through the kernel, each is a system call, so few */
#define CHUNK_SIZE 4096u

static const char k_begin[] = "-----BEGIN CERTIFICATE-----";
static const char k_end[] = "-----END CERTIFICATE-----";

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

typedef struct Reader {
    VitalsCaRead read;
    void *context;
    unsigned char buffer[CHUNK_SIZE];
    size_t position;
    size_t length;
    uint32_t base;
    int failed;
} Reader;

/* 1 = byte read, 0 = end of file, -1 = I/O error */
static int reader_next(Reader *reader, unsigned char *out) {
    if (reader->position == reader->length) {
        uint32_t next = reader->base + (uint32_t)reader->length;
        if (next >= MAX_FILE_SIZE) return -1;
        int count = reader->read(reader->context, next, reader->buffer, sizeof(reader->buffer));
        if (count < 0) return -1;
        if (count == 0) return 0;
        reader->base = next;
        reader->length = (size_t)count;
        reader->position = 0;
    }
    *out = reader->buffer[reader->position++];
    return 1;
}

static uint32_t reader_offset(const Reader *reader) {
    return reader->base + (uint32_t)reader->position;
}

static int starts_with(const unsigned char *line, size_t length, const char *prefix, size_t prefix_length) {
    return length >= prefix_length && memcmp(line, prefix, prefix_length) == 0;
}

static void add_entry(VitalsCaIndex *index, unsigned char *block, size_t block_length,
    uint32_t start, uint32_t end) {
    mbedtls_x509_crt crt;
    if (index->count >= VITALS_CA_INDEX_MAX_ENTRIES) return;
    block[block_length] = '\0';
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse(&crt, block, block_length + 1) == 0 && crt.raw.p != NULL) {
        VitalsCaEntry *entry = &index->entries[index->count++];
        entry->name_hash = hash_name(&crt.subject);
        entry->offset = start;
        entry->length = end - start;
    }
    mbedtls_x509_crt_free(&crt);
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
    Reader *reader = NULL;
    unsigned char *block = NULL;
    unsigned char line[LINE_CAPACITY];
    size_t block_length = 0;
    uint32_t block_start = 0;
    int in_block = 0;
    int result = MBEDTLS_ERR_X509_FILE_IO_ERROR;

    if (index == NULL || read == NULL) return result;
    memset(index, 0, sizeof(*index));

    reader = calloc(1, sizeof(*reader));
    block = malloc(VITALS_CA_INDEX_MAX_BLOCK + 2u);
    index->entries = calloc(VITALS_CA_INDEX_MAX_ENTRIES, sizeof(*index->entries));
    if (reader == NULL || block == NULL || index->entries == NULL) {
        result = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto cleanup;
    }
    reader->read = read;
    reader->context = context;

    for (;;) {
        size_t line_length = 0;
        int overflow = 0;
        int status = 1;
        uint32_t line_start = reader_offset(reader);
        unsigned char c;

        while ((status = reader_next(reader, &c)) == 1) {
            if (c == '\n') break;
            if (line_length < sizeof(line)) line[line_length++] = c;
            else overflow = 1;
        }
        if (status < 0) goto cleanup;
        if (status == 0 && line_length == 0 && !overflow) break;

        if (!in_block && !overflow &&
            starts_with(line, line_length, k_begin, sizeof(k_begin) - 1u)) {
            in_block = 1;
            block_start = line_start;
            block_length = 0;
        }
        if (in_block) {
            if (overflow || block_length + line_length + 1u > VITALS_CA_INDEX_MAX_BLOCK) {
                in_block = 0;
            } else {
                memcpy(block + block_length, line, line_length);
                block_length += line_length;
                block[block_length++] = '\n';
                if (starts_with(line, line_length, k_end, sizeof(k_end) - 1u)) {
                    add_entry(index, block, block_length, block_start, reader_offset(reader));
                    in_block = 0;
                }
            }
        }
        if (status == 0) break;
    }

    VITALS_LOG("event=ca.index entries=%u", (unsigned int)index->count);
    if (index->count == 0) {
        result = MBEDTLS_ERR_X509_INVALID_FORMAT;
        goto cleanup;
    }
    index->read = read;
    index->context = context;
    result = 0;

cleanup:
    free(reader);
    free(block);
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
