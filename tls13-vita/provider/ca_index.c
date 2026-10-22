#include "ca_index.h"
#include "diagnostics.h"

#include <mbedtls/platform.h>
#include <psp2/io/fcntl.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE_SIZE (4 * 1024 * 1024)
#define LINE_CAPACITY 160u
#define CHUNK_SIZE 512u

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
    SceUID fd;
    unsigned char buffer[CHUNK_SIZE];
    size_t position;
    size_t length;
    uint32_t base;
    int failed;
} Reader;

/* 1 = byte read, 0 = end of file, -1 = I/O error */
static int reader_next(Reader *reader, unsigned char *out) {
    if (reader->position == reader->length) {
        int count = sceIoRead(reader->fd, reader->buffer, sizeof(reader->buffer));
        if (count < 0) return -1;
        if (count == 0) return 0;
        reader->base += (uint32_t)reader->length;
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

int vitals_ca_index_build(VitalsCaIndex *index, const char *path) {
    Reader *reader = NULL;
    unsigned char *block = NULL;
    unsigned char line[LINE_CAPACITY];
    size_t block_length = 0;
    uint32_t block_start = 0;
    int in_block = 0;
    int64_t file_size;
    int result = MBEDTLS_ERR_X509_FILE_IO_ERROR;

    if (index == NULL || path == NULL || *path == '\0' ||
        strlen(path) >= sizeof(index->path)) return result;
    memset(index, 0, sizeof(*index));

    reader = calloc(1, sizeof(*reader));
    block = malloc(VITALS_CA_INDEX_MAX_BLOCK + 2u);
    index->entries = calloc(VITALS_CA_INDEX_MAX_ENTRIES, sizeof(*index->entries));
    if (reader == NULL || block == NULL || index->entries == NULL) {
        result = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto cleanup;
    }
    reader->fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    VITALS_VERBOSE("event=ca.open path=%s fd=%08X", path, reader->fd);
    if (reader->fd < 0) goto cleanup;
    file_size = sceIoLseek(reader->fd, 0, SCE_SEEK_END);
    VITALS_VERBOSE("event=ca.size bytes=%lld", (long long)file_size);
    if (file_size <= 0 || file_size > MAX_FILE_SIZE ||
        sceIoLseek(reader->fd, 0, SCE_SEEK_SET) < 0) goto cleanup;

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
    memcpy(index->path, path, strlen(path) + 1u);
    result = 0;

cleanup:
    if (reader != NULL && reader->fd >= 0 && sceIoClose(reader->fd) < 0 && result == 0) {
        result = MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }
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
    SceUID fd = -1;
    uint32_t hash;
    int result = 0;

    if (candidates == NULL) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    *candidates = NULL;
    if (index == NULL || index->entries == NULL || child == NULL) return 0;

    hash = hash_name(&child->issuer);
    for (size_t i = 0; i < index->count; ++i) {
        const VitalsCaEntry *entry = &index->entries[i];
        size_t consumed = 0;
        if (entry->name_hash != hash || entry->length >= VITALS_CA_INDEX_MAX_BLOCK) continue;
        if (head == NULL) {
            head = mbedtls_calloc(1, sizeof(*head));
            block = malloc(VITALS_CA_INDEX_MAX_BLOCK + 2u);
            if (head == NULL || block == NULL) {
                result = MBEDTLS_ERR_X509_ALLOC_FAILED;
                goto cleanup;
            }
            mbedtls_x509_crt_init(head);
            fd = sceIoOpen(index->path, SCE_O_RDONLY, 0);
            if (fd < 0) goto cleanup;
        }
        if (sceIoLseek(fd, entry->offset, SCE_SEEK_SET) < 0) continue;
        while (consumed < entry->length) {
            int count = sceIoRead(fd, block + consumed, (SceSize)(entry->length - consumed));
            if (count <= 0) break;
            consumed += (size_t)count;
        }
        if (consumed != entry->length) continue;
        block[consumed++] = '\n';
        block[consumed++] = '\0';
        (void)mbedtls_x509_crt_parse(head, block, consumed);
    }

cleanup:
    if (fd >= 0) (void)sceIoClose(fd);
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
