#include "vitals/switches.h"
#include "vitals/ca_store.h"
#include "vitals/redirects.h"
#include "vitals/useragent.h"
#include <kernel_mock.h>
#include <assert.h>
#include <stdio.h>

#define FD 31
#define NOT_FOUND ((int)0x80010002)
#define INVALID ((int)0x80010016)

int syscall_depth;
static const char *file_text, *file_path = "ux0:data/vitals/redirects.txt";
static int read_error, copy_error, opens, closes;
static SceSize largest_read;

/* The certificate store's parts, when ca_texts is set: Sony's, Mozilla's and the user's (NULL when
 * missing); each is opened as FD + 1 + its number */
static const char *const ca_paths[] = {"ux0:data/vitals/system/sony-certs.pem",
    "ux0:data/vitals/system/mozilla-certs.pem", "ux0:data/vitals/custom-certs.pem"};
static const char *ca_texts[3];
static int ca_mode, ca_open_parts, ca_stat_error, ca_open_error;
/* What Getstat says a part's size is, when not strlen (a file rewritten meanwhile) */
static long ca_stated[3] = {-1, -1, -1};

static int ca_part(const char *path) {
    for (int i = 0; i < 3; ++i)
        if (strcmp(path, ca_paths[i]) == 0) return i;
    return -1;
}
/* redirects.off, while redirects_off */
static int redirects_off;
int ksceIoGetstat(const char *path, SceIoStat *status) {
    if (strcmp(path, VITALS_REDIRECTS_OFF) == 0) {
        assert(syscall_depth == 1);
        return redirects_off ? 0 : NOT_FOUND;
    }
    int part = ca_part(path);
    assert(ca_mode && part >= 0 && syscall_depth == 1);
    if (part == 0 && ca_stat_error) return ca_stat_error;
    if (ca_texts[part] == NULL) return NOT_FOUND;
    memset(status, 0, sizeof(*status));
    status->st_size = ca_stated[part] >= 0 ? ca_stated[part] : (int64_t)strlen(ca_texts[part]);
    return 0;
}

int ksceIoOpen(const char *path, int flags, int mode) {
    assert(flags == SCE_O_RDONLY && mode == 0);
    if (ca_mode) {
        int part = ca_part(path);
        assert(part >= 0 && syscall_depth == 1);
        if (ca_texts[part] == NULL || ca_open_error) return ca_open_error ? ca_open_error : NOT_FOUND;
        ++opens;
        ca_open_parts |= 1 << part;
        return FD + 1 + part;
    }
    assert(strcmp(path, file_path) == 0);
    /* The file is only touched inside the syscall state */
    assert(syscall_depth == 1);
    if (file_text == NULL) return NOT_FOUND;
    /* Only successful opens are counted, as only those need closing */
    ++opens;
    return FD;
}
int ksceIoPread(SceUID fd, void *data, SceSize size, SceOff offset) {
    const char *text = file_text;
    if (ca_mode) {
        assert(fd >= FD + 1 && fd <= FD + 3);
        text = ca_texts[fd - FD - 1];
    } else {
        assert(fd == FD);
    }
    assert(offset >= 0);
    if (size > largest_read) largest_read = size;
    if (read_error) return read_error;
    size_t length = strlen(text);
    if ((size_t)offset >= length) return 0;
    size_t count = length - (size_t)offset;
    if (count > size) count = size;
    memcpy(data, text + offset, count);
    return (int)count;
}
int ksceIoClose(int fd) {
    assert((ca_mode ? fd >= FD + 1 && fd <= FD + 3 : fd == FD) && syscall_depth == 1);
    ++closes;
    return 0;
}
int ksceKernelCopyToUser(void *destination, const void *source, SceSize length) {
    assert(syscall_depth == 1);
    if (copy_error) return copy_error;
    memcpy(destination, source, length);
    return 0;
}

static void reset(const char *text) {
    file_text = text;
    read_error = copy_error = opens = closes = 0;
    largest_read = 0;
}

static void check_state_restored(void) {
    assert(syscall_depth == 0 && opens == closes);
}

/* The list is copied in pieces, from any offset, and the end reads as 0 */
static void test_reads_in_pieces(void) {
    char buffer[300];
    reset("old.example new.example\nsecond.example two.example\n");
    memset(buffer, 0, sizeof(buffer));
    assert(vitals_redirects_read(0, buffer, 10) == 10 && memcmp(buffer, "old.exampl", 10) == 0);
    assert(vitals_redirects_read(24, buffer, 6) == 6 && memcmp(buffer, "second", 6) == 0);
    int length = (int)strlen(file_text);
    assert(vitals_redirects_read(0, buffer, sizeof(buffer)) == length);
    assert(vitals_redirects_read((unsigned int)length, buffer, 10) == 0);
    assert(vitals_redirects_read(100000, buffer, 10) == 0);
    /* Each read opens and closes the list, so the next game sees the latest edits */
    assert(opens == 5);
    check_state_restored();
}

/* A request larger than a piece is cut to one, so the kernel's buffer cannot overflow */
static void test_large_requests_are_cut(void) {
    static char big[1024];
    char buffer[1024];
    memset(big, 'a', sizeof(big) - 1);
    reset(big);
    assert(vitals_redirects_read(0, buffer, sizeof(buffer)) == (int)VITALS_REDIRECTS_CHUNK);
    assert(largest_read == VITALS_REDIRECTS_CHUNK);
    check_state_restored();
}

/* Errors are returned as they are, and nothing is left open */
static void test_errors(void) {
    char buffer[16];
    reset(NULL);
    assert(vitals_redirects_read(0, buffer, sizeof(buffer)) == NOT_FOUND && closes == 0);
    check_state_restored();

    reset("old.example new.example\n");
    read_error = (int)0x80010005;
    assert(vitals_redirects_read(0, buffer, sizeof(buffer)) == (int)0x80010005 && closes == 1);
    check_state_restored();

    /* A bad destination in the caller's memory */
    reset("old.example new.example\n");
    copy_error = (int)0x800F0000;
    assert(vitals_redirects_read(0, buffer, sizeof(buffer)) == INVALID && closes == 1);
    check_state_restored();

    /* Arguments are checked before anything is opened */
    reset("old.example new.example\n");
    assert(vitals_redirects_read(0, NULL, 16) == INVALID);
    assert(vitals_redirects_read(0, buffer, 0) == INVALID);
    assert(opens == 0);
    check_state_restored();
}

/* The User-Agent suffix comes from its own file, from its start */
static void test_useragent(void) {
    char buffer[64];
    file_path = "ux0:data/vitals/useragent.txt";
    reset("Custom/1.0 (Vita)\n");
    assert(vitals_useragent_read(buffer, sizeof(buffer)) == 18 && memcmp(buffer, "Custom/1.0 (Vita)\n", 18) == 0);
    reset(NULL);
    assert(vitals_useragent_read(buffer, sizeof(buffer)) == NOT_FOUND);
    assert(vitals_useragent_read(NULL, 16) == INVALID);
    check_state_restored();
    file_path = "ux0:data/vitals/redirects.txt";
}

/* The certificate store: in ux0:data/vitals/system, a whole request copied in one call with one open
 * (a chunk at a time), cut at VITALS_CA_READ_MAX, from any offset, the end as 0 */
static void ca_reset(const char *sony, const char *mozilla, const char *custom) {
    reset("");
    ca_mode = 1;
    ca_texts[0] = sony; ca_texts[1] = mozilla; ca_texts[2] = custom;
    ca_open_parts = ca_stat_error = ca_open_error = 0;
    ca_stated[0] = ca_stated[1] = ca_stated[2] = -1;
}

/* The whole store, in calls of size bytes from 0 to the end; its length */
static int read_store(char *out, size_t capacity, unsigned int size) {
    unsigned int offset = 0;
    for (;;) {
        assert(offset + size <= capacity);
        int count = vitals_ca_read(offset, out + offset, size);
        assert(count >= 0 && (unsigned int)count <= size);
        if (count == 0) return (int)offset;
        offset += (unsigned int)count;
    }
}

static void test_certificate_store(void) {
    static char sony[3000], mozilla[700], buffer[8000], expected[8000];
    for (size_t i = 0; i + 1 < sizeof(sony); ++i) sony[i] = (char)('A' + i % 26);
    for (size_t i = 0; i + 1 < sizeof(mozilla); ++i) mozilla[i] = (char)('a' + i % 26);
    const char custom[] = "-----BEGIN CERTIFICATE-----\nmine\n-----END CERTIFICATE-----";

    /* Sony's, Mozilla's and the user's, each followed by a line break, in pieces of any size and
     * through the parts' edges; one open per part a call touches */
    ca_reset(sony, mozilla, custom);
    snprintf(expected, sizeof(expected), "%s\n%s\n%s\n", sony, mozilla, custom);
    for (unsigned int size = 1; size < 4000; size = size * 3 + 1) {
        memset(buffer, 0, sizeof(buffer));
        assert(read_store(buffer, sizeof(buffer), size) == (int)strlen(expected));
        assert(memcmp(buffer, expected, strlen(expected)) == 0);
        check_state_restored();
    }
    ca_reset(sony, mozilla, custom);
    assert(vitals_ca_read(0, buffer, sizeof(buffer)) == (int)strlen(expected));
    assert(opens == 3 && closes == 3 && largest_read <= VITALS_REDIRECTS_CHUNK);
    /* A piece inside Mozilla's opens only that one */
    ca_reset(sony, mozilla, custom);
    assert(vitals_ca_read(3100, buffer, 100) == 100 && memcmp(buffer, expected + 3100, 100) == 0);
    assert(opens == 1 && ca_open_parts == 2);
    /* Only the line break after Sony's: nothing opened */
    ca_reset(sony, mozilla, custom);
    assert(vitals_ca_read((unsigned int)strlen(sony), buffer, 1) == 1 && buffer[0] == '\n' && opens == 0);
    assert(vitals_ca_read((unsigned int)strlen(expected), buffer, 10) == 0);

    /* Without the user's file, or Mozilla's, or with empty ones, the rest is the store */
    const char *others[][2] = {{mozilla, NULL}, {NULL, custom}, {NULL, NULL}, {"", ""}, {mozilla, ""}};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i) {
        ca_reset(sony, others[i][0], others[i][1]);
        snprintf(expected, sizeof(expected), "%s\n%s%s%s%s", sony,
            others[i][0] != NULL && others[i][0][0] ? others[i][0] : "",
            others[i][0] != NULL && others[i][0][0] ? "\n" : "",
            others[i][1] != NULL && others[i][1][0] ? others[i][1] : "",
            others[i][1] != NULL && others[i][1][0] ? "\n" : "");
        assert(read_store(buffer, sizeof(buffer), 512) == (int)strlen(expected));
        assert(memcmp(buffer, expected, strlen(expected)) == 0);
        check_state_restored();
    }

    /* Without Sony's there is no store */
    ca_reset(NULL, mozilla, custom);
    assert(vitals_ca_read(0, buffer, sizeof(buffer)) == NOT_FOUND && opens == 0);
    ca_reset(sony, mozilla, custom);
    ca_stat_error = (int)0x80010005;
    assert(vitals_ca_read(0, buffer, sizeof(buffer)) == (int)0x80010005 && opens == 0);
    /* A part shorter than its size said (rewritten meanwhile) ends the store there */
    ca_reset(sony, mozilla, custom);
    ca_stated[1] = (long)strlen(mozilla) + 50;
    assert(vitals_ca_read(0, buffer, sizeof(buffer)) == (int)(strlen(sony) + 1 + strlen(mozilla)));
    check_state_restored();
    /* Errors: opening, reading, copying, and the arguments */
    ca_reset(sony, mozilla, custom);
    ca_open_error = (int)0x80010013;
    assert(vitals_ca_read(0, buffer, sizeof(buffer)) == (int)0x80010013 && closes == 0);
    ca_reset(sony, mozilla, custom);
    read_error = (int)0x80010005;
    assert(vitals_ca_read(0, buffer, sizeof(buffer)) == (int)0x80010005 && closes == 1);
    ca_reset(sony, mozilla, custom);
    copy_error = -1;
    assert(vitals_ca_read(0, buffer, sizeof(buffer)) == INVALID && closes == 1);
    assert(vitals_ca_read(0, NULL, 16) == INVALID && vitals_ca_read(0, buffer, 0) == INVALID);
    /* At most VITALS_CA_READ_MAX bytes a call */
    static char big[VITALS_CA_READ_MAX + 100], big_out[VITALS_CA_READ_MAX + 200];
    memset(big, 'x', sizeof(big) - 1);
    ca_reset(big, NULL, NULL);
    assert(vitals_ca_read(0, big_out, sizeof(big_out)) == (int)VITALS_CA_READ_MAX);
    check_state_restored();
    ca_mode = 0;
}

/* While redirects.off is there the list reads as missing, without being opened */
static void test_redirects_switch(void) {
    char buffer[64];
    reset("old.example new.example\n");
    redirects_off = 1;
    assert(vitals_redirects_read(0, buffer, sizeof(buffer)) == NOT_FOUND && opens == 0);
    redirects_off = 0;
    assert(vitals_redirects_read(0, buffer, sizeof(buffer)) == 24 && opens == 1);
    check_state_restored();
}

int main(void) {
    test_reads_in_pieces();
    test_large_requests_are_cut();
    test_errors();
    test_useragent();
    test_certificate_store();
    test_redirects_switch();
    puts("kernel redirect list, User-Agent and certificate store (Sony, Mozilla and custom as one) reads PASS");
    return 0;
}
