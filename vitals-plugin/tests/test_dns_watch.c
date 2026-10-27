#include "dns_watch.h"
#include "dns_message.h"
#include <kernel_mock.h>
#include <taihen.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

/* The parameter blocks as the hooks read them */
typedef struct {
    int socket;
    const void *message;
    unsigned int length;
    int flags;
    const void *to;
    unsigned int to_length;
} SendParameter;
typedef struct {
    int socket;
    void *buffer;
    unsigned int length;
    int flags;
    void *from;
    unsigned int *from_length;
} ReceiveParameter;

enum { SENDTO, RECVFROM };
static const uint32_t nids[] = {UINT32_C(0x39796C01), UINT32_C(0x144C9758)};

int syscall_depth;
static int copy_failures, originals, hooks, releases, locked, mutexes;
static void *hooked[2];
static char last_log[512];
static const void *last_original_argument;
static SceUID current_pid = 0x4321;
static int64_t now = 1000000;

int ksceKernelCopyFromUser(void *destination, const void *source, SceSize length) {
    if (copy_failures) return -1;
    memcpy(destination, source, length);
    return 0;
}
int ksceKernelCopyToUser(void *destination, const void *source, SceSize length) {
    memcpy(destination, source, length);
    return 0;
}
int ksceKernelRunWithStack(SceSize size, int (*function)(void *), void *argument) {
    assert(size >= 4096 && syscall_depth == 1);
    return function(argument);
}
int ksceDebugPrintf(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vsnprintf(last_log, sizeof(last_log), format, list);
    va_end(list);
    return 0;
}
SceUID ksceKernelGetProcessId(void) { return current_pid; }
int ksceKernelSysrootGetProcessTitleId(SceUID pid, char *title, SceSize size) {
    assert(pid == current_pid && size >= 10);
    strcpy(title, "NPXS10000");
    return 0;
}
int64_t ksceKernelGetSystemTimeWide(void) { return now; }
SceUID ksceKernelCreateMutex(const char *name, unsigned int attributes, int count, const void *options) {
    assert(strcmp(name, "vitals_dns") == 0 && attributes == 0 && count == 0 && options == NULL);
    ++mutexes;
    return 0x55;
}
int ksceKernelDeleteMutex(SceUID mutex) { assert(mutex == 0x55 && !locked); --mutexes; return 0; }
int ksceKernelLockMutex(SceUID mutex, int count, unsigned int *timeout) {
    assert(mutex == 0x55 && count == 1 && timeout == NULL && !locked);
    locked = 1;
    return 0;
}
int ksceKernelUnlockMutex(SceUID mutex, int count) {
    assert(mutex == 0x55 && count == 1 && locked);
    locked = 0;
    return 0;
}

/* The memory a renamed query is sent from: one page in the app's own process, freed once the send
 * returns */
static _Alignas(16) unsigned char app_block[0x1000];
static int blocks_live, blocks_made, block_failures;
SceUID ksceKernelAllocMemBlock(const char *name, int type, SceSize size, const void *options) {
    const SceKernelAllocMemBlockKernelOpt *kernel_options = options;
    assert(strcmp(name, "vitals_dns") == 0 && type == SCE_KERNEL_MEMBLOCK_TYPE_USER_RW && size == 0x1000);
    assert(kernel_options != NULL && kernel_options->size == sizeof(*kernel_options));
    assert(kernel_options->attr == SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID && kernel_options->pid == current_pid);
    assert(blocks_live == 0);
    if (block_failures) return (int)0x80024303;
    ++blocks_live;
    ++blocks_made;
    memset(app_block, 0xee, sizeof(app_block));
    return 0x66;
}
int ksceKernelGetMemBlockBase(SceUID block, void **base) {
    assert(block == 0x66);
    *base = app_block;
    return 0;
}
int ksceKernelFreeMemBlock(SceUID block) { assert(block == 0x66 && blocks_live == 1); --blocks_live; return 0; }
int ksceKernelCopyToUserProc(SceUID pid, void *destination, const void *source, SceSize length) {
    unsigned char *at = destination;
    assert(pid == current_pid && at >= app_block && at + length <= app_block + sizeof(app_block));
    memcpy(destination, source, length);
    return 0;
}

/* The redirect list, or NULL when it is missing */
static const char *list_text;
static int list_reads;
int ksceIoOpen(const char *path, int flags, int mode) {
    /* DNS rules have their own list, apart from the HTTP library's redirects.txt */
    assert(strcmp(path, "ux0:data/vitals/dns.txt") == 0 && flags == SCE_O_RDONLY && mode == 0);
    ++list_reads;
    return list_text != NULL ? 7 : (int)0x80010002;
}
int ksceIoPread(SceUID fd, void *buffer, SceSize size, SceOff offset) {
    assert(fd == 7);
    size_t length = strlen(list_text);
    if ((size_t)offset >= length) return 0;
    size_t count = length - (size_t)offset < size ? length - (size_t)offset : size;
    memcpy(buffer, list_text + offset, count);
    return (int)count;
}
int ksceIoClose(int fd) { assert(fd == 7); return 0; }

/* A standard question for name (dotted), of the given type, at out + 12 */
static size_t question(unsigned char *out, const char *name, unsigned type) {
    size_t at = 12;
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t label = dot ? (size_t)(dot - name) : strlen(name);
        out[at++] = (unsigned char)label;
        memcpy(out + at, name, label);
        at += label;
        name += label + (dot != NULL);
    }
    out[at++] = 0;
    out[at++] = (unsigned char)(type >> 8);
    out[at++] = (unsigned char)type;
    out[at++] = 0;
    out[at++] = 1;
    return at;
}

/* A standard query for name, of the given type */
static size_t query(unsigned char *out, const char *name, unsigned type) {
    static const unsigned char header[12] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    memcpy(out, header, sizeof(header));
    return question(out, name, type);
}

/* A server's answer to query id for name: a CNAME first when cname is set, then count addresses
 * 93.184.216.N (N from 34), each with TTL ttl + N */
static size_t answer(unsigned char *out, unsigned id, const char *name, unsigned rcode, int cname, unsigned count,
                     uint32_t ttl) {
    unsigned char header[12] = {(unsigned char)(id >> 8), (unsigned char)id, 0x81, (unsigned char)(0x80 | rcode),
                                0, 1, 0, (unsigned char)(count + (cname != 0)), 0, 0, 0, 0};
    memcpy(out, header, sizeof(header));
    size_t at = question(out, name, 1);
    if (cname) {
        static const unsigned char record[] = {0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 9, 0, 6, 3, 'c', 'd', 'n', 0xc0, 12};
        memcpy(out + at, record, sizeof(record));
        at += sizeof(record);
    }
    for (unsigned i = 0; i < count; ++i) {
        uint32_t record_ttl = ttl + i;
        const unsigned char record[] = {0xc0, 12, 0, 1, 0, 1, (unsigned char)(record_ttl >> 24),
            (unsigned char)(record_ttl >> 16), (unsigned char)(record_ttl >> 8), (unsigned char)record_ttl, 0, 4,
            93, 184, 216, (unsigned char)(34 + i)};
        memcpy(out + at, record, sizeof(record));
        at += sizeof(record);
    }
    return at;
}

/* The query the system last sent, as the original send call read it from the app's memory */
static unsigned char sent[512];
static size_t sent_length;
static int original_sendto(void *argument) {
    const SendParameter *parameter = argument;
    ++originals;
    last_original_argument = argument;
    if (parameter != NULL && parameter->length <= sizeof(sent)) {
        memcpy(sent, parameter->message, parameter->length);
        sent_length = parameter->length;
    }
    return 77;
}
/* What the network delivers to the app's next receive */
static unsigned char network[512];
static size_t network_length;
static int original_recvfrom(void *argument) {
    ReceiveParameter *parameter = argument;
    ++originals;
    size_t count = network_length < parameter->length ? network_length : parameter->length;
    memcpy(parameter->buffer, network, count);
    return (int)count;
}
int taiHookFunctionExportForKernel(SceUID pid, tai_hook_ref_t *reference, const char *module, uint32_t library,
                                   uint32_t function, const void *hook) {
    static const tai_hook_ref_t originals_by_hook[] = {(tai_hook_ref_t)original_sendto,
        (tai_hook_ref_t)original_recvfrom};
    assert(pid == KERNEL_PID && strcmp(module, "SceNetPs") == 0 && library == UINT32_C(0x2CBED2C6));
    for (int i = 0; i < 2; ++i) {
        if (function != nids[i]) continue;
        ++hooks;
        hooked[i] = (void *)hook;
        *reference = originals_by_hook[i];
        return 9 + i;
    }
    assert(!"unexpected hook");
    return -1;
}
int taiHookReleaseForKernel(SceUID id, tai_hook_ref_t reference) {
    assert((id == 9 || id == 10) && reference != 0);
    ++releases;
    return 0;
}

static void test_parse(void) {
    unsigned char message[600];
    char name[254];
    unsigned type = 0;
    size_t length = query(message, "gs-sec.ww.np.dl.playstation.net", 1);
    assert(vitals_dns_query_name(message, length, name, sizeof(name), &type) == 0);
    assert(strcmp(name, "gs-sec.ww.np.dl.playstation.net") == 0 && type == 1);
    length = query(message, "native-vita.np.ac.playstation.net", 28);
    assert(vitals_dns_query_name(message, length, name, sizeof(name), &type) == 0 && type == 28);
    /* Characters a host name never has are shown as '?' */
    length = query(message, "a\tb.example", 1);
    assert(vitals_dns_query_name(message, length, name, sizeof(name), &type) == 0 && strcmp(name, "a?b.example") == 0);

    /* Not a query, not standard, no question, cut short, compressed, or too long for the buffer */
    length = query(message, "example.com", 1);
    unsigned char bad[600];
    memcpy(bad, message, length); bad[2] |= 0x80;
    assert(vitals_dns_query_name(bad, length, name, sizeof(name), &type) != 0);
    memcpy(bad, message, length); bad[2] |= 0x10;
    assert(vitals_dns_query_name(bad, length, name, sizeof(name), &type) != 0);
    memcpy(bad, message, length); bad[5] = 0;
    assert(vitals_dns_query_name(bad, length, name, sizeof(name), &type) != 0);
    /* Two questions, an answer, or bytes left over after the question */
    memcpy(bad, message, length); bad[5] = 2;
    assert(vitals_dns_query_name(bad, length, name, sizeof(name), &type) != 0);
    memcpy(bad, message, length); bad[7] = 1;
    assert(vitals_dns_query_name(bad, length, name, sizeof(name), &type) != 0);
    memcpy(bad, message, length); bad[length] = 0;
    assert(vitals_dns_query_name(bad, length + 1, name, sizeof(name), &type) != 0);
    /* One additional record (as resolvers add for EDNS) after the question is allowed */
    unsigned char edns[600];
    memcpy(edns, message, length);
    edns[11] = 1;
    static const unsigned char opt[11] = {0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0};
    memcpy(edns + length, opt, sizeof(opt));
    assert(vitals_dns_query_name(edns, length + sizeof(opt), name, sizeof(name), &type) == 0);
    for (size_t cut = 0; cut < length; ++cut)
        assert(vitals_dns_query_name(message, cut, name, sizeof(name), &type) != 0);
    memcpy(bad, message, length); bad[12] = 0xc0;
    assert(vitals_dns_query_name(bad, length, name, sizeof(name), &type) != 0);
    assert(vitals_dns_query_name(message, length, name, 5, &type) != 0);
    assert(vitals_dns_query_name(message, length, name, 12, &type) == 0 && strcmp(name, "example.com") == 0);
    assert(vitals_dns_query_name(message, length, name, 11, &type) != 0);
    assert(vitals_dns_query_name(NULL, length, name, sizeof(name), &type) != 0);
}

static void test_messages(void) {
    unsigned char message[600], output[600];
    char name[254];
    unsigned type = 0;

    /* A renamed query keeps its header, type and class, and any additional record */
    static const char old_name[] = "activity01.ww.np.community.playstation.net";
    size_t length = query(message, old_name, 1);
    size_t size = vitals_dns_rename_query(message, length, "activity.ture.fish", 18, output, sizeof(output));
    assert(size == length - strlen(old_name) + 18 && memcmp(output, message, 12) == 0);
    assert(vitals_dns_query_name(output, size, name, sizeof(name), &type) == 0);
    assert(strcmp(name, "activity.ture.fish") == 0 && type == 1);
    static const char longer[] = "a-much-longer-replacement-host.example.org";
    size = vitals_dns_rename_query(message, length, longer, strlen(longer), output, sizeof(output));
    assert(vitals_dns_query_name(output, size, name, sizeof(name), &type) == 0 && strcmp(name, longer) == 0);
    unsigned char edns[600];
    memcpy(edns, message, length);
    edns[11] = 1;
    static const unsigned char opt[11] = {0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0};
    memcpy(edns + length, opt, sizeof(opt));
    size = vitals_dns_rename_query(edns, length + sizeof(opt), "a.b", 3, output, sizeof(output));
    assert(size == 12 + 5 + 4 + sizeof(opt) && memcmp(output + size - sizeof(opt), opt, sizeof(opt)) == 0);
    assert(vitals_dns_query_name(output, size, name, sizeof(name), &type) == 0 && strcmp(name, "a.b") == 0);
    /* Not a query, not a host name, or no room */
    assert(vitals_dns_rename_query(message, length - 1, "a.b", 3, output, sizeof(output)) == 0);
    assert(vitals_dns_rename_query(message, length, "a..b", 4, output, sizeof(output)) == 0);
    assert(vitals_dns_rename_query(message, length, "a.", 2, output, sizeof(output)) == 0);
    assert(vitals_dns_rename_query(message, length, "", 0, output, sizeof(output)) == 0);
    char long_label[70];
    memset(long_label, 'x', 64);
    assert(vitals_dns_rename_query(message, length, long_label, 64, output, sizeof(output)) == 0);
    assert(vitals_dns_rename_query(message, length, long_label, 63, output, sizeof(output)) == 12 + 65 + 4);
    assert(vitals_dns_rename_query(message, length, "a.b", 3, output, 12 + 5 + 3) == 0);
    assert(vitals_dns_rename_query(message, length, "a.b", 3, output, 12 + 5 + 4) == 12 + 5 + 4);

    /* Addresses after a CNAME, with the lowest TTL; the count kept is limited, not the TTL */
    VitalsDnsAddress addresses[4];
    uint32_t ttl = 0;
    length = answer(message, 0x1234, "new.example", 0, 1, 3, 600);
    assert(vitals_dns_answer_addresses(message, length, 0x1234, addresses, 4, &ttl) == 3 && ttl == 600);
    assert(memcmp(addresses[2].octets, (const unsigned char[]){93, 184, 216, 36}, 4) == 0);
    assert(vitals_dns_answer_addresses(message, length, 0x1234, addresses, 2, &ttl) == 2 && ttl == 600);
    /* Another query's answer, a query, or one cut short is not read; a name error has none */
    assert(vitals_dns_answer_addresses(message, length, 0x1235, addresses, 4, &ttl) == -1);
    for (size_t cut = 0; cut < length; ++cut)
        assert(vitals_dns_answer_addresses(message, cut, 0x1234, addresses, 4, &ttl) == -1);
    unsigned char bad[600];
    memcpy(bad, message, length); bad[2] &= 0x7f;
    assert(vitals_dns_answer_addresses(bad, length, 0x1234, addresses, 4, &ttl) == -1);
    size_t error_length = answer(bad, 0x1234, "new.example", 3, 0, 0, 0);
    assert(vitals_dns_answer_addresses(bad, error_length, 0x1234, addresses, 4, &ttl) == 0);

    /* The answer for the new name, asked in mixed case, becomes one for the old name with only
     * the addresses */
    length = answer(message, 0x1234, "New.EXAMPLE", 0, 1, 2, 600);
    size = vitals_dns_rewrite_answer(message, length, 0x1234, "new.example", "old.host.example", addresses, 2, 60,
                                     output, sizeof(output));
    unsigned char expected[600];
    size_t expected_length = question(expected, "old.host.example", 1);
    assert(size == expected_length + 32 && memcmp(output + 12, expected + 12, expected_length - 12) == 0);
    assert(output[0] == 0x12 && output[1] == 0x34 && output[2] == 0x81 && output[3] == 0x80 && output[5] == 1);
    assert(output[7] == 2 && output[9] == 0 && output[11] == 0);
    VitalsDnsAddress read[4];
    assert(vitals_dns_answer_addresses(output, size, 0x1234, read, 4, &ttl) == 2 && ttl == 60);
    assert(memcmp(read, addresses, sizeof(VitalsDnsAddress) * 2) == 0);
    /* With no addresses, the server's error comes through for the old name */
    size = vitals_dns_rewrite_answer(bad, error_length, 0x1234, "new.example", "old.host.example", NULL, 0, 60,
                                     output, sizeof(output));
    assert(size == expected_length && (output[3] & 0x0f) == 3 && output[7] == 0);
    /* An answer for the same name (an address on the list) keeps its question */
    size = vitals_dns_rewrite_answer(message, length, 0x1234, "new.example", "new.example", addresses, 1, 60,
                                     output, sizeof(output));
    assert(vitals_dns_answer_addresses(output, size, 0x1234, read, 4, &ttl) == 1);
    /* Too small a buffer, another query's answer, another name, a longer name or another type */
    assert(vitals_dns_rewrite_answer(message, length, 0x1234, "new.example", "old.host.example", addresses, 2, 60,
                                     output, expected_length + 31) == 0);
    assert(vitals_dns_rewrite_answer(message, length, 0x1235, "new.example", "old.host.example", addresses, 2, 60,
                                     output, sizeof(output)) == 0);
    assert(vitals_dns_rewrite_answer(message, length, 0x1234, "old.host.example", "old.host.example", addresses, 2,
                                     60, output, sizeof(output)) == 0);
    assert(vitals_dns_rewrite_answer(message, length, 0x1234, "new.example.org", "x.y", addresses, 2, 60, output,
                                     sizeof(output)) == 0);
    assert(vitals_dns_rewrite_answer(message, length, 0x1234, "new", "x.y", addresses, 2, 60, output,
                                     sizeof(output)) == 0);
    assert(vitals_dns_rewrite_answer(message, length, 0x1234, "new.example", "bad..name", addresses, 2, 60, output,
                                     sizeof(output)) == 0);
    memcpy(bad, message, length); bad[12 + 13] = 28;
    assert(vitals_dns_rewrite_answer(bad, length, 0x1234, "new.example", "x.y", addresses, 2, 60, output,
                                     sizeof(output)) == 0);

    VitalsDnsAddress address;
    assert(vitals_dns_parse_address("10.0.0.5", 8, &address) && address.octets[0] == 10 && address.octets[3] == 5);
    assert(vitals_dns_parse_address("255.255.255.255", 15, &address));
    static const char *const not_addresses[] = {"256.0.0.1", "1.2.3", "1.2.3.4.5", "1..2.3", "1.2.3.", "a.b.c.d",
        "1234.1.1.1", "1.2.3.4x", ""};
    for (size_t i = 0; i < sizeof(not_addresses) / sizeof(not_addresses[0]); ++i)
        assert(!vitals_dns_parse_address(not_addresses[i], strlen(not_addresses[i]), &address));
}

/* Sends through the hook on socket 3 to the given port; returns whether anything was logged
 * The system leaves the address's length byte at 0, as seen on hardware; port 0 means a connected
 * socket, which sends with no address */
static int send_to(const unsigned char *message, size_t length, unsigned port, unsigned to_length) {
    unsigned char address[16] = {0, 2, (unsigned char)(port >> 8), (unsigned char)port, 8, 8, 8, 8};
    SendParameter parameter = {3, message, (unsigned)length, 0, port != 0 ? address : NULL, to_length};
    last_log[0] = '\0';
    int before = originals;
    int result = ((int (*)(void *))hooked[SENDTO])(&parameter);
    /* The original always runs, with the same argument, and its result is passed back */
    assert(result == 77 && originals == before + 1 && last_original_argument == &parameter);
    assert(syscall_depth == 0 && !locked && blocks_live == 0);
    return last_log[0] != '\0';
}

/* The app's query for name on a connected socket; returns whether it went out renamed (from the
 * memory block, the app's own query untouched) */
static int send_query(int socket, unsigned id, const char *name, unsigned type) {
    unsigned char message[600], copy[600];
    size_t length = query(message, name, type);
    message[0] = (unsigned char)(id >> 8);
    message[1] = (unsigned char)id;
    memcpy(copy, message, length);
    SendParameter parameter = {socket, message, (unsigned)length, 0, NULL, 0};
    SendParameter before = parameter;
    last_log[0] = '\0';
    assert(((int (*)(void *))hooked[SENDTO])(&parameter) == 77 && syscall_depth == 0 && !locked);
    assert(blocks_live == 0 && memcmp(copy, message, length) == 0 && memcmp(&before, &parameter, sizeof(parameter)) == 0);
    if (last_original_argument == &parameter) return 0;
    /* The copy of the parameter block differs only in the message it points at */
    const SendParameter *renamed = last_original_argument;
    assert((const unsigned char *)renamed == app_block && renamed->socket == socket && renamed->to == NULL);
    assert((const unsigned char *)renamed->message > app_block && renamed->length == sent_length);
    return 1;
}

/* The app's receive on socket, into a buffer of capacity bytes, of what the network delivers;
 * returns its result, with the message received in buffer */
static int receive(int socket, unsigned char *buffer, unsigned capacity, int flags) {
    ReceiveParameter parameter = {socket, buffer, capacity, flags, NULL, NULL};
    last_log[0] = '\0';
    int result = ((int (*)(void *))hooked[RECVFROM])(&parameter);
    assert(syscall_depth == 0 && !locked);
    return result;
}

/* The server answers the query it was sent, with count addresses (0: a name error) */
static void server_answers(unsigned count) {
    char name[254];
    unsigned type;
    assert(vitals_dns_query_name(sent, sent_length, name, sizeof(name), &type) == 0);
    network_length = answer(network, (unsigned)sent[0] << 8 | sent[1], name, count == 0 ? 3 : 0, 1, count, 600);
}

/* The addresses in a received answer to query id for name; -1 when it is not one */
static int received_addresses(const unsigned char *buffer, int length, unsigned id, const char *name,
                              VitalsDnsAddress *addresses) {
    uint32_t ttl;
    char asked[254];
    size_t at = 12, out = 0;
    if (length < 12) return -1;
    while (buffer[at] != 0) {
        if (out) asked[out++] = '.';
        memcpy(asked + out, buffer + at + 1, buffer[at]);
        out += buffer[at];
        at += 1u + buffer[at];
    }
    asked[out] = '\0';
    if (strcmp(asked, name) != 0) return -1;
    return vitals_dns_answer_addresses(buffer, (size_t)length, (uint16_t)id, addresses, 4, &ttl);
}

static void test_log(void) {
    unsigned char message[600];
    size_t length = query(message, "auth.api.np.ac.playstation.net", 1);

    assert(send_to(message, length, 53, 16));
    assert(strcmp(last_log, "vitals: dns query pid=0x4321 title=NPXS10000 name=auth.api.np.ac.playstation.net type=1\n") == 0);
    /* A connected socket sends with no address; the query is still recognised */
    assert(send_to(message, length, 0, 0));
    /* Game traffic on a connected socket is not mistaken for a query */
    unsigned char game[64];
    for (size_t i = 0; i < sizeof(game); ++i) game[i] = (unsigned char)(i * 37 + 11);
    assert(!send_to(game, sizeof(game), 0, 0));
    memcpy(game, message, 12);
    assert(!send_to(game, sizeof(game), 0, 0));

    /* Other ports, other address sizes, sizes no query has, unreadable memory and no parameter
     * pass through without a log */
    assert(!send_to(message, length, 443, 16));
    assert(!send_to(message, length, 5353, 16));
    assert(!send_to(message, length, 53, 28));
    assert(!send_to(message, 16, 53, 16));
    assert(!send_to(message, 513, 53, 16));
    copy_failures = 1;
    assert(!send_to(message, length, 53, 16));
    copy_failures = 0;
    last_log[0] = '\0';
    assert(((int (*)(void *))hooked[SENDTO])(NULL) == 77 && last_log[0] == '\0');
    /* A DNS answer sent to port 53 is not a query */
    message[2] |= 0x80;
    assert(!send_to(message, length, 53, 16));
}

static void test_redirect(void) {
    unsigned char buffer[512];
    VitalsDnsAddress addresses[4];
    static const char old_name[] = "activity01.ww.np.community.playstation.net";

    /* The list is read once, then again only after the refresh time */
    int reads = list_reads;
    assert(!send_query(3, 0x0102, "unlisted.example", 1) && list_reads == reads);
    now += 6000000;
    assert(!send_query(3, 0x0103, "unlisted.example", 1) && list_reads > reads);

    /* A listed name goes out asking for the new host, from memory of the app's own; the server's
     * answer comes back as one for the old name */
    assert(send_query(3, 0x0201, old_name, 1) && blocks_made == 1);
    char name[254];
    unsigned type;
    assert(vitals_dns_query_name(sent, sent_length, name, sizeof(name), &type) == 0);
    assert(strcmp(name, "activity.ture.fish") == 0 && sent[0] == 0x02 && sent[1] == 0x01);
    assert(strcmp(last_log, "vitals: dns redirect pid=0x4321 title=NPXS10000 "
                            "activity01.ww.np.community.playstation.net -> activity.ture.fish\n") == 0);
    server_answers(2);
    int result = receive(3, buffer, sizeof(buffer), 0);
    assert(received_addresses(buffer, result, 0x0201, old_name, addresses) == 2 && addresses[1].octets[3] == 35);
    assert(strcmp(last_log, "vitals: dns redirect answered pid=0x4321 title=NPXS10000 "
                            "name=activity01.ww.np.community.playstation.net address=93.184.216.34 count=2\n") == 0);
    /* Only that answer: the next one passes unchanged */
    assert(receive(3, buffer, sizeof(buffer), 0) == (int)network_length && last_log[0] == '\0');
    assert(memcmp(buffer, network, network_length) == 0);

    /* A new host that does not exist: the app gets the name error, for the name it asked */
    assert(send_query(3, 0x0202, old_name, 1));
    server_answers(0);
    result = receive(3, buffer, sizeof(buffer), 0);
    assert(received_addresses(buffer, result, 0x0202, old_name, addresses) == 0 && (buffer[3] & 0x0f) == 3);
    assert(strstr(last_log, "with no address rcode=3") != NULL);
    /* A longer new name goes out just the same */
    assert(send_query(3, 0x0203, "short.example", 1));
    assert(vitals_dns_query_name(sent, sent_length, name, sizeof(name), &type) == 0);
    assert(strcmp(name, "a-much-longer-replacement-host.community.example.org") == 0);
    server_answers(1);
    assert(received_addresses(buffer, receive(3, buffer, sizeof(buffer), 0), 0x0203, "short.example", addresses) == 1);

    /* An address on the list: the query goes out as it is, and its answer is replaced */
    assert(!send_query(3, 0x0301, "IP.example", 1));
    assert(strstr(last_log, "IP.example -> 10.0.0.5") != NULL);
    server_answers(0);
    result = receive(3, buffer, sizeof(buffer), 0);
    assert(received_addresses(buffer, result, 0x0301, "IP.example", addresses) == 1);
    assert(memcmp(addresses[0].octets, (const unsigned char[]){10, 0, 0, 5}, 4) == 0);

    /* "block": the query goes out as it is, and whatever the server says, the name doesn't exist */
    assert(!send_query(3, 0x0302, "ads.example", 1));
    assert(strstr(last_log, "ads.example -> BLOCK") != NULL);
    server_answers(2);
    result = receive(3, buffer, sizeof(buffer), 0);
    assert(result >= 12 && (buffer[3] & 0x0f) == 3 && buffer[6] == 0 && buffer[7] == 0);
    assert(received_addresses(buffer, result, 0x0302, "ads.example", addresses) == 0);
    assert(strstr(last_log, "dns blocked") != NULL && strstr(last_log, "name=ads.example") != NULL);

    /* Only the socket and process that asked get it, only the answer to that query, never a
     * peek, and only when it fits */
    assert(send_query(3, 0x0401, old_name, 1));
    server_answers(2);
    assert(receive(4, buffer, sizeof(buffer), 0) == (int)network_length);
    current_pid = 0x5555;
    assert(receive(3, buffer, sizeof(buffer), 0) == (int)network_length);
    current_pid = 0x4321;
    assert(receive(3, buffer, sizeof(buffer), 0x2) == (int)network_length);
    assert(receive(3, buffer, (unsigned)network_length, 0) == (int)network_length);
    network[1] ^= 1;
    assert(receive(3, buffer, sizeof(buffer), 0) == (int)network_length);
    network[1] ^= 1;
    /* Waiting answers expire */
    now += 11000000;
    assert(receive(3, buffer, sizeof(buffer), 0) == (int)network_length);
    assert(memcmp(buffer, network, network_length) == 0);

    /* Without memory for the renamed query, the app's own goes out */
    block_failures = 1;
    assert(!send_query(3, 0x0501, old_name, 1));
    assert(strstr(last_log, "failed rc=0x80024303") != NULL);
    block_failures = 0;
    /* Only A queries are redirected */
    assert(!send_query(3, 0x0601, old_name, 28) && strstr(last_log, "dns query") != NULL);

    /* Many queries at once each keep their answer, up to the table's size */
    for (int socket = 10; socket < 18; ++socket) {
        assert(send_query(socket, 0x0700u + (unsigned)socket, old_name, 1));
    }
    for (int socket = 10; socket < 18; ++socket) {
        network_length = answer(network, 0x0700u + (unsigned)socket, "activity.ture.fish", 0, 0, 1, 30);
        assert(received_addresses(buffer, receive(socket, buffer, sizeof(buffer), 0), 0x0700u + (unsigned)socket,
                                  old_name, addresses) == 1);
    }
    /* With none waiting, receives are left alone without a look */
    copy_failures = 1;
    assert(receive(10, buffer, sizeof(buffer), 0) == (int)network_length);
    copy_failures = 0;
}

int main(void) {
    test_parse();
    test_messages();
    assert(vitals_dns_watch_start() == 9 && hooks == 2 && mutexes == 1);
    assert(vitals_dns_watch_start() == 9 && hooks == 2);
    test_log();
    list_text = "# dns\nactivity01.ww.np.community.playstation.net activity.ture.fish\n"
                "short.example a-much-longer-replacement-host.community.example.org\nip.example 10.0.0.5\n"
                "ads.example BLOCK\n";
    test_redirect();
    vitals_dns_watch_stop();
    vitals_dns_watch_stop();
    assert(releases == 2 && mutexes == 0 && blocks_live == 0);
    puts("kernel DNS: query parsing, listed hosts renamed and answered for the old name, fixed addresses, blocks, "
         "logging, start and stop PASS");
    return 0;
}
