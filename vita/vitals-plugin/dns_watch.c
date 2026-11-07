#include "dns_watch.h"
#include "dns_message.h"

#include "vitals/host_map.h"
#include "vitals/redirect_list.h"

#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysroot.h>
#include <taihen.h>
#include <vitasdkkern.h>

#include <stdint.h>

#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif

/* SceNetPsForSyscalls: the kernel side of sceNetSendto and sceNetRecvfrom */
#define SCE_NET_PS_SYSCALLS_NID UINT32_C(0x2CBED2C6)
#define SCE_NET_SYSCALL_SENDTO_NID UINT32_C(0x39796C01)
#define SCE_NET_SYSCALL_RECVFROM_NID UINT32_C(0x144C9758)
/* A DNS query: a 12-byte header, at least a one-letter name, and the type and class */
#define DNS_MESSAGE_MIN 17u
#define DNS_HEADER_SIZE 12u
#define DNS_PORT 53u
#define NET_INET 2u
#define NET_PEEK 0x2
/* How long a query waits for its answer to be rewritten, and how often the list is reread */
#define PENDING_LIFETIME INT64_C(10000000)
#define LIST_REFRESH INT64_C(5000000)
#define PENDING_MAX 8u
/* The TTL given for an address on the list, and the most a rewritten answer may be kept, so that
 * list changes apply soon */
#define ADDRESS_TTL 60u
#define TTL_MAX 300u
/* The system call's kernel stack is small; the work runs on its own */
#define WORK_STACK 8192
/* The memory a renamed query is sent from, in the app's own process: the parameter block, then
 * the query */
#define SEND_BLOCK_SIZE 0x1000u
#define SEND_BLOCK_MESSAGE 0x40u

/* The syscall's parameter block: sceNetSendto's arguments in order (its layout isn't published;
 * confirmed on 3.65 hardware); everything is still checked before use */
typedef struct SendtoParameter
{
    int socket;
    const void *message;
    unsigned int length;
    int flags;
    const void *to;
    unsigned int to_length;
} SendtoParameter;

/* sceNetRecvfrom's arguments, in the same order */
typedef struct RecvfromParameter
{
    int socket;
    void *buffer;
    unsigned int length;
    int flags;
    void *from;
    unsigned int *from_length;
} RecvfromParameter;

/* A query owed a rewritten answer: the app's process, socket and query id, the old name it asked
 * for, and the name the server was asked instead; or, for an address on the list, that address */
typedef struct Pending
{
    SceUID pid;
    int socket;
    unsigned id;
    int literal;
    int blocked;
    int64_t expires;
    char name[VITALS_DNS_HOST_MAX];
    char asked[VITALS_DNS_HOST_MAX];
    VitalsDnsAddress address;
} Pending;

/* A query on its way out; when it is renamed, the copy to send instead, in the app's memory */
typedef struct Sending
{
    const SendtoParameter *parameter;
    SceUID block;
    void *argument;
} Sending;

typedef struct Received
{
    const RecvfromParameter *parameter;
    int result;
} Received;

static SceUID g_send_hook = -1, g_receive_hook = -1;
static tai_hook_ref_t g_send_ref, g_receive_ref;
static int g_redirect;
/* Guards the list and the pending queries */
static SceUID g_lock = -1;
static VitalsHostMap g_map;
static char g_names[VITALS_HOST_MAP_MAX_RULES * 2u * (VITALS_HOST_MAP_MAX_HOST + 1u)];
static size_t g_names_used;
static char g_list_work[VITALS_REDIRECT_LIST_WORK_SIZE];
static int64_t g_list_read_at;
static int g_list_read;
static Pending g_pending[PENDING_MAX];
/* The pending entries in use, read without the lock so that other receives stay cheap */
static int g_pending_count;

static size_t name_length(const char *name)
{
    size_t length = 0;
    while (length < VITALS_DNS_HOST_MAX - 1 && name[length] != '\0')
        ++length;
    return length;
}

static void copy_name(char *to, const char *from)
{
    size_t length = name_length(from);
    for (size_t i = 0; i < length; ++i)
        to[i] = from[i];
    to[length] = '\0';
}

/* "block", without case: the target that makes a name not exist */
static int is_block(const char *target, size_t length)
{
    static const char word[] = "block";
    if (length != sizeof(word) - 1)
        return 0;
    for (size_t i = 0; i < length; ++i)
        if ((target[i] | 0x20) != word[i])
            return 0;
    return 1;
}

static void process_title(SceUID pid, char title[16])
{
    for (size_t i = 0; i < 16; ++i)
        title[i] = '\0';
    (void)ksceKernelSysrootGetProcessTitleId(pid, title, 16);
    title[15] = '\0';
}

static int read_list(unsigned int offset, void *buffer, unsigned int size)
{
    SceUID fd = ksceIoOpen(VITALS_DNS_LIST_PATH, SCE_O_RDONLY, 0);
    if (fd < 0)
        return fd;
    int result = ksceIoPread(fd, buffer, size, (SceOff)offset);
    (void)ksceIoClose(fd);
    return result;
}

/* Copies one pair into g_names; the space holds the most rules the map takes */
static int keep_rule(void *context, const VitalsHostRule *rule)
{
    (void)context;
    char *from = g_names + g_names_used;
    for (size_t i = 0; i < rule->from_length; ++i)
        from[i] = rule->from[i];
    from[rule->from_length] = '\0';
    char *to = from + rule->from_length + 1;
    for (size_t i = 0; i < rule->to_length; ++i)
        to[i] = rule->to[i];
    to[rule->to_length] = '\0';
    g_names_used += rule->from_length + rule->to_length + 2;
    g_map.rules[g_map.count++] = (VitalsHostRule){from, to, rule->from_length, rule->to_length};
    return g_map.count == VITALS_HOST_MAP_MAX_RULES;
}

/* Rereads the list once the last read is older than the refresh time; the lock is held. A
 * missing or unreadable list redirects nothing */
static void refresh_list(int64_t now)
{
    if (g_list_read && now - g_list_read_at < LIST_REFRESH)
        return;
    g_list_read = 1;
    g_list_read_at = now;
    g_map.count = 0;
    g_names_used = 0;
    if (vitals_redirect_list_read(read_list, g_list_work, keep_rule, NULL) < 0)
        g_map.count = 0;
}

/* Keeps a query's answer; one socket waits for one answer, and when every place is taken the
 * entry closest to expiring goes. The lock is held */
static void add_pending(const Pending *entry)
{
    unsigned slot = 0;
    for (unsigned i = 0; i < PENDING_MAX; ++i)
    {
        if (g_pending[i].pid == entry->pid && g_pending[i].socket == entry->socket)
        {
            slot = i;
            break;
        }
        if (g_pending[i].pid == 0 || (g_pending[slot].pid != 0 && g_pending[i].expires < g_pending[slot].expires))
            slot = i;
    }
    if (g_pending[slot].pid == 0)
        __atomic_store_n(&g_pending_count, g_pending_count + 1, __ATOMIC_RELAXED);
    g_pending[slot] = *entry;
}

static void clear_pending(unsigned slot)
{
    g_pending[slot].pid = 0;
    __atomic_store_n(&g_pending_count, g_pending_count - 1, __ATOMIC_RELAXED);
}

/* The renamed query, and a copy of the parameter block pointing at it, in a memory block of the
 * app's own: the system call reads both from the app's memory, and the app's own buffers are left
 * as they are. Returns the block, or a negative error */
static SceUID place_renamed(SceUID pid, const SendtoParameter *parameter, const unsigned char *message, size_t length,
                            void **argument)
{
    SceKernelAllocMemBlockKernelOpt options;
    void *base = NULL;

    for (size_t i = 0; i < sizeof(options); ++i)
        ((unsigned char *)&options)[i] = 0;
    options.size = sizeof(options);
    options.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID;
    options.pid = pid;
    SceUID block = ksceKernelAllocMemBlock("vitals_dns", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, SEND_BLOCK_SIZE, &options);
    if (block < 0)
        return block;
    int result = ksceKernelGetMemBlockBase(block, &base);
    if (result >= 0 && base == NULL)
        result = -1;
    if (result >= 0)
    {
        SendtoParameter renamed = *parameter;
        renamed.message = (const unsigned char *)base + SEND_BLOCK_MESSAGE;
        renamed.length = (unsigned int)length;
        result = ksceKernelCopyToUserProc(pid, (unsigned char *)base + SEND_BLOCK_MESSAGE, message, length);
        if (result >= 0)
            result = ksceKernelCopyToUserProc(pid, base, &renamed, sizeof(renamed));
    }
    if (result < 0)
    {
        (void)ksceKernelFreeMemBlock(block);
        return result;
    }
    *argument = base;
    return block;
}

/* A query on its way out: logged with debug output on, and when its name is on the list, renamed
 * to ask for the new host (or, for an address on the list, sent as it is) */
static int prepare_send(void *argument)
{
    Sending *sending = argument;
    const SendtoParameter *parameter = sending->parameter;
    unsigned char message[VITALS_DNS_MESSAGE_MAX], renamed[VITALS_DNS_MESSAGE_MAX];
    char name[VITALS_DNS_HOST_MAX], target[VITALS_DNS_HOST_MAX], title[16];
    unsigned type;

    if (ksceKernelCopyFromUser(message, parameter->message, parameter->length) < 0 ||
        vitals_dns_query_name(message, parameter->length, name, sizeof(name), &type) != 0)
        return 0;
    SceUID pid = ksceKernelGetProcessId();
    process_title(pid, title);
#if VITALS_DEBUG >= 1
    ksceDebugPrintf("vitals: dns query pid=0x%X title=%s name=%s type=%u\n", pid, title, name, type);
#endif
    if (!g_redirect || type != VITALS_DNS_TYPE_A)
        return 0;

    size_t target_length = 0;
    (void)ksceKernelLockMutex(g_lock, 1, NULL);
    refresh_list(ksceKernelGetSystemTimeWide());
    const VitalsHostRule *rule = vitals_host_map_find(&g_map, name, name_length(name));
    if (rule != NULL)
    {
        target_length = rule->to_length;
        for (size_t i = 0; i <= target_length; ++i)
            target[i] = rule->to[i];
    }
    (void)ksceKernelUnlockMutex(g_lock, 1);
    if (target_length == 0)
        return 0;

    Pending entry = {.pid = pid, .socket = parameter->socket, .id = (unsigned)message[0] << 8 | message[1]};
    copy_name(entry.name, name);
    /* An address on the list, or "block", needs no other server: the query goes out as it is,
     * and its answer is replaced with the address, or with "no such name" */
    entry.blocked = is_block(target, target_length);
    entry.literal = !entry.blocked && vitals_dns_parse_address(target, target_length, &entry.address);
    if (entry.literal || entry.blocked)
        copy_name(entry.asked, name);
    else
    {
        copy_name(entry.asked, target);
        size_t length = vitals_dns_rename_query(message, parameter->length, target, target_length, renamed,
                                                sizeof(renamed));
        SceUID block = length == 0 ? -1 : place_renamed(pid, parameter, renamed, length, &sending->argument);
        if (block < 0)
        {
            ksceDebugPrintf("vitals: dns redirect pid=0x%X title=%s %s -> %s failed rc=0x%08X\n", pid, title, name,
                            target, block);
            return 0;
        }
        sending->block = block;
    }
    entry.expires = ksceKernelGetSystemTimeWide() + PENDING_LIFETIME;
    (void)ksceKernelLockMutex(g_lock, 1, NULL);
    add_pending(&entry);
    (void)ksceKernelUnlockMutex(g_lock, 1);
    ksceDebugPrintf("vitals: dns redirect pid=0x%X title=%s %s -> %s\n", pid, title, name, target);
    return 0;
}

/* A message received on a socket owed an answer: when it is the server's answer to that query,
 * it is rewritten into an answer for the old name */
static int rewrite_received(void *argument)
{
    Received *received = argument;
    const RecvfromParameter *parameter = received->parameter;
    SceUID pid = ksceKernelGetProcessId();
    int64_t now = ksceKernelGetSystemTimeWide();
    unsigned slot = PENDING_MAX;
    Pending entry = {0};

    (void)ksceKernelLockMutex(g_lock, 1, NULL);
    for (unsigned i = 0; i < PENDING_MAX; ++i)
    {
        if (g_pending[i].pid == 0)
            continue;
        if (g_pending[i].expires <= now)
            clear_pending(i);
        else if (g_pending[i].pid == pid && g_pending[i].socket == parameter->socket)
        {
            slot = i;
            entry = g_pending[i];
        }
    }
    (void)ksceKernelUnlockMutex(g_lock, 1);
    if (slot == PENDING_MAX)
        return 0;

    unsigned char response[VITALS_DNS_MESSAGE_MAX], answer[VITALS_DNS_MESSAGE_MAX];
    VitalsDnsAddress addresses[VITALS_DNS_ADDRESSES_MAX];
    size_t length = (unsigned)received->result < sizeof(response) ? (size_t)received->result : sizeof(response);
    size_t capacity = parameter->length < sizeof(answer) ? parameter->length : sizeof(answer);
    if (ksceKernelCopyFromUser(response, parameter->buffer, length) < 0)
        return 0;
    uint32_t ttl = ADDRESS_TTL;
    int count = 1;
    if (entry.blocked)
        count = 0;
    else if (entry.literal)
        addresses[0] = entry.address;
    else
        count = vitals_dns_answer_addresses(response, length, (uint16_t)entry.id, addresses, VITALS_DNS_ADDRESSES_MAX,
                                            &ttl);
    if (count < 0)
        return 0;
    if (ttl > TTL_MAX)
        ttl = TTL_MAX;
    size_t size = vitals_dns_rewrite_answer(response, length, (uint16_t)entry.id, entry.asked, entry.name, addresses,
                                            (unsigned)count, ttl, answer, capacity);
    /* A blocked name doesn't exist, whatever the server said: NXDOMAIN */
    if (size != 0 && entry.blocked)
        answer[3] = (unsigned char)((answer[3] & 0xf0u) | 3u);
    if (size == 0 || ksceKernelCopyToUser(parameter->buffer, answer, size) < 0)
        return 0;
    received->result = (int)size;
    (void)ksceKernelLockMutex(g_lock, 1, NULL);
    if (g_pending[slot].pid == pid && g_pending[slot].socket == entry.socket && g_pending[slot].id == entry.id)
        clear_pending(slot);
    (void)ksceKernelUnlockMutex(g_lock, 1);
    char title[16];
    process_title(pid, title);
    if (entry.blocked)
        ksceDebugPrintf("vitals: dns blocked pid=0x%X title=%s name=%s\n", pid, title, entry.name);
    else if (count > 0)
    {
        const unsigned char *first = addresses[0].octets;
        ksceDebugPrintf("vitals: dns redirect answered pid=0x%X title=%s name=%s address=%u.%u.%u.%u count=%d\n", pid,
                        title, entry.name, first[0], first[1], first[2], first[3], count);
    }
    else
        ksceDebugPrintf("vitals: dns redirect answered pid=0x%X title=%s name=%s with no address rcode=%u\n", pid,
                        title, entry.name, response[3] & 0x0fu);
    return 0;
}

/* An IPv4 address on port 53, its length byte ignored: the system leaves it at 0 */
static int dns_server_address(const unsigned char *address)
{
    return address[1] == NET_INET && address[2] == 0 && address[3] == DNS_PORT;
}

static int sendto_patched(void *argument)
{
    SendtoParameter parameter;
    unsigned char address[16];

    /* A message a DNS query could be, sent to IPv4 port 53 or, on a connected socket, with no
     * address at all (then only its header tells). Only a query-shaped header is copied in full
     * and parsed */
    unsigned char header[DNS_HEADER_SIZE];
    if (argument != NULL && ksceKernelCopyFromUser(&parameter, argument, sizeof(parameter)) >= 0 &&
        parameter.message != NULL && parameter.length >= DNS_MESSAGE_MIN &&
        parameter.length <= VITALS_DNS_MESSAGE_MAX &&
        (parameter.to == NULL ||
         (parameter.to_length == sizeof(address) &&
          ksceKernelCopyFromUser(address, parameter.to, sizeof(address)) >= 0 && dns_server_address(address))) &&
        ksceKernelCopyFromUser(header, parameter.message, sizeof(header)) >= 0 && vitals_dns_query_header(header))
    {
        Sending sending = {&parameter, -1, NULL};
        int state;
        ENTER_SYSCALL(state);
        (void)ksceKernelRunWithStack(WORK_STACK, prepare_send, &sending);
        EXIT_SYSCALL(state);
        if (sending.block >= 0)
        {
            /* The renamed query goes out instead; its memory is only needed until the send returns */
            int result = TAI_CONTINUE(int, g_send_ref, sending.argument);
            ENTER_SYSCALL(state);
            (void)ksceKernelFreeMemBlock(sending.block);
            EXIT_SYSCALL(state);
            return result;
        }
    }
    return TAI_CONTINUE(int, g_send_ref, argument);
}

static int recvfrom_patched(void *argument)
{
    RecvfromParameter parameter;
    int result = TAI_CONTINUE(int, g_receive_ref, argument);

    /* Only while a query is owed an answer is a received message looked at */
    if (result >= (int)DNS_HEADER_SIZE && __atomic_load_n(&g_pending_count, __ATOMIC_RELAXED) > 0 &&
        argument != NULL && ksceKernelCopyFromUser(&parameter, argument, sizeof(parameter)) >= 0 &&
        parameter.buffer != NULL && (parameter.flags & NET_PEEK) == 0 && parameter.length >= (unsigned)result)
    {
        Received received = {&parameter, result};
        int state;
        ENTER_SYSCALL(state);
        (void)ksceKernelRunWithStack(WORK_STACK, rewrite_received, &received);
        EXIT_SYSCALL(state);
        result = received.result;
    }
    return result;
}

SceUID vitals_dns_watch_start(void)
{
    if (g_send_hook >= 0)
        return g_send_hook;
    g_lock = ksceKernelCreateMutex("vitals_dns", 0, 0, NULL);
    if (g_lock < 0)
        return g_lock;
    /* The receive hook goes first: a query the send hook renames needs its answer rewritten */
    g_receive_hook = taiHookFunctionExportForKernel(KERNEL_PID, &g_receive_ref, "SceNetPs", SCE_NET_PS_SYSCALLS_NID,
                                                    SCE_NET_SYSCALL_RECVFROM_NID, recvfrom_patched);
    g_redirect = g_receive_hook >= 0;
    g_send_hook = taiHookFunctionExportForKernel(KERNEL_PID, &g_send_ref, "SceNetPs", SCE_NET_PS_SYSCALLS_NID,
                                                 SCE_NET_SYSCALL_SENDTO_NID, sendto_patched);
    ksceDebugPrintf("vitals: dns hooks send=0x%08X receive=0x%08X\n", g_send_hook, g_receive_hook);
    return g_send_hook;
}

void vitals_dns_watch_stop(void)
{
    if (g_send_hook >= 0)
        (void)taiHookReleaseForKernel(g_send_hook, g_send_ref);
    if (g_receive_hook >= 0)
        (void)taiHookReleaseForKernel(g_receive_hook, g_receive_ref);
    g_send_hook = g_receive_hook = -1;
    g_redirect = 0;
    if (g_lock >= 0)
        (void)ksceKernelDeleteMutex(g_lock);
    g_lock = -1;
}
