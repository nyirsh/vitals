/* The debug output's file (log_file.h) */

#include "log_file.h"

#include <vitasdkkern.h>

#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include "vitals/log_write.h"
#include "vitals/switches.h"

#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif

#if VITALS_DEBUG < 1

/* The release build has no file: only the system call the modules' stub names */
void vitals_log_file_start(void) {}
void vitals_log_file_stop(void) {}
int vitals_log_write(const char *text, unsigned int length)
{
    (void)text;
    (void)length;
    return 0;
}

#else

#define LOG_DIRECTORY "ux0:data/vitals/logs"
#define LOG_PATH LOG_DIRECTORY "/vitals.log"
#define LOG_OLD_PATH LOG_PATH ".old"
/* Room for a burst of Full debug between two passes */
#define RING_SIZE 0x10000u
#define CHUNK_SIZE 0x1000u
#define STEP_MICROSECONDS 250000u
/* How long ux0: is waited for, in passes: about a minute */
#define WAIT_STEPS 240u

enum
{
    MODE_UNKNOWN,
    MODE_FILE,
    MODE_CONSOLE
};

static char g_ring[RING_SIZE], g_chunk[CHUNK_SIZE];
static unsigned int g_head, g_used, g_dropped, g_waits;
static volatile int g_mode = MODE_UNKNOWN, g_stop;
static int g_rotated;
static SceUID g_lock = -1, g_thread = -1;

int vitals_log_file_put(const char *text, unsigned int length)
{
    if (g_lock < 0 || g_mode == MODE_CONSOLE)
        return 0;
    (void)ksceKernelLockMutex(g_lock, 1, NULL);
    if (length > RING_SIZE - g_used)
    {
        ++g_dropped;
    }
    else
    {
        unsigned int tail = (g_head + g_used) % RING_SIZE, first = RING_SIZE - tail;
        if (first > length)
            first = length;
        memcpy(g_ring + tail, text, first);
        memcpy(g_ring, text + first, length - first);
        g_used += length;
    }
    (void)ksceKernelUnlockMutex(g_lock, 1);
    return g_mode == MODE_FILE;
}

/* Milliseconds since boot, the clock the app's and the modules' lines use */
static unsigned int now_ms(void)
{
    return (unsigned int)((unsigned long long)ksceKernelGetSystemTimeWide() / 1000u);
}

void vitals_log_kernel(const char *name, const char *format, ...)
{
    char line[VITALS_LOG_LINE_MAX];
    int used = snprintf(line, sizeof(line), "%s: [%u ms] ", name, now_ms());
    if (used < 0)
        return;
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line + used, sizeof(line) - (size_t)used, format, arguments);
    va_end(arguments);
    if (length < 0)
        return;
    length += used;
    if ((unsigned int)length >= sizeof(line))
    {
        /* Cut, still a line */
        length = sizeof(line) - 1;
        line[length - 1] = '\n';
    }
    if (!vitals_log_file_put(line, (unsigned int)length))
        ksceDebugPrintf("%s", line);
}

int vitals_log_write(const char *text, unsigned int length)
{
    char line[VITALS_LOG_LINE_MAX];
    int state, taken = 0;
    if (text == NULL || length == 0 || g_mode == MODE_CONSOLE)
        return 0;
    if (length > sizeof(line))
        length = sizeof(line);
    ENTER_SYSCALL(state);
    if (ksceKernelCopyFromUser(line, text, length) >= 0)
        taken = vitals_log_file_put(line, length);
    EXIT_SYSCALL(state);
    return taken;
}

static void decide(void)
{
    SceIoStat status;
    if (ksceIoGetstat("ux0:data", &status) < 0)
    {
        if (++g_waits >= WAIT_STEPS)
            g_mode = MODE_CONSOLE;
        return;
    }
    g_mode = ksceIoGetstat(VITALS_LOG_TO_FILE, &status) >= 0 ? MODE_FILE : MODE_CONSOLE;
}

/* The first time this boot: the folder, and the last boot's log kept once */
static void rotate(void)
{
    SceIoStat status;
    if (g_rotated)
        return;
    g_rotated = 1;
    (void)ksceIoMkdir(LOG_DIRECTORY, 0777);
    if (ksceIoGetstat(LOG_PATH, &status) >= 0)
    {
        (void)ksceIoRemove(LOG_OLD_PATH);
        (void)ksceIoRename(LOG_PATH, LOG_OLD_PATH);
    }
}

static void write_waiting(void)
{
    SceUID fd = -1;
    for (;;)
    {
        (void)ksceKernelLockMutex(g_lock, 1, NULL);
        unsigned int count = g_used < CHUNK_SIZE ? g_used : CHUNK_SIZE, dropped = g_dropped;
        unsigned int first = RING_SIZE - g_head < count ? RING_SIZE - g_head : count;
        memcpy(g_chunk, g_ring + g_head, first);
        memcpy(g_chunk + first, g_ring, count - first);
        g_head = (g_head + count) % RING_SIZE;
        g_used -= count;
        g_dropped = 0;
        (void)ksceKernelUnlockMutex(g_lock, 1);
        if (count == 0 && dropped == 0)
            break;
        if (fd < 0)
        {
            rotate();
            fd = ksceIoOpen(LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
            if (fd < 0)
                return;
        }
        if (count != 0)
            (void)ksceIoWrite(fd, g_chunk, count);
        if (dropped != 0)
        {
            char note[64];
            int length = snprintf(note, sizeof(note), "vitals-boot: [%u ms] %u lines lost, too many at once\n", now_ms(), dropped);
            if (length > 0)
                (void)ksceIoWrite(fd, note, (unsigned int)length);
        }
    }
    if (fd >= 0)
        (void)ksceIoClose(fd);
}

void vitals_log_file_step(void)
{
    if (g_mode == MODE_UNKNOWN)
        decide();
    if (g_mode == MODE_FILE)
        write_waiting();
    else if (g_mode == MODE_CONSOLE && g_used != 0)
    {
        /* The console had them all as they came */
        (void)ksceKernelLockMutex(g_lock, 1, NULL);
        g_head = g_used = g_dropped = 0;
        (void)ksceKernelUnlockMutex(g_lock, 1);
    }
}

static int thread_main(SceSize size, void *argument)
{
    (void)size;
    (void)argument;
    while (!g_stop)
    {
        vitals_log_file_step();
        (void)ksceKernelDelayThread(STEP_MICROSECONDS);
    }
    vitals_log_file_step();
    return 0;
}

void vitals_log_file_start(void)
{
    g_lock = ksceKernelCreateMutex("vitals_log", 0, 0, NULL);
    if (g_lock < 0)
        return;
    g_thread = ksceKernelCreateThread("vitals_log", thread_main, 0x40, 0x2000, 0, 0, NULL);
    if (g_thread >= 0)
        (void)ksceKernelStartThread(g_thread, 0, NULL);
}

void vitals_log_file_stop(void)
{
    if (g_thread >= 0)
    {
        g_stop = 1;
        (void)ksceKernelWaitThreadEnd(g_thread, NULL, NULL);
        (void)ksceKernelDeleteThread(g_thread);
        g_thread = -1;
    }
    if (g_lock >= 0)
    {
        (void)ksceKernelDeleteMutex(g_lock);
        g_lock = -1;
    }
}

#endif
