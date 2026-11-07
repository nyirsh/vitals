/* The Vita under the shared app (platform.h): its 960x544 screen, which the app draws at its own size
 * (ui.c scales the layout to it), the pads, the time and app0:'s files */

#include "platform.h"

#include <psp2/apputil.h>
#include <psp2/ctrl.h>
#include <psp2/display.h>
#include <psp2/io/fcntl.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/system_param.h>
#include <stdlib.h>
#include <string.h>

#define SCREEN_WIDTH 960
#define SCREEN_HEIGHT 544

/* ---- the screen ---- */

/* The screen has one buffer, which shows what's in it: the app draws in canvas, and each finished
 * frame is copied in at the next vertical blank */
static SceUID display = -1;
static uint32_t *pixels, *canvas;
static int display_active;

int platform_display_init(void)
{
    SceKernelAllocMemBlockOpt opt;
    memset(&opt, 0, sizeof(opt));
    opt.size = sizeof(opt);
    opt.attr = 4;
    opt.alignment = 256 * 1024;
    display = sceKernelAllocMemBlock("vitals screen", SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW, 2 * 1024 * 1024, &opt);
    if (display < 0)
        return display;
    void *base = NULL;
    int rc = sceKernelGetMemBlockBase(display, &base);
    if (rc < 0)
        return rc;
    pixels = base;
    canvas = malloc(SCREEN_WIDTH * SCREEN_HEIGHT * sizeof(*canvas));
    if (canvas == NULL)
        return -1;
    memset(pixels, 0, SCREEN_WIDTH * SCREEN_HEIGHT * sizeof(*pixels));
    SceDisplayFrameBuf frame;
    memset(&frame, 0, sizeof(frame));
    frame.size = sizeof(frame);
    frame.base = pixels;
    frame.pitch = SCREEN_WIDTH;
    frame.pixelformat = SCE_DISPLAY_PIXELFORMAT_A8B8G8R8;
    frame.width = SCREEN_WIDTH;
    frame.height = SCREEN_HEIGHT;
    rc = sceDisplaySetFrameBuf(&frame, SCE_DISPLAY_SETBUF_NEXTFRAME);
    if (rc < 0)
        return rc;
    display_active = 1;
    sceDisplayWaitSetFrameBuf();
    return 0;
}

uint32_t *platform_canvas(void)
{
    return canvas;
}

void platform_canvas_size(int *width, int *height)
{
    *width = SCREEN_WIDTH;
    *height = SCREEN_HEIGHT;
}

void platform_present(const uint32_t *frame)
{
    /* The app's 0xAARRGGBB into the screen's A8B8G8R8: red and blue change places */
    sceDisplayWaitVblankStart();
    for (unsigned i = 0; i < SCREEN_WIDTH * SCREEN_HEIGHT; ++i)
    {
        uint32_t v = frame[i];
        pixels[i] = (v & 0xff00ff00u) | ((v >> 16) & 0xffu) | ((v & 0xffu) << 16);
    }
}

void platform_show_again(void)
{
    /* The screen keeps showing its buffer */
}

static int app_util_ready;

void platform_display_close(void)
{
    if (app_util_ready)
        sceAppUtilShutdown();
    app_util_ready = 0;
    if (display_active)
    {
        if (sceDisplaySetFrameBuf(NULL, SCE_DISPLAY_SETBUF_NEXTFRAME) >= 0 && sceDisplayWaitSetFrameBuf() >= 0)
            sceKernelFreeMemBlock(display);
    }
    else if (display >= 0)
        sceKernelFreeMemBlock(display);
    display = -1;
    display_active = 0;
    free(canvas);
    canvas = NULL;
}

/* ---- the pads ---- */

static int circle_confirms;
/* The buttons held at the last sample, for a read with no new sample */
static unsigned last_buttons;
static unsigned last_left_y = 128, last_right_y = 128;

int platform_pad_init(void)
{
    sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG);
    /* Cross confirms and Circle goes back, unless the system setting swaps them (as on Japanese
     * consoles); read once at start-up */
    SceAppUtilInitParam init;
    SceAppUtilBootParam boot;
    memset(&init, 0, sizeof(init));
    memset(&boot, 0, sizeof(boot));
    int rc = sceAppUtilInit(&init, &boot);
    app_util_ready = rc >= 0;
    int enter = SCE_SYSTEM_PARAM_ENTER_BUTTON_CROSS;
    if (app_util_ready && sceAppUtilSystemParamGetInt(SCE_SYSTEM_PARAM_ID_ENTER_BUTTON, &enter) >= 0)
        circle_confirms = enter == SCE_SYSTEM_PARAM_ENTER_BUTTON_CIRCLE;
    return rc < 0 ? rc : 0;
}

static unsigned pad_buttons(unsigned buttons)
{
    static const struct {
        unsigned sce, pad;
    } map[] = {
        {SCE_CTRL_UP, PAD_UP},         {SCE_CTRL_DOWN, PAD_DOWN},         {SCE_CTRL_LEFT, PAD_LEFT},
        {SCE_CTRL_RIGHT, PAD_RIGHT},   {SCE_CTRL_CROSS, PAD_CROSS},       {SCE_CTRL_CIRCLE, PAD_CIRCLE},
        {SCE_CTRL_SQUARE, PAD_SQUARE}, {SCE_CTRL_TRIANGLE, PAD_TRIANGLE}, {SCE_CTRL_START, PAD_START},
    };
    unsigned mask = 0;
    for (unsigned i = 0; i < sizeof(map) / sizeof(map[0]); ++i)
        if (buttons & map[i].sce)
            mask |= map[i].pad;
    return mask;
}

PadState platform_pad_read(void)
{
    /* Every sample queued since the last read, so a press that came and went while a screen was
     * drawn still counts */
    SceCtrlData pads[64];
    int count = sceCtrlReadBufferPositive(0, pads, 64);
    PadState state = {last_buttons, last_left_y, last_right_y};
    for (int i = 0; i < count && i < 64; ++i)
    {
        unsigned buttons = pad_buttons(pads[i].buttons);
        state.buttons = i == 0 ? buttons : state.buttons | buttons;
        last_buttons = buttons;
        last_left_y = state.left_y = pads[i].ly;
        last_right_y = state.right_y = pads[i].ry;
    }
    return state;
}

int platform_circle_confirms(void)
{
    return circle_confirms;
}

/* ---- threads ---- */

struct PlatformThread {
    SceUID id;
    void (*run)(void *argument);
    void *argument;
};

static int thread_entry(SceSize size, void *arguments)
{
    (void)size;
    PlatformThread *thread = *(PlatformThread **)arguments;
    thread->run(thread->argument);
    return sceKernelExitThread(0);
}

PlatformThread *platform_thread_start(const char *name, void (*run)(void *argument), void *argument, size_t stack_size)
{
    PlatformThread *thread = malloc(sizeof(*thread));
    if (thread == NULL)
        return NULL;
    thread->run = run;
    thread->argument = argument;
    thread->id = sceKernelCreateThread(name, thread_entry, 0x10000100, (SceSize)stack_size, 0, 0, NULL);
    /* The thread gets a copy of the pointer */
    if (thread->id < 0 || sceKernelStartThread(thread->id, sizeof(thread), &thread) < 0)
    {
        if (thread->id >= 0)
            sceKernelDeleteThread(thread->id);
        free(thread);
        return NULL;
    }
    return thread;
}

void platform_thread_join(PlatformThread *thread)
{
    if (thread == NULL)
        return;
    sceKernelWaitThreadEnd(thread->id, NULL, NULL);
    sceKernelDeleteThread(thread->id);
    free(thread);
}

/* ---- the system ---- */

int platform_exit_requested(void)
{
    /* The Vita suspends the app instead; it never asks it to end */
    return 0;
}

void platform_sleep_ms(unsigned ms)
{
    sceKernelDelayThread(ms * 1000);
}

uint64_t platform_now_ms(void)
{
    return (uint64_t)sceKernelGetSystemTimeWide() / 1000;
}

long platform_read_file(const char *path, char *data, size_t capacity)
{
    SceUID file = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (file < 0)
        return -1;
    size_t length = 0;
    while (length < capacity)
    {
        int read = sceIoRead(file, data + length, (SceSize)(capacity - length));
        if (read < 0)
        {
            sceIoClose(file);
            return -1;
        }
        if (read == 0)
            break;
        length += (size_t)read;
    }
    sceIoClose(file);
    return (long)length;
}
