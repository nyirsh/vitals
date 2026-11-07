/* The screen, pads and XMB callbacks, as PS3DK's hello-ppu-font-render sets the RSX up: two display
 * buffers in RSX memory, flipped on vertical blank */

#include "platform.h"

#include "app_log.h"
#include "ui.h"

#include <cell/cell_fs.h>
#include <cell/pad.h>
#include <cell/sysutil.h>
#include <cell/sysutil_sysparam.h>
#include <malloc.h>
#include <ppu-types.h>
#include <rsx/gcm_sys.h>
#include <rsx/rsx.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/memory.h>
#include <sys/ppu_thread.h>
#include <sys/sys_time.h>
#include <sys/timer.h>
#include <sysutil/video.h>
#include <unistd.h>

#define CB_SIZE 0x100000
#define HOST_SIZE (32 * 1024 * 1024)
#define GCM_LABEL_INDEX 255
#define FLIP_TIMEOUT_US 2000000

static gcmContextData *context;
static uint32_t *buffers[2];
static uint16_t screen_width, screen_height;
static int shown, current;
/* The frame at the screen's size, in main memory: each flip copies it into the back buffer, as a
 * game draws each frame afresh, so what the system draws over the app never builds up. Only when
 * the RSX can't scale the canvas (below) */
static uint32_t *frame;
/* The canvas the app draws in, in the main memory mapped for the RSX (after its command buffer), so
 * the RSX's 2D engine scales it into a display buffer itself: the CPU scaled it at 1080p in 98 ms,
 * and copied the result in 12 more. rsx_scaling once it's there */
static uint32_t *mapped_canvas;
static u32 canvas_offset, buffer_offsets[2];
static int rsx_scaling;
/* The canvas's size: the screen's own when it has the layout's shape (1920x1080, 1280x720), so the
 * app draws at the screen's resolution and the RSX copies it as it is; else 1280x720, the RSX scaling
 * it (the SD modes, and 1080's narrower ones: 1600, 1440, 1280 and 960 across) */
static int canvas_width = CHECK_WIDTH, canvas_height = CHECK_HEIGHT;
static volatile int exit_requested;
/* The system draws over the app (the PS button's menu, a dialog): it needs a frame flipped every
 * vertical blank meanwhile, and the app only flips when its own screen changes */
static volatile int system_menu, system_drawing;

/* 0 when the RSX got there within 2 seconds */
static int wait_rsx_idle(void)
{
	u32 label = 1;
	rsxSetWriteBackendLabel(context, GCM_LABEL_INDEX, label);
	rsxSetWaitLabel(context, GCM_LABEL_INDEX, label);
	label++;
	rsxSetWriteBackendLabel(context, GCM_LABEL_INDEX, label);
	rsxFlushBuffer(context);
	for (int waited = 0; *(vu32 *)gcmGetLabelAddress(GCM_LABEL_INDEX) != label; waited += 30) {
		if (waited >= 2000000)
			return -1;
		usleep(30);
	}
	return 0;
}

static int wait_flip(void)
{
	int waited = 0;
	while (gcmGetFlipStatus() != 0) {
		if (waited >= FLIP_TIMEOUT_US)
			return 0;
		usleep(200);
		waited += 200;
	}
	gcmResetFlipStatus();
	return 1;
}

static void on_system_event(uint64_t status, uint64_t parameter, void *user)
{
	(void)parameter, (void)user;
	if (status == CELL_SYSUTIL_REQUEST_EXITGAME)
		exit_requested = 1;
	else if (status == CELL_SYSUTIL_SYSTEM_MENU_OPEN)
		system_menu = 1;
	else if (status == CELL_SYSUTIL_SYSTEM_MENU_CLOSE)
		system_menu = 0;
	else if (status == CELL_SYSUTIL_DRAWING_BEGIN)
		system_drawing = 1;
	else if (status == CELL_SYSUTIL_DRAWING_END)
		system_drawing = 0;
}

int platform_display_init(void)
{
	sys_addr_t host = 0;
	int rc = sys_memory_allocate(HOST_SIZE, SYS_MEMORY_PAGE_SIZE_1M, &host);
	if (rc != 0) {
		app_log("display: sys_memory_allocate 0x%08X", (unsigned)rc);
		return -1;
	}
	rsxInit(&context, CB_SIZE, HOST_SIZE, (void *)(uintptr_t)host);
	if (context == NULL) {
		app_log("display: rsxInit failed");
		return -2;
	}
	videoState state;
	videoResolution resolution;
	rc = videoGetState(VIDEO_PRIMARY, 0, &state);
	if (rc != 0 || state.state != 0) {
		app_log("display: videoGetState 0x%08X, state %d", (unsigned)rc, state.state);
		return -3;
	}
	/* The console's own mode, as the XMB has it: switching the TV to 720p (the canvas's size) took
	 * it 2 seconds and left a black screen on the console, so the canvas is scaled instead */
	uint8_t chosen = state.displayMode.resolution;
	int got = videoGetResolution(chosen, &resolution);
	if (got != 0) {
		app_log("display: videoGetResolution(%d) 0x%08X", chosen, (unsigned)got);
		return -4;
	}
	videoConfiguration configuration;
	memset(&configuration, 0, sizeof(configuration));
	configuration.resolution = chosen;
	configuration.format = VIDEO_BUFFER_FORMAT_XRGB;
	configuration.pitch = resolution.width * sizeof(u32);
	configuration.aspect = state.displayMode.aspect;
	if (wait_rsx_idle() != 0)
		app_log("display: the RSX didn't go idle within 2 seconds");
	rc = videoConfigure(VIDEO_PRIMARY, &configuration, NULL, 0);
	if (rc != 0) {
		app_log("display: videoConfigure 0x%08X", (unsigned)rc);
		return -5;
	}
	gcmSetFlipMode(GCM_FLIP_VSYNC);
	gcmResetFlipStatus();
	screen_width = resolution.width;
	screen_height = resolution.height;
	for (int i = 0; i < 2; ++i) {
		u32 offset;
		int pitch = screen_width * (int)sizeof(u32);
		buffers[i] = rsxMemalign(64, (u32)pitch * screen_height);
		int mapped = buffers[i] != NULL ? rsxAddressToOffset(buffers[i], &offset) : -1;
		int set = mapped == 0 ? gcmSetDisplayBuffer(i, offset, pitch, screen_width, screen_height) : -1;
		if (mapped != 0 || set != 0) {
			app_log("display: buffer %d at %p, rsxAddressToOffset 0x%08X, gcmSetDisplayBuffer 0x%08X", i,
			        (void *)buffers[i], (unsigned)mapped, (unsigned)set);
			return -6;
		}
		buffer_offsets[i] = offset;
		memset(buffers[i], 0, (size_t)pitch * screen_height);
	}
	/* The canvas right after the command buffer, in the main memory rsxInit mapped for the RSX */
	mapped_canvas = (uint32_t *)(uintptr_t)(host + CB_SIZE);
	int canvas_mapped = rsxAddressToOffset(mapped_canvas, &canvas_offset);
	rsx_scaling = canvas_mapped == 0;
	if (rsx_scaling) {
		if (screen_height >= CHECK_HEIGHT && (int)screen_width * CHECK_HEIGHT == (int)screen_height * CHECK_WIDTH &&
		    (size_t)screen_width * screen_height * sizeof(uint32_t) <= HOST_SIZE - CB_SIZE) {
			canvas_width = screen_width;
			canvas_height = screen_height;
		}
		memset(mapped_canvas, 0, (size_t)canvas_width * canvas_height * sizeof(uint32_t));
	} else {
		app_log("display: the canvas can't be mapped for the RSX (0x%08X): scaled by the CPU", (unsigned)canvas_mapped);
		mapped_canvas = NULL;
		frame = memalign(128, (size_t)screen_width * screen_height * sizeof(uint32_t));
		if (frame == NULL) {
			app_log("display: no memory for a %ux%u frame", screen_width, screen_height);
			return -7;
		}
		memset(frame, 0, (size_t)screen_width * screen_height * sizeof(uint32_t));
	}
	rc = cellSysutilRegisterCallback(0, on_system_event, NULL);
	if (rc != 0)
		app_log("display: cellSysutilRegisterCallback 0x%08X", (unsigned)rc);
	app_log("display: %ux%u (video mode %d), drawn at %dx%d%s", screen_width, screen_height, chosen, canvas_width,
	        canvas_height, canvas_width == screen_width && canvas_height == screen_height ? "" : ", scaled");
	return 0;
}

/* With a file named "screenshot" in the app's USRDIR, each frame shown is also saved there as
 * screenshot.bmp (24-bit): a screenshot from RPCS3 or the console (RPCS3 empties /dev_hdd0/tmp) */
#define SCREENSHOT_SWITCH "/dev_hdd0/game/" VITALS_TITLE_ID "/USRDIR/screenshot"
#define SCREENSHOT_PATH "/dev_hdd0/game/" VITALS_TITLE_ID "/USRDIR/screenshot.bmp"

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8), p[2] = (uint8_t)(v >> 16), p[3] = (uint8_t)(v >> 24);
}

static void save_screenshot(const uint32_t *canvas)
{
	static int checked, wanted;
	if (!checked) {
		CellFsStat status;
		wanted = cellFsStat(SCREENSHOT_SWITCH, &status) == CELL_FS_SUCCEEDED;
		checked = 1;
	}
	int fd;
	if (!wanted || cellFsOpen(SCREENSHOT_PATH, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &fd, NULL, 0) !=
	                   CELL_FS_SUCCEEDED)
		return;
	const uint32_t row = (uint32_t)canvas_width * 3, size = row * (uint32_t)canvas_height;
	uint8_t head[54] = {'B', 'M'};
	put32(head + 2, 54 + size);
	put32(head + 10, 54);
	put32(head + 14, 40);
	put32(head + 18, (uint32_t)canvas_width);
	put32(head + 22, (uint32_t)canvas_height);
	head[26] = 1;
	head[28] = 24;
	put32(head + 34, size);
	uint64_t written;
	cellFsWrite(fd, head, sizeof(head), &written);
	static uint8_t line[1920 * 3];
	for (int y = canvas_height - 1; y >= 0; --y) {
		for (int x = 0; x < canvas_width && x < 1920; ++x) {
			uint32_t px = canvas[y * canvas_width + x];
			line[x * 3] = (uint8_t)px, line[x * 3 + 1] = (uint8_t)(px >> 8), line[x * 3 + 2] = (uint8_t)(px >> 16);
		}
		cellFsWrite(fd, line, row, &written);
	}
	cellFsClose(fd);
}

/* Two pixels mixed, weight w (0 to 256) of the second: red and blue together, then green */
static inline uint32_t mix(uint32_t a, uint32_t b, uint32_t w)
{
	uint32_t rb = (((a & 0xff00ffu) * (256 - w) + (b & 0xff00ffu) * w) >> 8) & 0xff00ffu;
	uint32_t g = (((a & 0x00ff00u) * (256 - w) + (b & 0x00ff00u) * w) >> 8) & 0x00ff00u;
	return rb | g;
}

/* The canvas to the screen's size, bilinear, a row at a time into cached memory and then copied to
 * the display buffer: where each column and row comes from is worked out once */
static void scale(const uint32_t *canvas, uint32_t *target)
{
	static uint16_t column[1920], row_of[1080];
	static uint8_t column_weight[1920], row_weight[1080];
	static unsigned for_width, for_height;
	static uint32_t upper[CHECK_WIDTH], line[1920];
	unsigned width = screen_width < 1920 ? screen_width : 1920, height = screen_height < 1080 ? screen_height : 1080;
	if (for_width != width || for_height != height) {
		for (unsigned x = 0; x < width; ++x) {
			uint32_t f = (uint32_t)(((uint64_t)x * (CHECK_WIDTH - 1) << 8) / (width > 1 ? width - 1 : 1));
			column[x] = (uint16_t)(f >> 8);
			column_weight[x] = (uint8_t)(f & 255);
		}
		for (unsigned y = 0; y < height; ++y) {
			uint32_t f = (uint32_t)(((uint64_t)y * (CHECK_HEIGHT - 1) << 8) / (height > 1 ? height - 1 : 1));
			row_of[y] = (uint16_t)(f >> 8);
			row_weight[y] = (uint8_t)(f & 255);
		}
		for_width = width;
		for_height = height;
	}
	for (unsigned y = 0; y < height; ++y) {
		const uint32_t *top = canvas + (size_t)row_of[y] * CHECK_WIDTH;
		const uint32_t *bottom = row_of[y] + 1u < CHECK_HEIGHT ? top + CHECK_WIDTH : top;
		uint32_t wy = row_weight[y];
		/* The two source rows mixed once, then across */
		if (wy == 0)
			memcpy(upper, top, sizeof(upper));
		else
			for (unsigned x = 0; x < CHECK_WIDTH; ++x)
				upper[x] = mix(top[x], bottom[x], wy);
		for (unsigned x = 0; x < width; ++x) {
			unsigned sx = column[x], nx = sx + 1 < CHECK_WIDTH ? sx + 1 : sx;
			uint32_t wx = column_weight[x];
			line[x] = 0xff000000u | (wx == 0 ? upper[sx] & 0xffffffu : mix(upper[sx], upper[nx], wx));
		}
		memcpy(target + (size_t)y * screen_width, line, width * sizeof(uint32_t));
	}
}

/* The canvas into display buffer index, scaled to the screen by the RSX's 2D engine with bilinear
 * filtering (as PSGL resolves its frames, libPSGL's psgl_context.c); the flip queued after it waits
 * for it */
static void rsx_scale_canvas(int index)
{
	/* The canvas's last writes out of the PPU's caches, before the RSX reads it */
	__asm__ volatile("sync" ::: "memory");
	gcmTransferScale scale;
	gcmTransferSurface surface;
	memset(&scale, 0, sizeof(scale));
	memset(&surface, 0, sizeof(surface));
	scale.conversion = GCM_TRANSFER_CONVERSION_TRUNCATE;
	scale.format = GCM_TRANSFER_SCALE_FORMAT_X8R8G8B8;
	scale.operation = GCM_TRANSFER_OPERATION_SRCCOPY;
	scale.clipW = screen_width;
	scale.clipH = screen_height;
	scale.outW = screen_width;
	scale.outH = screen_height;
	scale.ratioX = rsxGetFixedSint32((float)canvas_width / (float)screen_width);
	scale.ratioY = rsxGetFixedSint32((float)canvas_height / (float)screen_height);
	scale.inW = (u16)canvas_width;
	scale.inH = (u16)canvas_height;
	scale.pitch = (u16)(canvas_width * sizeof(uint32_t));
	scale.origin = GCM_TRANSFER_ORIGIN_CENTER;
	scale.interp = GCM_TRANSFER_INTERPOLATOR_LINEAR;
	scale.offset = canvas_offset;
	surface.format = GCM_TRANSFER_SURFACE_FORMAT_A8R8G8B8;
	surface.pitch = (u16)(screen_width * sizeof(uint32_t));
	surface.offset = buffer_offsets[index];
	rsxSetTransferScaleMode(context, GCM_TRANSFER_MAIN_TO_LOCAL, GCM_TRANSFER_SURFACE);
	rsxSetTransferScaleSurface(context, &scale, &surface);
}

/* The frame into the back buffer, then flipped at the next vertical blank: 0, or -1 */
static int show_frame(void)
{
	uint32_t *target = buffers[current];
	if (target == NULL || (!rsx_scaling && frame == NULL))
		return -1;
	if (rsx_scaling)
		rsx_scale_canvas(current);
	else
		memcpy(target, frame, (size_t)screen_width * screen_height * sizeof(uint32_t));
	int flipped = gcmSetFlip(context, current), done = 0;
	if (flipped == 0) {
		rsxFlushBuffer(context);
		gcmSetWaitFlip(context);
		done = wait_flip();
		if (done)
			shown = 1;
	}
	current ^= 1;
	return flipped == 0 && done ? 0 : -1;
}

uint32_t *platform_canvas(void)
{
	return mapped_canvas;
}

void platform_canvas_size(int *width, int *height)
{
	*width = canvas_width;
	*height = canvas_height;
}

void platform_show_again(void)
{
	if (shown)
		show_frame();
}

void platform_present(const uint32_t *canvas)
{
	save_screenshot(canvas);
	if (rsx_scaling) {
		/* Drawn where the RSX reads it already (platform_canvas), else copied there */
		if (canvas != mapped_canvas)
			memcpy(mapped_canvas, canvas, (size_t)canvas_width * canvas_height * sizeof(*canvas));
	} else if (frame == NULL) {
		return;
	} else if (screen_width == CHECK_WIDTH && screen_height == CHECK_HEIGHT) {
		memcpy(frame, canvas, (size_t)CHECK_WIDTH * CHECK_HEIGHT * sizeof(*canvas));
	} else {
		scale(canvas, frame);
	}
	if (show_frame() != 0) {
		static int reported;
		if (!reported)
			app_log("present: the flip failed or timed out");
		reported = 1;
	}
}

void platform_display_close(void)
{
	if (context == NULL)
		return;
	if (shown) {
		gcmSetWaitFlip(context);
		rsxFinish(context, 1);
	}
}

int platform_pad_init(void)
{
	return cellPadInit(7);
}

PadState platform_pad_read(void)
{
	/* A pad's last report stays until it sends another (len 0 means nothing changed) */
	static uint16_t digital1[CELL_PAD_MAX_PORT_NUM], digital2[CELL_PAD_MAX_PORT_NUM];
	static uint8_t left_y[CELL_PAD_MAX_PORT_NUM], right_y[CELL_PAD_MAX_PORT_NUM];
	CellPadInfo2 info;
	PadState state = {0, 128, 128};
	if (cellPadGetInfo2(&info) != CELL_PAD_OK)
		return state;
	for (unsigned port = 0; port < CELL_PAD_MAX_PORT_NUM; ++port) {
		if ((info.port_status[port] & CELL_PAD_STATUS_CONNECTED) == 0) {
			digital1[port] = digital2[port] = 0;
			left_y[port] = right_y[port] = 128;
			continue;
		}
		CellPadData data;
		if (cellPadGetData(port, &data) == CELL_PAD_OK && data.len > 0) {
			digital1[port] = data.button[CELL_PAD_BTN_OFFSET_DIGITAL1];
			digital2[port] = data.button[CELL_PAD_BTN_OFFSET_DIGITAL2];
			left_y[port] = (uint8_t)data.button[CELL_PAD_BTN_OFFSET_ANALOG_LEFT_Y];
			right_y[port] = (uint8_t)data.button[CELL_PAD_BTN_OFFSET_ANALOG_RIGHT_Y];
		}
		unsigned d1 = digital1[port], d2 = digital2[port];
		state.buttons |= (d1 & CELL_PAD_CTRL_UP ? PAD_UP : 0) | (d1 & CELL_PAD_CTRL_DOWN ? PAD_DOWN : 0) |
		                 (d1 & CELL_PAD_CTRL_LEFT ? PAD_LEFT : 0) | (d1 & CELL_PAD_CTRL_RIGHT ? PAD_RIGHT : 0) |
		                 (d1 & CELL_PAD_CTRL_START ? PAD_START : 0) | (d2 & CELL_PAD_CTRL_CROSS ? PAD_CROSS : 0) |
		                 (d2 & CELL_PAD_CTRL_CIRCLE ? PAD_CIRCLE : 0) | (d2 & CELL_PAD_CTRL_SQUARE ? PAD_SQUARE : 0) |
		                 (d2 & CELL_PAD_CTRL_TRIANGLE ? PAD_TRIANGLE : 0);
		/* The stick furthest from the middle wins */
		if (left_y[port] < 100 || left_y[port] > 156)
			state.left_y = left_y[port];
		if (right_y[port] < 100 || right_y[port] > 156)
			state.right_y = right_y[port];
	}
	return state;
}

int platform_circle_confirms(void)
{
	int assign = CELL_SYSUTIL_ENTER_BUTTON_ASSIGN_CROSS;
	return cellSysutilGetSystemParamInt(CELL_SYSUTIL_SYSTEMPARAM_ID_ENTER_BUTTON_ASSIGN, &assign) == 0 &&
	       assign == CELL_SYSUTIL_ENTER_BUTTON_ASSIGN_CIRCLE;
}

int platform_exit_requested(void)
{
	cellSysutilCheckCallback();
	/* While the system draws over the app, the frame again into the back buffer and flipped, one a
	 * vertical blank, as a game keeps drawing */
	if ((system_menu || system_drawing) && shown)
		show_frame();
	return exit_requested;
}

void platform_sleep_ms(unsigned ms)
{
	sys_timer_usleep((uint64_t)ms * 1000);
}

uint64_t platform_now_ms(void)
{
	return (uint64_t)sys_time_get_system_time() / 1000;
}

long platform_read_file(const char *path, char *data, size_t capacity)
{
	int fd;
	if (cellFsOpen(path, CELL_FS_O_RDONLY, &fd, NULL, 0) != CELL_FS_SUCCEEDED)
		return -1;
	uint64_t length = 0, read = 0;
	while (length < capacity && cellFsRead(fd, data + length, capacity - length, &read) == CELL_FS_SUCCEEDED && read != 0)
		length += read;
	cellFsClose(fd);
	return (long)length;
}

/* ---- threads ---- */

struct PlatformThread {
	sys_ppu_thread_t id;
	void (*run)(void *argument);
	void *argument;
};

static void thread_entry(uint64_t argument)
{
	PlatformThread *thread = (PlatformThread *)(uintptr_t)argument;
	thread->run(thread->argument);
	sys_ppu_thread_exit(0);
}

PlatformThread *platform_thread_start(const char *name, void (*run)(void *argument), void *argument, size_t stack_size)
{
	PlatformThread *thread = malloc(sizeof(*thread));
	if (thread == NULL)
		return NULL;
	thread->run = run;
	thread->argument = argument;
	/* Below the main thread's priority (1000), as the test's worker */
	if (sys_ppu_thread_create(&thread->id, thread_entry, (uint64_t)(uintptr_t)thread, 1500, stack_size,
	                          SYS_PPU_THREAD_CREATE_JOINABLE, name) != 0) {
		free(thread);
		return NULL;
	}
	return thread;
}

void platform_thread_join(PlatformThread *thread)
{
	if (thread == NULL)
		return;
	uint64_t ignored;
	sys_ppu_thread_join(thread->id, &ignored);
	free(thread);
}
