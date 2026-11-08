#ifndef VITALS_APP_PLATFORM_H
#define VITALS_APP_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* The console under the app (platform_ps3.c, platform_vita.c): the screen, the pads, the time, the
 * app's files and the system's requests. The app draws in a canvas of CHECK_WIDTH x CHECK_HEIGHT
 * layout pixels (ui.h), or the size platform_canvas_size gives, which ui.c scales the layout to */

/* The buttons, as one mask over every pad */
enum {
	PAD_UP = 1 << 0,
	PAD_DOWN = 1 << 1,
	PAD_LEFT = 1 << 2,
	PAD_RIGHT = 1 << 3,
	PAD_CROSS = 1 << 4,
	PAD_CIRCLE = 1 << 5,
	PAD_SQUARE = 1 << 6,
	PAD_TRIANGLE = 1 << 7,
	PAD_START = 1 << 8,
};

typedef struct {
	/* The buttons held, and any pressed and let go since the last read, so a short press isn't
	 * lost while a screen is drawn */
	unsigned buttons;
	/* The sticks' vertical axes, 0 (up) to 255, 128 in the middle */
	unsigned left_y, right_y;
} PadState;

/* The screen: 0, or an error */
int platform_display_init(void);
/* A canvas at the console's own size to draw in after platform_display_init, which platform_present
 * shows: one the screen shows from itself (the PS3's), or one it copies in (the Vita's). NULL when
 * there's none, and platform_present copies (and scales) the 1280x720 one the app made */
uint32_t *platform_canvas(void);
/* The canvas's size: CHECK_WIDTH x CHECK_HEIGHT, or the screen's own, which ui.c draws the layout at */
void platform_canvas_size(int *width, int *height);
/* Shows the canvas at the next vertical blank */
void platform_present(const uint32_t *canvas);
/* The last frame shown again, without drawing it (the PS3's first frames stay black otherwise) */
void platform_show_again(void);
void platform_display_close(void);

int platform_pad_init(void);
/* Every pad's buttons and sticks together */
PadState platform_pad_read(void);
/* Whether the system setting makes Circle confirm (as on Japanese consoles) */
int platform_circle_confirms(void);

/* Runs the system's callbacks; 1 once it has asked the app to exit */
int platform_exit_requested(void);
void platform_sleep_ms(unsigned ms);
/* Milliseconds since some fixed point, for timing key repeats */
uint64_t platform_now_ms(void);

/* Reads at most capacity bytes of the file at path into data: how many, or -1 when it can't be read */
long platform_read_file(const char *path, char *data, size_t capacity);

/* A thread running run(argument) with a stack of stack_size bytes, or NULL when it couldn't start */
typedef struct PlatformThread PlatformThread;
PlatformThread *platform_thread_start(const char *name, void (*run)(void *argument), void *argument, size_t stack_size);
/* Waits for it to end, and frees it */
void platform_thread_join(PlatformThread *thread);
/* A lock between threads, not recursive: NULL when it couldn't be made. It lasts as long as the app */
typedef struct PlatformMutex PlatformMutex;
PlatformMutex *platform_mutex_create(const char *name);
void platform_mutex_lock(PlatformMutex *mutex);
void platform_mutex_unlock(PlatformMutex *mutex);

#endif
