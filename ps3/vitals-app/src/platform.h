#ifndef VITALS_APP_PLATFORM_H
#define VITALS_APP_PLATFORM_H

#include <stdint.h>

/* The PS3 under the app: the screen (RSX, two display buffers), the pads and the XMB's requests */

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
	unsigned buttons;
	/* The sticks' vertical axes, 0 (up) to 255, 128 in the middle */
	unsigned left_y, right_y;
} PadState;

/* The screen at 1280x720 (or the TV's resolution, the canvas scaled to it): 0, or an error */
int platform_display_init(void);
/* A canvas the RSX copies to the screen itself (main memory mapped for it), to draw in
 * after platform_display_init; NULL when there's none, and platform_present scales on the CPU */
uint32_t *platform_canvas(void);
/* Its size: the screen's own when that has the layout's shape (1920x1080, 1280x720), else 1280x720 */
void platform_canvas_size(int *width, int *height);
/* Shows the 1280x720 canvas at the next vertical blank */
void platform_present(const uint32_t *canvas);
/* The last frame shown again, without drawing or scaling it */
void platform_show_again(void);
void platform_display_close(void);

int platform_pad_init(void);
/* Every pad's buttons and sticks together */
PadState platform_pad_read(void);
/* Whether the system setting makes Circle confirm (Japanese consoles) */
int platform_circle_confirms(void);

/* Runs the XMB's callbacks; 1 once it has asked the app to exit */
int platform_exit_requested(void);
void platform_sleep_ms(unsigned ms);

#endif
