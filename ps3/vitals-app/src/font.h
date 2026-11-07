#ifndef VITALS_APP_FONT_H
#define VITALS_APP_FONT_H

#include <stdint.h>

/* Text in the system font, from the Vita's vitals-app font.h: glyphs rasterised by a backend
 * (font_ps3.c, cellFont; host/font_host.c, CoreText) and kept in a cache. The PS3's screen is
 * 1280x720, so glyphs are larger than the Vita's: up to 96 pixels a side, sizes 12 to 64 */

#define CHECK_GLYPH_SIDE 112
#define CHECK_FONT_MIN_SIZE 12
/* The largest text at 1080 (the 1280x720 layout drawn 1.5 times as big) */
#define CHECK_FONT_MAX_SIZE 72

typedef struct {
	uint8_t alpha[CHECK_GLYPH_SIDE * CHECK_GLYPH_SIDE];
	/* The image's size, where it sits from the pen (left) and above the baseline (top), and how
	 * far the pen moves */
	int width, height, left, top, advance;
} CheckGlyph;

/* The backend: 0, or a negative error */
int check_font_backend_init(void);
void check_font_backend_close(void);
/* One character at size pixels, its coverage into glyph->alpha (CHECK_GLYPH_SIDE a row) */
int check_font_raster(unsigned code, unsigned size, CheckGlyph *glyph);

/* The canvas text is drawn into: 1280x720 (CHECK_WIDTH x CHECK_HEIGHT) unless set, else the screen's
 * own size, the layout drawn bigger (ui.c) */
void check_canvas_set(int width, int height);
int check_canvas_width(void);
int check_canvas_height(void);

int check_font_init(void);
void check_font_close(void);
int check_font_width(const char *text, unsigned size);
/* text with its top at top, in color (0xAARRGGBB, alpha ignored), clipped at right */
void check_font_draw(uint32_t *pixels, int x, int top, const char *text, unsigned size, uint32_t color,
                     int right);

#endif
