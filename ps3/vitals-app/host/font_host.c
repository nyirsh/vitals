/* The font backend on a Mac, for host/preview.c: CoreText's Helvetica Neue in place of the PS3's
 * system font, at the same pixel sizes (the em in pixels, as cellFontSetScalePixel takes it) */

#include "font.h"

#include <CoreGraphics/CoreGraphics.h>
#include <CoreText/CoreText.h>
#include <math.h>
#include <string.h>

static CTFontRef fonts[CHECK_FONT_MAX_SIZE + 1];

int check_font_backend_init(void)
{
	return 0;
}

void check_font_backend_close(void)
{
	for (unsigned i = 0; i <= CHECK_FONT_MAX_SIZE; ++i)
		if (fonts[i] != NULL) {
			CFRelease(fonts[i]);
			fonts[i] = NULL;
		}
}

int check_font_raster(unsigned code, unsigned size, CheckGlyph *g)
{
	memset(g, 0, sizeof(*g));
	if (size > CHECK_FONT_MAX_SIZE)
		return -1;
	if (fonts[size] == NULL)
		fonts[size] = CTFontCreateWithName(CFSTR("Helvetica Neue"), (CGFloat)size, NULL);
	CTFontRef font = fonts[size];
	UniChar character = (UniChar)code;
	CGGlyph glyph;
	if (font == NULL || !CTFontGetGlyphsForCharacters(font, &character, &glyph, 1))
		return -1;
	CGSize advance;
	CTFontGetAdvancesForGlyphs(font, kCTFontOrientationHorizontal, &glyph, &advance, 1);
	CGRect box = CTFontGetBoundingRectsForGlyphs(font, kCTFontOrientationHorizontal, &glyph, NULL, 1);
	g->advance = (int)lround(advance.width);
	if (box.size.width <= 0 || box.size.height <= 0)
		return 0;
	g->left = (int)floor(box.origin.x) - 1;
	g->top = (int)ceil(box.origin.y + box.size.height) + 1;
	g->width = (int)ceil(box.origin.x + box.size.width) + 1 - g->left;
	g->height = g->top - ((int)floor(box.origin.y) - 1);
	if (g->width > CHECK_GLYPH_SIDE || g->height > CHECK_GLYPH_SIDE)
		return -1;
	CGColorSpaceRef gray = CGColorSpaceCreateDeviceGray();
	CGContextRef context = CGBitmapContextCreate(g->alpha, CHECK_GLYPH_SIDE, CHECK_GLYPH_SIDE, 8, CHECK_GLYPH_SIDE,
	                                             gray, kCGImageAlphaNone);
	CGColorSpaceRelease(gray);
	if (context == NULL)
		return -1;
	CGContextSetGrayFillColor(context, 1.0, 1.0);
	CGContextSetShouldAntialias(context, true);
	/* Row 0 of the buffer is the top: the baseline is top rows down from it */
	CGPoint origin = {(CGFloat)-g->left, (CGFloat)(CHECK_GLYPH_SIDE - g->top)};
	CTFontDrawGlyphs(font, &glyph, &origin, 1, context);
	CGContextRelease(context);
	return 0;
}
