/* The font backend on the PS3: the system's sans-serif through cellFont (FreeType), set up as
 * PS3DK's hello-ppu-font-render does. Each glyph is rendered into a scratch surface at a known pen
 * position, and where libfont puts its image says how it sits against the pen and the baseline */

#include "font.h"

#include "vitals/log.h"

#include <cell/font.h>
#include <cell/fontFT.h>
#include <cell/sysmodule.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#define SURFACE_SIDE 192
#define PEN_X 48
#define PEN_Y 32

static const CellFontLibrary *library;
static CellFont font;
static CellFontRenderer renderer;
static uint32_t *file_cache;
static uint8_t surface_pixels[SURFACE_SIDE * SURFACE_SIDE];
static int opened, bound;
static unsigned current_size;

static void *allocate(void *object, uint32_t size)
{
	(void)object;
	return malloc(size);
}

static void release(void *object, void *pointer)
{
	(void)object;
	free(pointer);
}

static void *resize(void *object, void *pointer, uint32_t size)
{
	(void)object;
	return realloc(pointer, size);
}

static void *allocate_zeroed(void *object, uint32_t count, uint32_t size)
{
	(void)object;
	return calloc(count, size);
}

int check_font_backend_init(void)
{
	int rc;
	if ((rc = cellSysmoduleLoadModule(CELL_SYSMODULE_FONT)) < 0 || (rc = cellSysmoduleLoadModule(CELL_SYSMODULE_FREETYPE)) < 0 ||
	    (rc = cellSysmoduleLoadModule(CELL_SYSMODULE_FONTFT)) < 0) {
		VITALS_LOG_ALWAYS("font: cellSysmoduleLoadModule 0x%08X", (unsigned)rc);
		return rc;
	}
	file_cache = memalign(128, 1024 * 1024);
	if (file_cache == NULL)
		return -1;
	CellFontConfig config;
	CellFontConfig_initialize(&config);
	config.FileCache.buffer = file_cache;
	config.FileCache.size = 1024 * 1024;
	rc = cellFontInit(&config);
	if (rc != CELL_OK) {
		VITALS_LOG_ALWAYS("font: cellFontInit 0x%08X", (unsigned)rc);
		return rc;
	}
	CellFontLibraryConfigFT ft;
	CellFontLibraryConfigFT_initialize(&ft);
	ft.MemoryIF.Malloc = allocate;
	ft.MemoryIF.Free = release;
	ft.MemoryIF.Realloc = resize;
	ft.MemoryIF.Calloc = allocate_zeroed;
	rc = cellFontInitLibraryFreeType(&ft, &library);
	if (rc != CELL_OK) {
		VITALS_LOG_ALWAYS("font: cellFontInitLibraryFreeType 0x%08X", (unsigned)rc);
		return rc;
	}
	CellFontType type;
	type.type = CELL_FONT_TYPE_DEFAULT_SANS_SERIF;
	type.map = CELL_FONT_MAP_UNICODE;
	rc = cellFontOpenFontset(library, &type, &font);
	if (rc != CELL_OK) {
		VITALS_LOG_ALWAYS("font: cellFontOpenFontset 0x%08X", (unsigned)rc);
		return rc;
	}
	opened = 1;
	if ((rc = cellFontSetResolutionDpi(&font, 72, 72)) != CELL_OK)
		return rc;
	CellFontRendererConfig renderer_config;
	CellFontRendererConfig_initialize(&renderer_config);
	CellFontRendererConfig_setAllocateBuffer(&renderer_config, 64 * 1024, 512 * 1024);
	if ((rc = cellFontCreateRenderer(library, &renderer_config, &renderer)) != CELL_OK ||
	    (rc = cellFontBindRenderer(&font, &renderer)) != CELL_OK) {
		VITALS_LOG_ALWAYS("font: renderer 0x%08X", (unsigned)rc);
		return rc;
	}
	bound = 1;
	return 0;
}

void check_font_backend_close(void)
{
	if (bound) {
		cellFontUnbindRenderer(&font);
		cellFontDestroyRenderer(&renderer);
	}
	if (opened)
		cellFontCloseFont(&font);
	if (library != NULL) {
		cellFontEndLibrary(library);
		cellFontEnd();
	}
	free(file_cache);
	bound = opened = 0;
	library = NULL;
	file_cache = NULL;
}

int check_font_raster(unsigned code, unsigned size, CheckGlyph *g)
{
	memset(g, 0, sizeof(*g));
	if (!bound)
		return -1;
	if (size != current_size) {
		if (cellFontSetScalePixel(&font, (float)size, (float)size) != CELL_OK ||
		    cellFontSetupRenderScalePixel(&font, (float)size, (float)size) != CELL_OK)
			return -1;
		current_size = size;
	}
	CellFontHorizontalLayout layout;
	if (cellFontGetHorizontalLayout(&font, &layout) != CELL_OK)
		return -1;
	CellFontRenderSurface surface;
	memset(surface_pixels, 0, sizeof(surface_pixels));
	cellFontRenderSurfaceInit(&surface, surface_pixels, SURFACE_SIDE, 1, SURFACE_SIDE, SURFACE_SIDE);
	cellFontRenderSurfaceSetScissor(&surface, 0, 0, SURFACE_SIDE, SURFACE_SIDE);
	CellFontGlyphMetrics metrics;
	CellFontImageTransInfo image;
	/* The pen at PEN_X, the line's top at PEN_Y: its baseline is baseLineY below */
	if (cellFontRenderCharGlyphImage(&font, code, &surface, (float)PEN_X, (float)PEN_Y, &metrics, &image) != CELL_OK)
		return -1;
	g->advance = (int)(metrics.Horizontal.advance + 0.5f);
	if (image.Image == NULL || image.imageWidth == 0 || image.imageHeight == 0)
		return 0;
	if (image.imageWidth > CHECK_GLYPH_SIDE || image.imageHeight > CHECK_GLYPH_SIDE)
		return -1;
	ptrdiff_t at = (const uint8_t *)image.Surface - surface_pixels;
	if (at < 0 || at >= (ptrdiff_t)sizeof(surface_pixels))
		return -1;
	int baseline = PEN_Y + (int)(layout.baseLineY + 0.5f);
	g->left = (int)(at % SURFACE_SIDE) - PEN_X;
	g->top = baseline - (int)(at / SURFACE_SIDE);
	g->width = (int)image.imageWidth;
	g->height = (int)image.imageHeight;
	for (int y = 0; y < g->height; ++y)
		memcpy(g->alpha + y * CHECK_GLYPH_SIDE, image.Image + y * image.imageWidthByte, (size_t)g->width);
	return 0;
}
