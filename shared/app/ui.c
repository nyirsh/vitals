/* The app's screens, the same on every console. They began as the Vita's vitals-app ui.c at 960x544,
 * so its coordinates are scaled to the 1280x720 layout: X() across (4/3), Y() down (720/544), F() for text sizes.
 * Those are layout pixels, 1280x720; the canvas may be the screen's own size, bigger (1920x1080), and
 * every drawing function here turns layout pixels into the canvas's (S()), so text is rendered and
 * shapes are drawn at the screen's resolution instead of stretched after */

#include "ui.h"

#include "font.h"

#include <stdio.h>
#include <string.h>

#define X(v) ((v) * 4 / 3)
#define Y(v) ((v) * 45 / 34)
#define F(v) (((v) * 4 + 1) / 3)

#define RGB(r, g, b) (0xff000000u | ((unsigned)(r) << 16) | ((unsigned)(g) << 8) | (unsigned)(b))

static const uint32_t bg = RGB(16, 20, 27), panel = RGB(27, 34, 45), white = RGB(239, 244, 251),
                      muted = RGB(162, 177, 196), green = RGB(72, 211, 151), red = RGB(255, 115, 125),
                      blue = RGB(111, 186, 255), amber = RGB(242, 198, 116), orange = RGB(255, 173, 80),
                      highlight = RGB(40, 52, 70), dim_blue = RGB(86, 132, 184),
                      /* Greyed out, under muted: the menus' sublabels and notes such as "(current)" */
                      faded = RGB(118, 130, 148);

static int circle_confirms;

void app_set_circle_confirms(int circle)
{
	circle_confirms = circle;
}

/* Layout pixels into the canvas's, rounded (the same factor across and down: the canvas is only
 * bigger when the screen has the layout's shape) */
static int S(int v)
{
	long scaled = (long)v * check_canvas_height() * 2;
	return (int)((scaled >= 0 ? scaled + CHECK_HEIGHT : scaled - CHECK_HEIGHT) / (2 * CHECK_HEIGHT));
}

static float SF(float v)
{
	return v * (float)check_canvas_height() / (float)CHECK_HEIGHT;
}

/* Canvas pixels [x0, x1) x [y0, y1) in c */
static void fill(uint32_t *p, int x0, int y0, int x1, int y1, uint32_t c)
{
	const int w = check_canvas_width(), h = check_canvas_height();
	x0 = x0 < 0 ? 0 : x0, y0 = y0 < 0 ? 0 : y0;
	x1 = x1 > w ? w : x1, y1 = y1 > h ? h : y1;
	for (int yy = y0; yy < y1; ++yy) {
		uint32_t *row = p + yy * w;
		for (int xx = x0; xx < x1; ++xx)
			row[xx] = c;
	}
}

/* A rectangle in layout pixels: its edges scaled, so rectangles side by side still meet */
static void rect(uint32_t *p, int x, int y, int w, int h, uint32_t c)
{
	fill(p, S(x), S(y), S(x + w), S(y + h), c);
}

/* c over the canvas pixel at (x, y) by coverage, 0 (none) to 16 (all of it) */
static void blend(uint32_t *p, int x, int y, uint32_t c, int coverage)
{
	const int w = check_canvas_width();
	if (x < 0 || y < 0 || x >= w || y >= check_canvas_height() || coverage <= 0)
		return;
	uint32_t *at = p + y * w + x;
	if (coverage >= 16) {
		*at = c;
		return;
	}
	uint32_t under = *at, out = 0;
	for (int shift = 0; shift < 24; shift += 8) {
		uint32_t a = (under >> shift) & 255, b = (c >> shift) & 255;
		out |= ((a * (uint32_t)(16 - coverage) + b * (uint32_t)coverage + 8) / 16) << shift;
	}
	*at = (under & 0xff000000u) | out;
}

/* How much of the pixel at (dx, dy) of a corner square (the circle's centre at (radius, radius))
 * the quarter circle covers: 4x4 samples, 0 to 16 */
static int corner_coverage(int dx, int dy, int radius)
{
	const int r = radius * 8;
	int inside = 0;
	for (int j = 0; j < 4; ++j)
		for (int i = 0; i < 4; ++i) {
			int sx = r - (dx * 8 + 2 * i + 1), sy = r - (dy * 8 + 2 * j + 1);
			inside += sx * sx + sy * sy <= r * r;
		}
	return inside;
}

/* A rounded card, its corners smoothed: each corner pixel blended with what's under it by how much
 * the curve covers it */
static void card(uint32_t *p, int x, int y, int w, int h, uint32_t c)
{
	/* In canvas pixels from here */
	const int x0 = S(x), y0 = S(y), x1 = S(x + w), y1 = S(y + h), radius = S(13);
	fill(p, x0 + radius, y0, x1 - radius, y1, c);
	fill(p, x0, y0 + radius, x0 + radius, y1 - radius, c);
	fill(p, x1 - radius, y0 + radius, x1, y1 - radius, c);
	for (int dy = 0; dy < radius; ++dy)
		for (int dx = 0; dx < radius; ++dx) {
			int coverage = corner_coverage(dx, dy, radius);
			blend(p, x0 + dx, y0 + dy, c, coverage);
			blend(p, x1 - 1 - dx, y0 + dy, c, coverage);
			blend(p, x0 + dx, y1 - 1 - dy, c, coverage);
			blend(p, x1 - 1 - dx, y1 - 1 - dy, c, coverage);
		}
}

/* Text in the Vita's sizes, scaled */
/* Text at x, y (layout pixels), its glyphs rendered at the canvas's size: px is the font's size in
 * layout pixels, right where it's cut (CHECK_WIDTH for the screen's edge) */
static void draw_text(uint32_t *p, int x, int y, const char *s, unsigned px, uint32_t c, int right)
{
	check_font_draw(p, S(x), S(y), s, (unsigned)S((int)px), c, right >= CHECK_WIDTH ? check_canvas_width() : S(right));
}

/* How wide text at px is, in layout pixels (measured at the canvas's size, so it fits what's drawn),
 * rounded up: text set against the edge it's clipped at must not cross it, or its last glyph goes */
static int text_width(const char *s, unsigned px)
{
	int canvas = check_font_width(s, (unsigned)S((int)px)), height = check_canvas_height();
	return (canvas * CHECK_HEIGHT + height - 1) / height;
}

int app_text_width(const char *s, unsigned px)
{
	return text_width(s, px);
}

static void text(uint32_t *p, int x, int y, const char *s, uint32_t c, unsigned size)
{
	draw_text(p, x, y, s, F(size), c, X(932));
}

static void text_clipped(uint32_t *p, int x, int y, const char *s, uint32_t c, unsigned size, int right)
{
	draw_text(p, x, y, s, F(size), c, right);
}

static int width(const char *s, unsigned size)
{
	return text_width(s, F(size));
}

static uint32_t tone(enum CheckState s)
{
	return s == CHECK_PASS      ? green
	       : s == CHECK_FAIL    ? red
	       : s == CHECK_RUNNING ? blue
	       : s == CHECK_WARNING ? orange
	       : s == CHECK_INFO    ? amber
	                            : muted;
}

/* A smoothed stroke along the line through points[0..count): every pixel near it blended by how
 * much of it (4x4 samples) lies within half of the line, its ends and joins round. Points are in
 * pixels from (x, y), a pixel's centre at +0.5 */
static void stroke(uint32_t *p, int x, int y, const float (*layout)[2], int count, float half_layout, uint32_t c)
{
	/* In canvas pixels from here, from the canvas's origin */
	float points[4][2];
	count = count > 4 ? 4 : count;
	for (int k = 0; k < count; ++k) {
		points[k][0] = SF((float)x + layout[k][0]);
		points[k][1] = SF((float)y + layout[k][1]);
	}
	const float half = SF(half_layout);
	x = 0;
	y = 0;
	float left = points[0][0], right = left, top = points[0][1], bottom = top;
	for (int k = 1; k < count; ++k) {
		left = points[k][0] < left ? points[k][0] : left;
		right = points[k][0] > right ? points[k][0] : right;
		top = points[k][1] < top ? points[k][1] : top;
		bottom = points[k][1] > bottom ? points[k][1] : bottom;
	}
	for (int py = (int)(top - half) - 1; py <= (int)(bottom + half) + 1; ++py)
		for (int px = (int)(left - half) - 1; px <= (int)(right + half) + 1; ++px) {
			int inside = 0;
			for (int j = 0; j < 4; ++j)
				for (int i = 0; i < 4; ++i) {
					float sx = (float)px + 0.125f + 0.25f * (float)i, sy = (float)py + 0.125f + 0.25f * (float)j;
					int near = 0;
					for (int k = 0; k + 1 < count && !near; ++k) {
						float ax = points[k][0], ay = points[k][1], dx = points[k + 1][0] - ax, dy = points[k + 1][1] - ay;
						float t = ((sx - ax) * dx + (sy - ay) * dy) / (dx * dx + dy * dy);
						t = t < 0.0f ? 0.0f : t > 1.0f ? 1.0f : t;
						float ex = sx - (ax + t * dx), ey = sy - (ay + t * dy);
						near = ex * ex + ey * ey <= half * half;
					}
					inside += near;
				}
			blend(p, x + px, y + py, c, inside);
		}
}

/* The icon for state s, drawn in colour c, in a 24-pixel square. The tick, the cross and the chevron
 * are smoothed strokes along the lines the earlier block-drawn ones followed, as thick and in the
 * same rows (mark_bottom) */
static void mark_colored(uint32_t *p, int x, int y, enum CheckState s, uint32_t c)
{
	if (s == CHECK_PASS) {
		static const float tick[][2] = {{2.0f, 12.0f}, {9.0f, 19.0f}, {25.0f, 3.0f}};
		stroke(p, x, y, tick, 3, 2.6f, c);
	} else if (s == CHECK_FAIL) {
		static const float down[][2] = {{2.5f, 2.0f}, {20.5f, 20.0f}}, up[][2] = {{20.5f, 2.0f}, {2.5f, 20.0f}};
		stroke(p, x, y, down, 2, 2.6f, c);
		stroke(p, x, y, up, 2, 2.6f, c);
	} else if (s == CHECK_WARNING) {
		rect(p, x + 9, y, 5, 15, c);
		rect(p, x + 9, y + 19, 5, 5, c);
	} else if (s == CHECK_RUNNING) {
		/* Its two arms meet in a point */
		static const float chevron[][2] = {{7.0f, 1.0f}, {17.0f, 11.0f}, {7.0f, 21.0f}};
		stroke(p, x, y, chevron, 3, 1.9f, c);
	} else if (s == CHECK_INFO) {
		/* A character, centred in the square */
		draw_text(p, x + (24 - text_width("?", F(24))) / 2, y - 9, "?", F(24), c, CHECK_WIDTH);
	} else {
		rect(p, x + 4, y + 10, 16, 4, c);
	}
}

static void mark(uint32_t *p, int x, int y, enum CheckState s)
{
	mark_colored(p, x, y, s, tone(s));
}

/* The last row each mark fills in its 24-pixel square (mark_colored), to stand it on a baseline */
static int mark_bottom(enum CheckState s)
{
	return s == CHECK_PASS ? 21 : s == CHECK_WARNING ? 23 : 22;
}

/* A filled disc, or a ring when inner is above 0, its edges smoothed: each pixel blended by how
 * much of it (4x4 samples) lies inside, the circles a half pixel out from the pixel centres as
 * before */
static void disc(uint32_t *p, int cx, int cy, int outer, int inner, uint32_t c)
{
	/* In canvas pixels: the centre of layout pixel (cx, cy), the radii a half pixel out */
	const float x = SF((float)cx + 0.5f), y = SF((float)cy + 0.5f), ro = SF((float)outer + 0.5f),
	            ri = SF((float)inner + 0.5f);
	for (int py = (int)(y - ro) - 1; py <= (int)(y + ro) + 1; ++py)
		for (int px = (int)(x - ro) - 1; px <= (int)(x + ro) + 1; ++px) {
			int inside = 0;
			for (int j = 0; j < 4; ++j)
				for (int i = 0; i < 4; ++i) {
					float sx = (float)px + 0.125f + 0.25f * (float)i - x, sy = (float)py + 0.125f + 0.25f * (float)j - y;
					float d = sx * sx + sy * sy;
					inside += d <= ro * ro && (inner == 0 || d > ri * ri);
				}
			blend(p, px, py, c, inside);
		}
}

/* START is drawn as its name on a key cap, in this size */
#define START_TEXT_SIZE 13

/* How much room a symbol takes in the bar; START's key cap is as wide as its name */
static int glyph_width(AppGlyph symbol)
{
	return symbol == APP_GLYPH_START ? width("START", START_TEXT_SIZE) + 19 + 11 : 29;
}

/* A control's symbol in a 21-pixel square at x, y, drawn in the bar's white */
static void glyph(uint32_t *p, int x, int y, AppGlyph symbol)
{
	const uint32_t c = white;
	if (symbol == APP_GLYPH_START) {
		const int w = width("START", START_TEXT_SIZE) + 19, h = 24;
		rect(p, x + 2, y - 1, w - 4, h, c);
		rect(p, x, y + 1, w, h - 4, c);
		rect(p, x + 1, y, w - 2, h - 2, c);
		text(p, x + 9, y + 1, "START", bg, START_TEXT_SIZE);
		return;
	}
	enum { CROSS, CIRCLE, TRIANGLE, SQUARE, DPAD, STICK } shape;
	switch (symbol) {
	case APP_GLYPH_CONFIRM:
		shape = circle_confirms ? CIRCLE : CROSS;
		break;
	case APP_GLYPH_BACK:
		shape = circle_confirms ? CROSS : CIRCLE;
		break;
	case APP_GLYPH_TRIANGLE:
		shape = TRIANGLE;
		break;
	case APP_GLYPH_SQUARE:
		shape = SQUARE;
		break;
	case APP_GLYPH_DPAD:
		shape = DPAD;
		break;
	case APP_GLYPH_STICK:
		shape = STICK;
		break;
	default:
		return;
	}
	if (shape == CROSS)
		for (int i = 0; i < 17; ++i) {
			rect(p, x + 1 + i, y + 1 + i, 3, 3, c);
			rect(p, x + 17 - i, y + 1 + i, 3, 3, c);
		}
	else if (shape == CIRCLE)
		disc(p, x + 10, y + 10, 9, 6, c);
	else if (shape == TRIANGLE) {
		for (int row = 0; row < 16; ++row) {
			int half = row * 9 / 15;
			rect(p, x + 9 - half, y + 2 + row, 3, 1, c);
			rect(p, x + 9 + half, y + 2 + row, 3, 1, c);
		}
		rect(p, x, y + 17, 21, 3, c);
	} else if (shape == SQUARE) {
		rect(p, x + 2, y + 2, 17, 3, c);
		rect(p, x + 2, y + 16, 17, 3, c);
		rect(p, x + 2, y + 2, 3, 17, c);
		rect(p, x + 16, y + 2, 3, 17, c);
	} else if (shape == DPAD) {
		rect(p, x + 8, y + 1, 5, 19, c);
		rect(p, x + 1, y + 8, 19, 5, c);
	} else {
		disc(p, x + 10, y + 10, 9, 6, c);
		disc(p, x + 10, y + 10, 4, 0, c);
	}
}

/* The bar at the bottom: each control's symbols, then what it does */
static void footer(uint32_t *p, const AppHint *hints, unsigned count)
{
	rect(p, 0, Y(509), CHECK_WIDTH, CHECK_HEIGHT - Y(509), panel);
	int x = X(28);
	for (unsigned i = 0; i < count; ++i) {
		AppGlyph symbols[2] = {hints[i].glyph, hints[i].also};
		for (unsigned s = 0; s < 2; ++s)
			if (symbols[s] != APP_GLYPH_NONE) {
				glyph(p, x, Y(518) + 1, symbols[s]);
				x += glyph_width(symbols[s]);
			}
		text(p, x, Y(516), hints[i].label, white, 16);
		x += width(hints[i].label, 16) + X(34);
	}
}

/* A list of checks in one line: how many passed out of how many there are */
static enum CheckState summarize(const enum CheckState *states, unsigned count, int complete, char *label,
                                 size_t capacity)
{
	unsigned passed = 0, failed = 0, finished = 0, not_tested = 0;
	for (unsigned i = 0; i < count; ++i) {
		passed += states[i] == CHECK_PASS;
		failed += states[i] == CHECK_FAIL;
		not_tested += states[i] == CHECK_INFO;
		finished += states[i] == CHECK_PASS || states[i] == CHECK_FAIL || states[i] == CHECK_INFO;
	}
	if (count == 0) {
		snprintf(label, capacity, "%s", complete ? "None listed" : "Waiting");
		return CHECK_WAIT;
	}
	if (finished < count) {
		enum CheckState state = finished || states[0] == CHECK_RUNNING ? CHECK_RUNNING : CHECK_WAIT;
		snprintf(label, capacity, state == CHECK_RUNNING ? "Checking %u/%u" : "Waiting", finished, count);
		return state;
	}
	if (not_tested == count) {
		snprintf(label, capacity, "Not tested");
		return CHECK_INFO;
	}
	snprintf(label, capacity, "%u/%u", passed, count);
	return failed || not_tested ? CHECK_FAIL : CHECK_PASS;
}

/* A summary row under the protocol tiles: name, source, then the summary on the right */
#define SUMMARY_HEIGHT 36
static void summary_row(uint32_t *p, int y, const char *name, const char *source, const char *label,
                        enum CheckState state)
{
	card(p, X(28), Y(y), X(904), Y(SUMMARY_HEIGHT), panel);
	/* The text's capitals in the middle of the card's height: at size 18 they start 6 pixels below
	 * where the text is drawn and are 18 tall (measured in the preview) */
	const int text_y = Y(y) + Y(SUMMARY_HEIGHT) / 2 - 6 - 9;
	text(p, X(44), text_y, name, white, 18);
	text(p, X(270), text_y, source, muted, 18);
	int label_left = X(916) - width(label, 18);
	/* The mark's 24-pixel square in the middle of the card's height */
	mark(p, label_left - 40, Y(y) + (Y(SUMMARY_HEIGHT) - 24) / 2, state);
	text(p, label_left, text_y, label, tone(state), 18);
}

/* The status card in the top right corner: "<label> <mark> <status>"; style picks the icon, color
 * draws it and the status */
static void status_card(uint32_t *p, const char *label, const char *status, enum CheckState style, uint32_t color)
{
	int label_width = width(label, 20), status_width = width(status, 20);
	int box_width = 48 + label_width + 19 + 24 + 16 + status_width;
	int left = X(932) - box_width;
	int icon_left = left + 24 + label_width + 19;
	card(p, left, Y(27), box_width, Y(42), panel);
	text(p, left + 24, Y(34), label, muted, 20);
	mark_colored(p, icon_left, Y(39) + 2, style, color);
	text(p, icon_left + 40, Y(34), status, color, 20);
}

static void header(uint32_t *p, const AppStatus *s)
{
	char line[112];
	rect(p, 0, 0, CHECK_WIDTH, CHECK_HEIGHT, bg);
	text(p, X(28), Y(17), "vitals", white, 32);
	if (s->console != NULL && s->console[0] != '\0')
		snprintf(line, sizeof(line), "Version %s, on %s", VITALS_VERSION, s->console);
	else
		snprintf(line, sizeof(line), "Version %s", VITALS_VERSION);
	text(p, X(30), Y(58), line, muted, 17);
	char status[48];
	int known = s->installed_version != NULL && s->installed_version[0] != '\0';
	if (s->outdated && known && strcmp(s->installed_version, VITALS_VERSION) != 0)
		snprintf(status, sizeof(status), "%s -> %s", s->installed_version, VITALS_VERSION);
	else if (s->outdated)
		snprintf(status, sizeof(status), known ? "%s, other build" : "update available", s->installed_version);
	else if (s->installed && s->debug_output != NULL)
		snprintf(status, sizeof(status), "%s, %s", known ? s->installed_version : "installed", s->debug_output);
	else if (s->installed)
		snprintf(status, sizeof(status), "%s", known ? s->installed_version : "installed");
	else
		snprintf(status, sizeof(status), "not installed");
	enum CheckState style = s->outdated ? CHECK_WARNING : s->installed ? CHECK_PASS : CHECK_FAIL;
	/* A working debug build keeps its checkmark, in amber so it stands out */
	status_card(p, "vitals:", status, style, style == CHECK_PASS && s->debug_output != NULL ? amber : tone(style));
}

/* A choice's arrows: smaller than the choice (size 21), and drawn this much lower so they're
 * centred on its capitals (measured in the preview) */
#define CHOICE_ARROW_SIZE 16
#define CHOICE_ARROW_DROP 2

/* A menu's cards from y down; size 0 the tallest, 1 shorter, 2 shorter still */
static void menu(uint32_t *p, const AppMenuItem *items, unsigned count, unsigned selected_item, int y, int size)
{
	int compact = size >= 1, tight = size >= 2;
	int height = Y(tight ? 46 : compact ? 54 : 62), step = Y(tight ? 50 : compact ? 62 : 72);
	for (unsigned i = 0; i < count; ++i) {
		int selected = i == selected_item;
		card(p, X(28), y, X(904), height, selected ? highlight : panel);
		if (selected)
			rect(p, X(28), y + Y(12), 5, height - 2 * Y(12), blue);
		const int label_y = y + Y(tight ? 2 : compact ? 4 : 7);
		text(p, X(48), label_y, items[i].label, selected ? white : muted, 21);
		/* A choice reads apart from its label: in blue between arrows, then whether it is the one in
		 * use now */
		if (items[i].choice != NULL) {
			/* An arrow only where Left or Right can go, its place kept so the choice doesn't move */
			static const char left[] = "<  ", right[] = "  >";
			uint32_t color = selected ? blue : dim_blue;
			uint32_t tone = items[i].choice_tone == APP_TONE_ORANGE ? orange
			                : items[i].choice_tone == APP_TONE_RED  ? red
			                                                        : color;
			int x = X(48) + width(items[i].label, 21) + X(18);
			if (!items[i].choice_first)
				text(p, x, label_y + CHOICE_ARROW_DROP, left, color, CHOICE_ARROW_SIZE);
			x += width(left, CHOICE_ARROW_SIZE);
			text(p, x, label_y, items[i].choice, tone, 21);
			x += width(items[i].choice, 21);
			if (!items[i].choice_last)
				text(p, x, label_y + CHOICE_ARROW_DROP, right, color, CHOICE_ARROW_SIZE);
			x += width(right, CHOICE_ARROW_SIZE);
			if (items[i].choice_current)
				text(p, x + X(12), label_y + Y(4), "(current)", faded, 16);
		} else if (items[i].value != NULL && items[i].value[0] != '\0') {
			/* Small, as "(current)" is: "Last update: 2026-11-04", the date red when alert */
			static const char lead[] = "Last update: ";
			int x = X(48) + width(items[i].label, 21) + X(18);
			text(p, x, label_y + Y(4), lead, faded, 16);
			text(p, x + width(lead, 16), label_y + Y(4), items[i].value, items[i].value_alert ? red : faded, 16);
		}
		text(p, X(48), y + Y(tight ? 25 : compact ? 30 : 37), items[i].description, faded, 16);
		y += step;
	}
}

void app_draw_home(uint32_t *p, const AppHome *home)
{
	header(p, &home->status);
	int y = Y(97);
	if (home->warning_title != NULL) {
		card(p, X(28), y, X(904), Y(70), panel);
		mark(p, X(46), y + Y(14), CHECK_WARNING);
		text(p, X(76), y + Y(8), home->warning_title, amber, 21);
		text(p, X(76), y + Y(40), home->warning_text != NULL ? home->warning_text : "", muted, 16);
		y += Y(86);
	}
	/* Six items only fit above the credits with shorter cards, and seven or more with shorter still */
	menu(p, home->items, home->count, home->selected, y, home->count > 6 ? 2 : home->count > 5 ? 1 : 0);
	static const AppHint usual[] = {
	    {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Choose"},
	    {APP_GLYPH_CONFIRM, APP_GLYPH_NONE, "Select"},
	    {APP_GLYPH_BACK, APP_GLYPH_NONE, "Exit"},
	};
	if (home->hints != NULL)
		footer(p, home->hints, home->hint_count);
	else
		footer(p, usual, sizeof(usual) / sizeof(usual[0]));
}

void app_draw_options(uint32_t *p, const AppOptions *options)
{
	header(p, &options->status);
	text(p, X(28), Y(97), "Options", white, 23);
	/* Five items under the title fit above the note with the shorter cards, six with the home
	 * screen's tight ones */
	menu(p, options->items, options->count, options->selected, Y(135), options->count >= 6 ? 2 : 1);
	static const char note[] = "Reboot the console to apply the changes";
	text(p, (CHECK_WIDTH - width(note, 15)) / 2, Y(482), note, muted, 15);
	footer(p, options->hints, options->hint_count);
}

void app_draw_task(uint32_t *p, const AppTask *task)
{
	header(p, &task->status);
	text(p, X(28), Y(97), task->title, white, 23);
	card(p, X(28), Y(135), X(904), Y(306), panel);
	unsigned first = task->count > APP_TASK_VISIBLE_LINES ? task->count - APP_TASK_VISIBLE_LINES : 0;
	for (unsigned i = first; i < task->count; ++i)
		text_clipped(p, X(48), Y(147) + (int)(i - first) * Y(24), task->lines[i],
		             i + 1 == task->count && task->state == CHECK_RUNNING ? white : muted, 17, X(912));
	/* The mark's bottom on the status line's baseline, as in the TLS tiles: at size 21 the capitals
	 * end 28 pixels below where the line is drawn (measured in the preview) */
	mark(p, X(30), Y(460) + 28 - mark_bottom(task->state), task->state);
	text(p, X(60), Y(460), task->status_line, tone(task->state), 21);
	static const AppHint waiting = {APP_GLYPH_NONE, APP_GLYPH_NONE, "Please wait and keep your PS3 turned on."};
	static const AppHint back = {APP_GLYPH_BACK, APP_GLYPH_NONE, "Back"};
	if (task->state == CHECK_RUNNING)
		footer(p, &waiting, 1);
	else if (task->hints != NULL)
		footer(p, task->hints, task->hint_count);
	else
		footer(p, &back, 1);
}

void app_draw_changelog(uint32_t *p, const AppChangelog *changelog)
{
	header(p, &changelog->status);
	text(p, X(28), Y(97), changelog->title, white, 23);
	const int scrolls = changelog->count > APP_CHANGELOG_VISIBLE_LINES;
	if (scrolls) {
		/* Where the visible part sits in the whole list */
		char position[48];
		unsigned last = changelog->scroll + APP_CHANGELOG_VISIBLE_LINES;
		snprintf(position, sizeof(position), "Lines %u-%u of %u", changelog->scroll + 1,
		         last < changelog->count ? last : changelog->count, changelog->count);
		text(p, X(932) - width(position, 16), Y(104), position, muted, 16);
	}
	card(p, X(28), Y(135), X(904), Y(360), panel);
	for (unsigned i = 0; i < APP_CHANGELOG_VISIBLE_LINES && changelog->scroll + i < changelog->count; ++i) {
		const ChangelogLine *line = &changelog->lines[changelog->scroll + i];
		const int y = Y(147) + (int)i * Y(24);
		switch (line->kind) {
		case CHANGELOG_HEADING:
			draw_text(p, X(48), y - 2, line->text, F(20), white, X(48) + APP_CHANGELOG_WIDTH);
			break;
		case CHANGELOG_ITEM:
			draw_text(p, X(54), y, "-", APP_CHANGELOG_TEXT_SIZE, blue, CHECK_WIDTH);
			/* Then the change's text, level with its continued lines */
			__attribute__((fallthrough));
		case CHANGELOG_CONTINUED:
			draw_text(p, X(48) + APP_CHANGELOG_WIDTH - APP_CHANGELOG_ITEM_WIDTH, y, line->text,
			                APP_CHANGELOG_TEXT_SIZE, muted, X(48) + APP_CHANGELOG_WIDTH);
			break;
		case CHANGELOG_TEXT:
			draw_text(p, X(48), y, line->text, APP_CHANGELOG_TEXT_SIZE, muted, X(48) + APP_CHANGELOG_WIDTH);
			break;
		case CHANGELOG_BLANK:
			break;
		}
	}
	static const AppHint scrolling[] = {
	    {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Scroll"},
	    {APP_GLYPH_BACK, APP_GLYPH_NONE, "Back"},
	};
	footer(p, scrolls ? scrolling : scrolling + 1, scrolls ? 2u : 1u);
}

/* libhttp's certificate flags (CELL_HTTPS_VERIFY_ERROR_*) for the request details */
static void verify_flags(uint32_t flags, char *text_out, size_t capacity)
{
	if (flags == 0)
		snprintf(text_out, capacity, "-");
	else
		snprintf(text_out, capacity, "flags 0x%04X", (unsigned)flags);
}

void check_draw(uint32_t *p, const CheckService *s, int page, unsigned scroll, int busy, const char *notice)
{
	char line[256];
	rect(p, 0, 0, CHECK_WIDTH, CHECK_HEIGHT, bg);
	text(p, X(28), Y(17), "Connection test", white, 32);
	text(p, X(30), Y(58), "TLS, certificates, redirects and DNS rules", muted, 17);
	const char *provider_status = s->vitals_enabled < 0 ? "checking..." : s->vitals_enabled ? "enabled" : "not enabled";
	enum CheckState provider_style = s->vitals_enabled < 0 ? CHECK_WAIT : s->vitals_enabled ? CHECK_PASS : CHECK_FAIL;
	status_card(p, "vitals:", provider_status, provider_style, tone(provider_style));
	for (unsigned col = 0; col < 4; ++col) {
		unsigned v = 3 - col;
		int left = X(28 + (int)col * 232);
		const CheckResult *r = &s->protocols[v];
		card(p, left, Y(97), X(208), Y(80), panel);
		snprintf(line, sizeof(line), "TLS 1.%u", v);
		text(p, left + X(16), Y(105), line, white, 24);
		CheckProtocolDisplay display = check_protocol_display(v, r, s->vitals_enabled);
		/* The mark's bottom on the title's baseline: "TLS 1.3" at size 24 ends 31 pixels below where it's
		 * drawn (measured in the preview) */
		mark(p, left + X(170) - 4, Y(105) + 31 - mark_bottom(display.style), display.style);
		text(p, left + X(16), Y(143), display.label, tone(display.style), 20);
		if (display.qualifier) {
			int x = left + X(192) - width(display.qualifier, 16);
			text(p, x, Y(148), display.qualifier, muted, 16);
		}
	}
	_Static_assert(CHECK_DNS_MAX <= CHECK_REDIRECT_MAX, "the DNS rules' states share the redirects' array");
	enum CheckState states[CHECK_REDIRECT_MAX > CHECK_BADSSL_COUNT ? CHECK_REDIRECT_MAX : CHECK_BADSSL_COUNT];
	char summary[48];
	for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i)
		states[i] = s->badssl[i].state;
	enum CheckState state = summarize(states, CHECK_BADSSL_COUNT, s->complete, summary, sizeof(summary));
	/* The TLS report, as a row like the others: what the server saw, or why there's nothing */
	const char *report_label;
	enum CheckState report_state = s->connection.state;
	if (!s->started && notice && notice[0]) {
		report_label = notice;
		report_state = CHECK_FAIL;
	} else if (report_state == CHECK_PASS && s->handshake.valid)
		report_label = s->handshake.cipher.name;
	else if (report_state == CHECK_RUNNING)
		report_label = "Reading report";
	else if (report_state == CHECK_FAIL || report_state == CHECK_INFO)
		report_label = s->connection.message[0] ? s->connection.message : "Failed";
	else {
		report_label = "Waiting";
		report_state = CHECK_WAIT;
	}
	summary_row(p, 185, "TLS report", "tls.browserleaks.com", report_label, report_state);
	summary_row(p, 227, "Certificate checks", "badssl.com", summary, state);
	for (unsigned i = 0; i < s->redirect_count; ++i)
		states[i] = s->redirects[i].result.state;
	state = summarize(states, s->redirect_count, s->complete, summary, sizeof(summary));
	summary_row(p, 269, "Redirections", CHECK_REDIRECTS_PATH, summary, state);
	/* The DNS rules: Off while flags/dns.off is there, and "Not applied" when every rule tested
	 * got the server's own answer, which is what DNS rules that aren't running this boot give */
	unsigned dns_passed = 0, dns_failed = 0;
	for (unsigned i = 0; i < s->dns_count; ++i) {
		states[i] = s->dns[i].result.state;
		dns_passed += states[i] == CHECK_PASS;
		dns_failed += states[i] == CHECK_FAIL;
	}
	state = summarize(states, s->dns_count, s->complete, summary, sizeof(summary));
	if (s->dns_off && s->dns_count) {
		snprintf(summary, sizeof(summary), "Off");
		state = CHECK_INFO;
	} else if (state == CHECK_FAIL && dns_passed == 0 && dns_failed > 1) {
		snprintf(summary, sizeof(summary), "Not applied");
	}
	summary_row(p, 311, "DNS rules", CHECK_DNS_PATH, summary, state);
	rect(p, X(28), Y(353), X(904), 1, panel);
	if (page == CHECK_PAGE_CIPHERS) {
		text(p, X(28), Y(362), "Cipher suites", white, 23);
		if (s->handshake.cipher_count)
			snprintf(line, sizeof(line), "%u offered / Hold arrows or stick", s->handshake.cipher_count);
		else
			snprintf(line, sizeof(line), "Report unavailable");
		text(p, X(932) - width(line, 16), Y(370), line, muted, 16);
		for (unsigned i = 0; i < CHECK_VISIBLE_CIPHERS && scroll + i < s->handshake.cipher_count; ++i) {
			const CheckNamed *c = &s->handshake.ciphers[scroll + i];
			int y = Y(397 + (int)i * 21);
			snprintf(line, sizeof(line), "%02u", scroll + i + 1);
			text(p, X(30), y, line, muted, 16);
			snprintf(line, sizeof(line), "0x%04X", c->id);
			text(p, X(65), y, line, muted, 16);
			text(p, X(138), y - 1, c->name, white, 18);
		}
		if (!s->handshake.cipher_count) {
			text(p, X(28), Y(407), "No cipher report received.", muted, 20);
			text(p, X(28), Y(440), "Square opens the request errors and handshake details.", muted, 17);
		}
	} else if (page == CHECK_PAGE_REQUESTS) {
		text(p, X(28), Y(362), "Request details", white, 23);
		text(p, X(608), Y(370), "Error / certificate", muted, 16);
		text(p, X(878), Y(370), "Time", muted, 16);
		for (unsigned i = 0; i < 4; ++i) {
			const CheckResult *r = &s->protocols[3 - i];
			int y = Y(394 + (int)i * 22);
			snprintf(line, sizeof(line), "TLS 1.%u", 3 - i);
			text(p, X(30), y, line, white, 18);
			CheckProtocolDisplay display = check_protocol_display(3 - i, r, s->vitals_enabled);
			check_protocol_detail(r, line, sizeof(line));
			text_clipped(p, X(150), y, line, tone(display.detail_style), 18, X(590));
			if (r->error || r->verify_error) {
				char flags[32];
				verify_flags(r->verify_error, flags, sizeof(flags));
				snprintf(line, sizeof(line), "0x%08X / %s", (unsigned)r->error, flags);
			} else
				snprintf(line, sizeof(line), "%s", r->state == CHECK_PASS ? "OK" : "-");
			text(p, X(608), y + 2, line, muted, 16);
			if (r->elapsed_ms)
				snprintf(line, sizeof(line), "%u ms", r->elapsed_ms);
			else
				snprintf(line, sizeof(line), "-");
			text(p, X(856), y + 2, line, muted, 16);
		}
	} else if (page == CHECK_PAGE_CERTIFICATES) {
		text(p, X(28), Y(362), "Certificate checks", white, 23);
		snprintf(line, sizeof(line), "%u hosts / Hold arrows or stick", CHECK_BADSSL_COUNT);
		text(p, X(932) - width(line, 16), Y(370), line, muted, 16);
		/* The host, what it tests and whether it should load, then what it gave */
		for (unsigned i = 0; i < CHECK_VISIBLE_BADSSL && scroll + i < CHECK_BADSSL_COUNT; ++i) {
			const CheckBadssl *test = check_badssl(scroll + i);
			const CheckResult *r = &s->badssl[scroll + i];
			int y = Y(397 + (int)i * 21);
			snprintf(line, sizeof(line), "%s: %s, should %s", test->host, test->label, test->refuse ? "be refused" : "load");
			text_clipped(p, X(30), y, line, white, 16, X(530));
			snprintf(line, sizeof(line), "%s",
			         r->message[0] ? r->message : r->state == CHECK_RUNNING ? "Testing..." : "Waiting");
			text_clipped(p, X(545), y, line, tone(r->state), 16, X(840));
			if (r->elapsed_ms)
				snprintf(line, sizeof(line), "%u ms", r->elapsed_ms);
			else
				snprintf(line, sizeof(line), "-");
			text(p, X(856), y, line, muted, 16);
		}
	} else if (page == CHECK_PAGE_REDIRECTS) {
		text(p, X(28), Y(362), "Host redirects", white, 23);
		if (s->redirect_count == 0)
			text(p, X(28), Y(407), "No redirects listed in " CHECK_REDIRECTS_PATH ".", muted, 20);
		else {
			snprintf(line, sizeof(line), "%u listed / Hold arrows or stick", s->redirect_count);
			text(p, X(932) - width(line, 16), Y(370), line, muted, 16);
		}
		/* Old host -> new host, then what requesting the old host through vitals gave */
		for (unsigned i = 0; i < CHECK_VISIBLE_REDIRECTS && scroll + i < s->redirect_count; ++i) {
			const CheckRedirect *redirect = &s->redirects[scroll + i];
			const CheckResult *r = &redirect->result;
			int y = Y(397 + (int)i * 21);
			snprintf(line, sizeof(line), "%s -> %s", redirect->from, redirect->to);
			text_clipped(p, X(30), y, line, white, 16, X(530));
			snprintf(line, sizeof(line), "%s",
			         r->message[0] ? r->message : r->state == CHECK_RUNNING ? "Testing..." : "Waiting");
			text_clipped(p, X(545), y, line, tone(r->state), 16, X(840));
			if (r->elapsed_ms)
				snprintf(line, sizeof(line), "%u ms", r->elapsed_ms);
			else
				snprintf(line, sizeof(line), "-");
			text(p, X(856), y, line, muted, 16);
		}
	} else if (page == CHECK_PAGE_DNS) {
		text(p, X(28), Y(362), "DNS rules", white, 23);
		if (s->dns_count == 0)
			text(p, X(28), Y(407), "No rules listed in " CHECK_DNS_PATH ".", muted, 20);
		else {
			snprintf(line, sizeof(line), "%u listed / Hold arrows or stick", s->dns_count);
			text(p, X(932) - width(line, 16), Y(370), line, muted, 16);
		}
		/* Host -> target, then what looking the host up gave */
		for (unsigned i = 0; i < CHECK_VISIBLE_DNS && scroll + i < s->dns_count; ++i) {
			const CheckRedirect *rule = &s->dns[scroll + i];
			const CheckResult *r = &rule->result;
			int y = Y(397 + (int)i * 21);
			snprintf(line, sizeof(line), "%s -> %s", rule->from, rule->to);
			text_clipped(p, X(30), y, line, white, 16, X(450));
			snprintf(line, sizeof(line), "%s",
			         r->message[0] ? r->message : r->state == CHECK_RUNNING ? "Looking up..." : "Waiting");
			text_clipped(p, X(465), y, line, tone(r->state), 16, X(840));
			if (r->elapsed_ms)
				snprintf(line, sizeof(line), "%u ms", r->elapsed_ms);
			else
				snprintf(line, sizeof(line), "-");
			text(p, X(856), y, line, muted, 16);
		}
	} else {
		text(p, X(28), Y(362), "Handshake details", white, 23);
		/* What was offered, in the corner like the other pages' counts */
		if (s->handshake.valid) {
			snprintf(line, sizeof(line), "%u offered groups / %u extensions", s->handshake.group_count,
			         s->handshake.extension_count);
			text(p, X(932) - width(line, 16), Y(370), line, muted, 16);
		}
		if (s->handshake.valid)
			snprintf(line, sizeof(line), "Negotiated   %s   /   %s   /   0x%04X", s->handshake.version.name,
			         s->handshake.group.name[0] ? s->handshake.group.name : "Key exchange not reported",
			         s->handshake.cipher.id);
		else
			snprintf(line, sizeof(line), "Negotiated   Not reported");
		text(p, X(28), Y(392), line, white, 18);
		snprintf(line, sizeof(line), "Signature   %s",
		         s->handshake.signature.name[0] ? s->handshake.signature.name : "Not reported");
		text(p, X(28), Y(414), line, white, 18);
		snprintf(line, sizeof(line), "ALPN offered   %s", s->handshake.alpn[0] ? s->handshake.alpn : "Not reported");
		text(p, X(28), Y(436), line, white, 18);
		snprintf(line, sizeof(line), "JA3   %s", s->handshake.ja3[0] ? s->handshake.ja3 : "Not reported");
		text(p, X(28), Y(458), line, muted, 17);
		snprintf(line, sizeof(line), "JA4   %s", s->handshake.ja4[0] ? s->handshake.ja4 : "Not reported");
		text(p, X(28), Y(480), line, muted, 17);
	}
	/* Which detail page this is, out of how many Square goes through */
	snprintf(line, sizeof(line), "Details %d/%d", page + 1, CHECK_PAGE_COUNT);
	/* A finished run that wasn't cancelled can have its report saved, once */
	const int saveable = !busy && s->started && s->complete && !s->interrupted;
	const char *save_label = s->report_saved > 0   ? "Saved to /dev_hdd0/vitals/reports/"
	                         : s->report_saved < 0 ? "Save failed, retry"
	                                               : "Save report";
	const AppHint hints[] = {
	    busy ? (AppHint){APP_GLYPH_TRIANGLE, APP_GLYPH_NONE, "Cancel"} : (AppHint){APP_GLYPH_CONFIRM, APP_GLYPH_NONE, "Retry"},
	    {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Scroll"},
	    {APP_GLYPH_SQUARE, APP_GLYPH_NONE, line},
	    {APP_GLYPH_BACK, APP_GLYPH_NONE, "Back"},
	    {APP_GLYPH_START, APP_GLYPH_NONE, save_label},
	};
	footer(p, hints, sizeof(hints) / sizeof(hints[0]) - (saveable ? 0u : 1u));
}
