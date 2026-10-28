#include "ui.h"
#include "font.h"
#include "options.h"
#include <stdio.h>
#include <string.h>
#define RGB(r, g, b) (0xff000000u | ((unsigned)(b) << 16) | ((unsigned)(g) << 8) | (r))
static const uint32_t bg = RGB(16, 20, 27), panel = RGB(27, 34, 45), white = RGB(239, 244, 251),
                      muted = RGB(162, 177, 196), green = RGB(72, 211, 151),
                      red = RGB(255, 115, 125), blue = RGB(111, 186, 255),
                      amber = RGB(242, 198, 116), orange = RGB(255, 173, 80),
                      highlight = RGB(40, 52, 70), dim_blue = RGB(86, 132, 184);
static int circle_confirms;
void app_set_circle_confirms(int circle) { circle_confirms = circle; }
static void rect(uint32_t *p, int x, int y, int w, int h, uint32_t c)
{
    for (int yy = y; yy < y + h && yy < CHECK_HEIGHT; ++yy)
        for (int xx = x; xx < x + w && xx < CHECK_WIDTH; ++xx)
            if (xx >= 0 && yy >= 0)
                p[yy * CHECK_WIDTH + xx] = c;
}
static void card(uint32_t *p, int x, int y, int w, int h, uint32_t c)
{
    const int radius = 10;
    rect(p, x + radius, y, w - 2 * radius, h, c);
    rect(p, x, y + radius, w, h - 2 * radius, c);
    for (int dy = 0; dy < radius; ++dy)
        for (int dx = 0; dx < radius; ++dx)
            if ((radius - dx) * (radius - dx) + (radius - dy) * (radius - dy) <= radius * radius)
            {
                rect(p, x + dx, y + dy, 1, 1, c);
                rect(p, x + w - 1 - dx, y + dy, 1, 1, c);
                rect(p, x + dx, y + h - 1 - dy, 1, 1, c);
                rect(p, x + w - 1 - dx, y + h - 1 - dy, 1, 1, c);
            }
}
static void text(uint32_t *p, int x, int y, const char *s, uint32_t c, unsigned size)
{
    check_font_draw(p, x, y, s, size, c, 932);
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
/* The icon for state s, drawn in colour c */
static void mark_colored(uint32_t *p, int x, int y, enum CheckState s, uint32_t c)
{
    if (s == CHECK_PASS)
    {
        for (int i = 0; i < 6; ++i)
            rect(p, x + i, y + 8 + i, 3, 3, c);
        for (int i = 0; i < 13; ++i)
            rect(p, x + 5 + i, y + 13 - i, 3, 3, c);
    }
    else if (s == CHECK_FAIL)
    {
        for (int i = 0; i < 15; ++i)
        {
            rect(p, x + i, y + i, 3, 3, c);
            rect(p, x + 14 - i, y + i, 3, 3, c);
        }
    }
    else if (s == CHECK_WARNING)
    {
        rect(p, x + 7, y, 4, 11, c);
        rect(p, x + 7, y + 14, 4, 4, c);
    }
    else
        text(p, x, y - 7, s == CHECK_RUNNING ? ">" : s == CHECK_INFO ? "?"
                                                                     : "-",
             c, 24);
}
static void mark(uint32_t *p, int x, int y, enum CheckState s)
{
    mark_colored(p, x, y, s, tone(s));
}
/* A filled disc, or a ring when inner is above 0 */
static void disc(uint32_t *p, int cx, int cy, int outer, int inner, uint32_t c)
{
    for (int dy = -outer; dy <= outer; ++dy)
        for (int dx = -outer; dx <= outer; ++dx)
        {
            /* Measured to the pixel's half-way point, so the edge has no single-pixel bumps */
            int distance = dx * dx + dy * dy;
            if (distance <= outer * outer + outer && (inner == 0 || distance > inner * inner + inner))
                rect(p, cx + dx, cy + dy, 1, 1, c);
        }
}
/* A control's symbol in a 16-pixel square at x, y, drawn in the bar's white */
/* START is drawn as its name on a key cap, in this size */
#define START_TEXT_SIZE 13
/* How much room a symbol takes in the bar; START's key cap is as wide as its name */
static int glyph_width(AppGlyph symbol)
{
    return symbol == APP_GLYPH_START ? check_font_width("START", START_TEXT_SIZE) + 14 + 8 : 22;
}
static void glyph(uint32_t *p, int x, int y, AppGlyph symbol)
{
    const uint32_t c = white;
    /* START: its name, dark on a white key cap with rounded corners */
    if (symbol == APP_GLYPH_START)
    {
        const int width = check_font_width("START", START_TEXT_SIZE) + 14, height = 18;
        rect(p, x + 2, y - 1, width - 4, height, c);
        rect(p, x, y + 1, width, height - 4, c);
        rect(p, x + 1, y, width - 2, height - 2, c);
        text(p, x + 7, y, "START", bg, START_TEXT_SIZE);
        return;
    }
    enum
    {
        CROSS,
        CIRCLE,
        TRIANGLE,
        SQUARE,
        DPAD,
        STICK
    } shape;
    switch (symbol)
    {
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
        for (int i = 0; i < 13; ++i)
        {
            rect(p, x + 1 + i, y + 1 + i, 2, 2, c);
            rect(p, x + 13 - i, y + 1 + i, 2, 2, c);
        }
    else if (shape == CIRCLE)
        disc(p, x + 8, y + 8, 7, 5, c);
    else if (shape == TRIANGLE)
    {
        for (int row = 0; row < 12; ++row)
        {
            int half = row * 7 / 11;
            rect(p, x + 7 - half, y + 2 + row, 2, 1, c);
            rect(p, x + 7 + half, y + 2 + row, 2, 1, c);
        }
        rect(p, x, y + 13, 16, 2, c);
    }
    else if (shape == SQUARE)
    {
        rect(p, x + 2, y + 2, 12, 2, c);
        rect(p, x + 2, y + 12, 12, 2, c);
        rect(p, x + 2, y + 2, 2, 12, c);
        rect(p, x + 12, y + 2, 2, 12, c);
    }
    else if (shape == DPAD)
    {
        rect(p, x + 6, y + 1, 4, 14, c);
        rect(p, x + 1, y + 6, 14, 4, c);
    }
    else
    {
        disc(p, x + 8, y + 8, 7, 5, c);
        disc(p, x + 8, y + 8, 3, 0, c);
    }
}
/* The bar at the bottom: each control's symbols, then what it does */
static void footer(uint32_t *p, const AppHint *hints, unsigned count)
{
    rect(p, 0, 509, 960, 35, panel);
    int x = 28;
    for (unsigned i = 0; i < count; ++i)
    {
        AppGlyph symbols[2] = {hints[i].glyph, hints[i].also};
        for (unsigned s = 0; s < 2; ++s)
            if (symbols[s] != APP_GLYPH_NONE)
            {
                glyph(p, x, 518, symbols[s]);
                x += glyph_width(symbols[s]);
            }
        text(p, x, 516, hints[i].label, white, 16);
        x += check_font_width(hints[i].label, 16) + 34;
    }
}
/* A list of checks in one line: how many passed out of how many there are */
static enum CheckState summarize(const enum CheckState *states, unsigned count, int complete,
                                 char *label, size_t capacity)
{
    unsigned passed = 0, failed = 0, finished = 0, not_tested = 0;
    for (unsigned i = 0; i < count; ++i)
    {
        passed += states[i] == CHECK_PASS;
        failed += states[i] == CHECK_FAIL;
        not_tested += states[i] == CHECK_INFO;
        finished += states[i] == CHECK_PASS || states[i] == CHECK_FAIL || states[i] == CHECK_INFO;
    }
    if (count == 0)
    {
        snprintf(label, capacity, "%s", complete ? "None listed" : "Waiting");
        return CHECK_WAIT;
    }
    if (finished < count)
    {
        enum CheckState state = finished || states[0] == CHECK_RUNNING ? CHECK_RUNNING : CHECK_WAIT;
        snprintf(label, capacity, state == CHECK_RUNNING ? "Checking %u/%u" : "Waiting", finished, count);
        return state;
    }
    if (not_tested == count)
    {
        snprintf(label, capacity, "Not tested");
        return CHECK_INFO;
    }
    snprintf(label, capacity, "%u/%u", passed, count);
    return failed || not_tested ? CHECK_FAIL : CHECK_PASS;
}
/* A summary row under the protocol tiles: name, source, then the summary on the right */
static void summary_row(uint32_t *p, int y, const char *name, const char *source,
                        const char *label, enum CheckState state)
{
    card(p, 28, y, 904, 38, panel);
    text(p, 44, y + 9, name, white, 18);
    text(p, 270, y + 9, source, muted, 18);
    int label_left = 916 - check_font_width(label, 18);
    mark(p, label_left - 30, y + 13, state);
    text(p, label_left, y + 9, label, tone(state), 18);
}
void check_draw(uint32_t *p, const CheckService *s, int page, unsigned scroll, int busy,
                const char *notice)
{
    char line[256];
    rect(p, 0, 0, 960, 544, bg);
    text(p, 28, 17, "Connection test", white, 32);
    text(p, 30, 58, "BrowserLeaks / sceHttp", muted, 17);
    const char *provider_status = s->vitals_enabled < 0 ? "checking..."
                                  : s->vitals_enabled   ? "enabled"
                                                        : "not enabled";
    enum CheckState provider_style = s->vitals_enabled < 0 ? CHECK_WAIT
                                     : s->vitals_enabled   ? CHECK_PASS
                                                           : CHECK_FAIL;
    int label_width = check_font_width("vitals:", 20);
    int status_width = check_font_width(provider_status, 20);
    int status_box_width = 36 + label_width + 14 + 18 + 12 + status_width;
    int status_left = 932 - status_box_width;
    int icon_left = status_left + 18 + label_width + 14;
    card(p, status_left, 27, status_box_width, 42, panel);
    text(p, status_left + 18, 34, "vitals:", muted, 20);
    mark(p, icon_left, 39, provider_style);
    text(p, icon_left + 30, 34, provider_status, tone(provider_style), 20);
    for (unsigned col = 0; col < 4; ++col)
    {
        unsigned v = 3 - col;
        int left = 28 + (int)col * 232;
        const CheckResult *r = &s->protocols[v];
        card(p, left, 97, 208, 88, panel);
        snprintf(line, sizeof(line), "TLS 1.%u", v);
        text(p, left + 16, 109, line, white, 24);
        CheckProtocolDisplay display = check_protocol_display(v, r);
        mark(p, left + 170, 119, display.style);
        text(p, left + 16, 151, display.label, tone(display.style), 20);
        if (display.qualifier)
        {
            int x = left + 192 - check_font_width(display.qualifier, 16);
            text(p, x, 156, display.qualifier, muted, 16);
        }
    }
    enum CheckState states[CHECK_REDIRECT_MAX > CHECK_BADSSL_COUNT ? CHECK_REDIRECT_MAX : CHECK_BADSSL_COUNT];
    char summary[48];
    for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i)
        states[i] = s->badssl[i].state;
    enum CheckState state = summarize(states, CHECK_BADSSL_COUNT, s->complete, summary, sizeof(summary));
    summary_row(p, 193, "Certificate checks", "badssl.com", summary, state);
    for (unsigned i = 0; i < s->redirect_count; ++i)
        states[i] = s->redirects[i].result.state;
    state = summarize(states, s->redirect_count, s->complete, summary, sizeof(summary));
    summary_row(p, 237, "Redirections", "ux0:data/vitals/redirects.txt", summary, state);
    text(p, 28, 283, "TLS REPORT", muted, 14);
    if (s->connection.state == CHECK_PASS)
    {
        text(p, 28, 302, s->handshake.cipher.name, white, 21);
        snprintf(line, sizeof(line), "%s   /   %s   /   0x%04X", s->handshake.version.name,
                 s->handshake.group.name[0] ? s->handshake.group.name : "Key exchange not reported",
                 s->handshake.cipher.id);
        text(p, 28, 330, line, muted, 16);
    }
    else
    {
        const char *msg = s->connection.state == CHECK_RUNNING ? "Reading TLS report..."
                          : s->connection.message[0]           ? s->connection.message
                          : s->started                         ? "Waiting for connection checks..."
                                                               : "Ready to test";
        if (!s->started && notice && notice[0])
            msg = notice;
        text(p, 28, 302, msg, s->connection.state == CHECK_FAIL ? red : white, 21);
        if (s->connection.state == CHECK_FAIL)
        {
            snprintf(line, sizeof(line), "HTTP %d / Req 0x%08X / SSL 0x%08X",
                     s->connection.http_code, (unsigned)s->connection.error,
                     (unsigned)s->connection.ssl_error);
            text(p, 28, 330, line, muted, 16);
        }
        else
            text(p, 28, 330, "Certificate verification on / Fresh connections", muted, 16);
    }
    rect(p, 28, 356, 904, 1, panel);
    if (page == 0)
    {
        text(p, 28, 365, "Cipher suites", white, 23);
        if (s->handshake.cipher_count)
            snprintf(line, sizeof(line), "%u offered / Hold arrows or stick",
                     s->handshake.cipher_count);
        else
            snprintf(line, sizeof(line), "Report unavailable");
        text(p, 621, 373, line, muted, 16);
        for (unsigned i = 0; i < CHECK_VISIBLE_CIPHERS && scroll + i < s->handshake.cipher_count;
             ++i)
        {
            const CheckNamed *c = &s->handshake.ciphers[scroll + i];
            int y = 402 + (int)i * 27;
            snprintf(line, sizeof(line), "%02u", scroll + i + 1);
            text(p, 30, y, line, muted, 16);
            snprintf(line, sizeof(line), "0x%04X", c->id);
            text(p, 65, y, line, muted, 16);
            text(p, 138, y - 1, c->name, white, 18);
        }
        if (!s->handshake.cipher_count)
        {
            text(p, 28, 410, "No cipher report received.", muted, 20);
            text(p, 28, 443, "Square opens the request errors and handshake details.", muted, 17);
        }
    }
    else if (page == 1)
    {
        text(p, 28, 365, "Request details", white, 23);
        text(p, 608, 373, "Request / SSL error", muted, 16);
        text(p, 878, 373, "Time", muted, 16);
        for (unsigned i = 0; i < 4; ++i)
        {
            const CheckResult *r = &s->protocols[3 - i];
            int y = 397 + (int)i * 22;
            snprintf(line, sizeof(line), "TLS 1.%u", 3 - i);
            text(p, 30, y, line, white, 18);
            CheckProtocolDisplay display = check_protocol_display(3 - i, r);
            check_protocol_detail(3 - i, r, line, sizeof(line));
            check_font_draw(p, 150, y, line, 18, tone(display.detail_style), 590);
            if (r->error || r->ssl_error)
                snprintf(line, sizeof(line), "0x%08X / 0x%08X", (unsigned)r->error,
                         (unsigned)r->ssl_error);
            else
                snprintf(line, sizeof(line), "%s", r->state == CHECK_PASS ? "OK" : "-");
            text(p, 608, y + 2, line, muted, 16);
            if (r->elapsed_ms)
                snprintf(line, sizeof(line), "%u ms", r->elapsed_ms + r->retry.elapsed_ms);
            else
                snprintf(line, sizeof(line), "-");
            text(p, 856, y + 2, line, muted, 16);
        }
    }
    else if (page == 3)
    {
        text(p, 28, 365, "Certificate checks", white, 23);
        snprintf(line, sizeof(line), "%u hosts / Hold arrows or stick", CHECK_BADSSL_COUNT);
        text(p, 621, 373, line, muted, 16);
        /* The host, what it tests and whether it should load, then what it gave */
        for (unsigned i = 0; i < CHECK_VISIBLE_REDIRECTS && scroll + i < CHECK_BADSSL_COUNT; ++i)
        {
            const CheckBadssl *test = check_badssl(scroll + i);
            const CheckResult *r = &s->badssl[scroll + i];
            int y = 400 + (int)i * 21;
            snprintf(line, sizeof(line), "%s: %s, should %s", test->host, test->label,
                     test->refuse ? "be refused" : "load");
            check_font_draw(p, 30, y, line, 16, white, 530);
            snprintf(line, sizeof(line), "%s",
                     r->message[0] ? r->message : r->state == CHECK_RUNNING ? "Testing..."
                                                                            : "Waiting");
            check_font_draw(p, 545, y, line, 16, tone(r->state), 840);
            if (r->elapsed_ms)
                snprintf(line, sizeof(line), "%u ms", r->elapsed_ms);
            else
                snprintf(line, sizeof(line), "-");
            text(p, 856, y, line, muted, 16);
        }
    }
    else if (page == 4)
    {
        text(p, 28, 365, "Host redirects", white, 23);
        if (s->redirect_count == 0)
            text(p, 28, 410, "No redirects listed in ux0:data/vitals/redirects.txt.", muted, 20);
        else
        {
            snprintf(line, sizeof(line), "%u listed / Hold arrows or stick", s->redirect_count);
            text(p, 621, 373, line, muted, 16);
        }
        /* Old host -> new host, then what requesting the old host through vitals gave */
        for (unsigned i = 0; i < CHECK_VISIBLE_REDIRECTS && scroll + i < s->redirect_count; ++i)
        {
            const CheckRedirect *redirect = &s->redirects[scroll + i];
            const CheckResult *r = &redirect->result;
            int y = 400 + (int)i * 21;
            snprintf(line, sizeof(line), "%s -> %s", redirect->from, redirect->to);
            check_font_draw(p, 30, y, line, 16, white, 530);
            snprintf(line, sizeof(line), "%s",
                     r->message[0] ? r->message : r->state == CHECK_RUNNING ? "Testing..."
                                                                            : "Waiting");
            check_font_draw(p, 545, y, line, 16, tone(r->state), 840);
            if (r->elapsed_ms)
                snprintf(line, sizeof(line), "%u ms", r->elapsed_ms);
            else
                snprintf(line, sizeof(line), "-");
            text(p, 856, y, line, muted, 16);
        }
    }
    else
    {
        text(p, 28, 365, "Handshake details", white, 23);
        snprintf(line, sizeof(line), "Signature   %s",
                 s->handshake.signature.name[0] ? s->handshake.signature.name : "Not reported");
        text(p, 28, 397, line, white, 18);
        snprintf(line, sizeof(line), "ALPN offered   %s",
                 s->handshake.alpn[0] ? s->handshake.alpn : "Not reported");
        text(p, 28, 421, line, white, 18);
        snprintf(line, sizeof(line), "JA3   %s",
                 s->handshake.ja3[0] ? s->handshake.ja3 : "Not reported");
        text(p, 28, 445, line, muted, 17);
        snprintf(line, sizeof(line), "JA4   %s",
                 s->handshake.ja4[0] ? s->handshake.ja4 : "Not reported");
        text(p, 28, 469, line, muted, 17);
        if (s->handshake.valid)
            snprintf(line, sizeof(line),
                     "%u offered groups   /   %u extensions   /   Full lists saved in the report",
                     s->handshake.group_count, s->handshake.extension_count);
        else
            snprintf(line, sizeof(line), "No handshake report received.");
        text(p, 28, 492, line, muted, 13);
    }
    /* Which detail page this is, out of how many Square goes through */
    snprintf(line, sizeof(line), "Details %d/%d", page + 1, CHECK_PAGE_COUNT);
    /* A finished run that wasn't cancelled can have its log saved, once */
    const int saveable = !busy && s->started && s->complete && !s->interrupted;
    const char *save_label = s->report_saved > 0   ? "Log saved to ux0:data/vitals/"
                             : s->report_saved < 0 ? "Save failed, retry"
                                                   : "Save log";
    const AppHint hints[] = {
        busy ? (AppHint){APP_GLYPH_TRIANGLE, APP_GLYPH_NONE, "Cancel"}
             : (AppHint){APP_GLYPH_CONFIRM, APP_GLYPH_NONE, "Retry"},
        {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Scroll"},
        {APP_GLYPH_SQUARE, APP_GLYPH_NONE, line},
        {APP_GLYPH_BACK, APP_GLYPH_NONE, "Back"},
        {APP_GLYPH_START, APP_GLYPH_NONE, save_label},
    };
    footer(p, hints, sizeof(hints) / sizeof(hints[0]) - (saveable ? 0u : 1u));
}

/* The status card in the top right corner: "<label> <mark> <status>" */
/* style picks the icon; color draws it and the status */
static void status_card(uint32_t *p, const char *label, const char *status, enum CheckState style,
                        uint32_t color)
{
    int label_width = check_font_width(label, 20);
    int status_width = check_font_width(status, 20);
    int box_width = 36 + label_width + 14 + 18 + 12 + status_width;
    int left = 932 - box_width;
    int icon_left = left + 18 + label_width + 14;
    card(p, left, 27, box_width, 42, panel);
    text(p, left + 18, 34, label, muted, 20);
    mark_colored(p, icon_left, 39, style, color);
    text(p, icon_left + 30, 34, status, color, 20);
}
/* outdated: a different version's plugin is installed than the one this app carries;
 * installed_version is its release number, empty when unknown */
/* latest_release: a newer published release than this app, shown next to its version */
static void header(uint32_t *p, int installed, int outdated, const char *installed_version,
                   const char *debug_output, const char *latest_release)
{
    char line[64];
    rect(p, 0, 0, 960, 544, bg);
    text(p, 28, 17, "vitals", white, 32);
    snprintf(line, sizeof(line), "Version %s", VITALS_VERSION);
    text(p, 30, 58, line, muted, 17);
    if (latest_release != NULL)
    {
        int left = 30 + check_font_width(line, 17);
        snprintf(line, sizeof(line), "  -  %s available on GitHub / GitLab", latest_release);
        text(p, left, 58, line, amber, 17);
    }
    char status[48];
    int known = installed_version != NULL && installed_version[0] != '\0';
    if (outdated && known && strcmp(installed_version, VITALS_VERSION) != 0)
        snprintf(status, sizeof(status), "%s -> %s", installed_version, VITALS_VERSION);
    else if (outdated)
        snprintf(status, sizeof(status), known ? "%s, other build" : "update available", installed_version);
    else if (installed && debug_output != NULL)
        snprintf(status, sizeof(status), "%s, %s debug", known ? installed_version : "installed", debug_output);
    else if (installed)
        snprintf(status, sizeof(status), "%s", known ? installed_version : "installed");
    else
        snprintf(status, sizeof(status), "not installed");
    enum CheckState style = outdated ? CHECK_WARNING : installed ? CHECK_PASS
                                                                 : CHECK_FAIL;
    /* A working debug build keeps its checkmark, in amber so it stands out */
    status_card(p, "vitals:", status, style,
                style == CHECK_PASS && debug_output != NULL ? amber : tone(style));
}
void app_draw_home(uint32_t *p, const AppHome *home)
{
    header(p, home->installed, home->outdated, home->installed_version, home->debug_output, home->latest_release);
    int y = 97;
    if (!home->firmware_supported)
    {
        char line[96];
        card(p, 28, y, 904, 70, panel);
        mark(p, 46, y + 14, CHECK_WARNING);
        snprintf(line, sizeof(line), "Unsupported firmware: %s", home->firmware);
        text(p, 76, y + 8, line, amber, 21);
        text(p, 76, y + 40, "vitals only supports firmware 3.60 and 3.65, so installing is disabled. "
                            "The connection test still works.",
             muted, 16);
        y += 86;
    }
    /* Six items only fit above the credits with shorter cards, and seven with shorter still */
    int compact = home->count > 5, tight = home->count > 6;
    int height = tight ? 46 : compact ? 54 : 62, step = tight ? 52 : compact ? 62 : 72;
    for (unsigned i = 0; i < home->count; ++i)
    {
        int selected = i == home->selected;
        card(p, 28, y, 904, height, selected ? highlight : panel);
        if (selected)
            rect(p, 28, y + 12, 4, height - 24, blue);
        const int label_y = y + (tight ? 2 : compact ? 4 : 7);
        text(p, 48, label_y, home->items[i].label, selected ? white : muted, 21);
        /* A choice reads apart from its label: in blue between arrows, then whether it is the one
         * in use now */
        if (home->items[i].choice != NULL)
        {
            char choice[64];
            snprintf(choice, sizeof(choice), "<  %s  >", home->items[i].choice);
            int x = 48 + check_font_width(home->items[i].label, 21) + 18;
            text(p, x, label_y, choice, selected ? blue : dim_blue, 21);
            if (home->items[i].choice_current)
                text(p, x + check_font_width(choice, 21) + 12, label_y + 4, "(current)", muted, 16);
        }
        text(p, 48, y + (tight ? 25 : compact ? 30 : 37), home->items[i].description, muted, 16);
        y += step;
    }
    /* The main credits from the README, centred above the controls */
    static const char credits[] = "Thanks to devnoname120, SKGleba, Reiko Asakura, Team Molecule and all of VitaSDK contributors";
    text(p, (960 - check_font_width(credits, 15)) / 2, 480, credits, muted, 15);
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
void app_draw_task(uint32_t *p, const AppTask *task)
{
    header(p, task->installed, task->outdated, task->installed_version, task->debug_output, task->latest_release);
    text(p, 28, 97, task->title, white, 23);
    card(p, 28, 135, 904, 306, panel);
    unsigned first = task->count > APP_TASK_VISIBLE_LINES ? task->count - APP_TASK_VISIBLE_LINES : 0;
    for (unsigned i = first; i < task->count; ++i)
        check_font_draw(p, 48, 147 + (int)(i - first) * 24, task->lines[i], 17,
                        i + 1 == task->count && task->state == CHECK_RUNNING ? white : muted, 864);
    mark(p, 30, 467, task->state);
    text(p, 60, 460, task->status, tone(task->state), 21);
    static const AppHint waiting = {APP_GLYPH_NONE, APP_GLYPH_NONE, "Please wait and keep your Vita turned on."};
    static const AppHint back = {APP_GLYPH_BACK, APP_GLYPH_NONE, "Back"};
    footer(p, task->state == CHECK_RUNNING ? &waiting : &back,
           task->state == CHECK_RUNNING || task->state == CHECK_FAIL ? 1u : 0u);
}
void app_draw_changelog(uint32_t *p, const AppChangelog *changelog)
{
    header(p, changelog->installed, changelog->outdated, changelog->installed_version, changelog->debug_output,
           changelog->latest_release);
    text(p, 28, 97, "Changelog", white, 23);
    const int scrolls = changelog->count > APP_CHANGELOG_VISIBLE_LINES;
    if (scrolls)
    {
        /* Where the visible part sits in the whole list */
        char position[48];
        unsigned last = changelog->scroll + APP_CHANGELOG_VISIBLE_LINES;
        snprintf(position, sizeof(position), "Lines %u-%u of %u", changelog->scroll + 1,
                 last < changelog->count ? last : changelog->count, changelog->count);
        text(p, 932 - check_font_width(position, 16), 104, position, muted, 16);
    }
    card(p, 28, 135, 904, 360, panel);
    for (unsigned i = 0; i < APP_CHANGELOG_VISIBLE_LINES && changelog->scroll + i < changelog->count; ++i)
    {
        const ChangelogLine *line = &changelog->lines[changelog->scroll + i];
        const int y = 147 + (int)i * 24;
        switch (line->kind)
        {
        case CHANGELOG_HEADING:
            check_font_draw(p, 48, y - 2, line->text, 20, white, APP_CHANGELOG_WIDTH);
            break;
        case CHANGELOG_ITEM:
            text(p, 54, y, "-", blue, APP_CHANGELOG_TEXT_SIZE);
            /* Then the change's text, level with its continued lines */
            __attribute__((fallthrough));
        case CHANGELOG_CONTINUED:
            check_font_draw(p, 48 + APP_CHANGELOG_WIDTH - APP_CHANGELOG_ITEM_WIDTH, y, line->text,
                            APP_CHANGELOG_TEXT_SIZE, muted, APP_CHANGELOG_ITEM_WIDTH);
            break;
        case CHANGELOG_TEXT:
            check_font_draw(p, 48, y, line->text, APP_CHANGELOG_TEXT_SIZE, muted, APP_CHANGELOG_WIDTH);
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
