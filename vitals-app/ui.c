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
                      highlight = RGB(40, 52, 70);
static const char *confirm_name = "Cross", *back_name = "Circle";
void app_set_circle_confirms(int circle_confirms)
{
    confirm_name = circle_confirms ? "Circle" : "Cross";
    back_name = circle_confirms ? "Cross" : "Circle";
}
const char *app_confirm_name(void) { return confirm_name; }
const char *app_back_name(void) { return back_name; }
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
    const CheckResult *ps = &s->playstation;
    const char *ps_label = ps->state == CHECK_PASS      ? "Connected"
                           : ps->state == CHECK_FAIL    ? "Failed"
                           : ps->state == CHECK_RUNNING ? "Checking..."
                           : ps->state == CHECK_INFO    ? "Not tested"
                                                        : "Waiting";
    card(p, 28, 193, 904, 38, panel);
    text(p, 44, 202, "PlayStation servers", white, 18);
    text(p, 270, 202, "native-vita.np.ac.playstation.net", muted, 18);
    int ps_label_left = 916 - check_font_width(ps_label, 18);
    mark(p, ps_label_left - 30, 206, ps->state);
    text(p, ps_label_left, 202, ps_label, tone(ps->state), 18);

    /* The host redirects in one line: how many passed out of how many are listed */
    unsigned passed = 0, failed = 0, finished = 0, not_tested = 0;
    for (unsigned i = 0; i < s->redirect_count; ++i)
    {
        enum CheckState state = s->redirects[i].result.state;
        passed += state == CHECK_PASS;
        failed += state == CHECK_FAIL;
        not_tested += state == CHECK_INFO;
        finished += state == CHECK_PASS || state == CHECK_FAIL || state == CHECK_INFO;
    }
    char redirect_label[48];
    enum CheckState redirect_state;
    if (s->redirect_count == 0)
    {
        redirect_state = CHECK_WAIT;
        snprintf(redirect_label, sizeof(redirect_label), "%s", s->complete ? "None listed" : "Waiting");
    }
    else if (finished < s->redirect_count)
    {
        redirect_state = finished || s->redirects[0].result.state == CHECK_RUNNING ? CHECK_RUNNING : CHECK_WAIT;
        snprintf(redirect_label, sizeof(redirect_label), redirect_state == CHECK_RUNNING ? "Checking %u/%u" : "Waiting",
                 finished, s->redirect_count);
    }
    else if (not_tested == s->redirect_count)
    {
        redirect_state = CHECK_INFO;
        snprintf(redirect_label, sizeof(redirect_label), "Not tested");
    }
    else
    {
        redirect_state = failed || not_tested ? CHECK_FAIL : CHECK_PASS;
        snprintf(redirect_label, sizeof(redirect_label), "%u/%u", passed, s->redirect_count);
    }
    card(p, 28, 237, 904, 38, panel);
    text(p, 44, 246, "Redirections", white, 18);
    text(p, 270, 246, "ux0:data/vitals/redirects.txt", muted, 18);
    int redirect_label_left = 916 - check_font_width(redirect_label, 18);
    mark(p, redirect_label_left - 30, 250, redirect_state);
    text(p, redirect_label_left, 246, redirect_label, tone(redirect_state), 18);
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
        for (unsigned i = 0; i < 5; ++i)
        {
            const CheckResult *r = i == 4 ? &s->playstation : &s->protocols[3 - i];
            int y = 397 + (int)i * 22;
            if (i == 4)
                snprintf(line, sizeof(line), "PlayStation");
            else
                snprintf(line, sizeof(line), "TLS 1.%u", 3 - i);
            text(p, 30, y, line, white, 18);
            enum CheckState detail_style = r->state;
            if (i == 4)
                snprintf(line, sizeof(line), "%s", r->message[0] ? r->message : ps_label);
            else
            {
                CheckProtocolDisplay display = check_protocol_display(3 - i, r);
                detail_style = display.detail_style;
                check_protocol_detail(3 - i, r, line, sizeof(line));
            }
            check_font_draw(p, 150, y, line, 18, tone(detail_style), 590);
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
                     r->message[0] ? r->message : r->state == CHECK_RUNNING ? "Testing..." : "Waiting");
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
    rect(p, 0, 509, 960, 35, panel);
    if (busy)
        snprintf(line, sizeof(line), "Triangle  Cancel     Hold arrows / stick  Scroll     Square  Details     %s  Back",
                 back_name);
    else
        snprintf(line, sizeof(line), "%s  Retry     Hold arrows / stick  Scroll     Square  Details     %s  Back",
                 confirm_name, back_name);
    text(p, 28, 516, line, white, 16);
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
    enum CheckState style = outdated ? CHECK_WARNING : installed ? CHECK_PASS : CHECK_FAIL;
    /* A working debug build keeps its checkmark, in amber so it stands out */
    status_card(p, "vitals:", status, style,
                style == CHECK_PASS && debug_output != NULL ? amber : tone(style));
}
static void footer(uint32_t *p, const char *hints)
{
    rect(p, 0, 509, 960, 35, panel);
    text(p, 28, 516, hints, white, 16);
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
    /* Six items only fit above the credits with shorter cards */
    int compact = home->count > 5;
    int height = compact ? 54 : 62, step = compact ? 62 : 72;
    for (unsigned i = 0; i < home->count; ++i)
    {
        int selected = i == home->selected;
        card(p, 28, y, 904, height, selected ? highlight : panel);
        if (selected)
            rect(p, 28, y + 12, 4, height - 24, blue);
        text(p, 48, y + (compact ? 4 : 7), home->items[i].label, selected ? white : muted, 21);
        text(p, 48, y + (compact ? 30 : 37), home->items[i].description, muted, 16);
        y += step;
    }
    /* The main credits from the README, centred above the controls */
    static const char credits[] = "Thanks to devnoname120, SKGleba, Reiko Asakura and Team Molecule";
    text(p, (960 - check_font_width(credits, 15)) / 2, 480, credits, muted, 15);
    char hints[96];
    snprintf(hints, sizeof(hints), "Arrows  Choose     %s  Select     %s  Exit", confirm_name, back_name);
    footer(p, home->hints != NULL ? home->hints : hints);
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
    char back[32];
    snprintf(back, sizeof(back), "%s  Back", back_name);
    footer(p, task->state == CHECK_RUNNING ? "Please wait and keep your Vita turned on."
              : task->state == CHECK_FAIL  ? back
                                           : "");
}
