/* The changelog's layout: headings, changes wrapped between words, plain lines, blank lines before
 * headings, overlong words and the line limit; and the CHANGELOG.md the app carries */
#include "changelog.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Every byte is 10 pixels wide, except UTF-8 continuation bytes, so a character counts once */
static int measure(const char *text)
{
    int width = 0;
    for (; *text != '\0'; ++text)
        if (((unsigned char)*text & 0xc0u) != 0x80u)
            width += 10;
    return width;
}

static ChangelogLine lines[64];

static size_t layout(const char *text, int width, int item_width)
{
    memset(lines, 0x5a, sizeof(lines));
    return vitals_changelog_layout(text, strlen(text), measure, width, item_width, lines, 64);
}

static void expect(size_t i, ChangelogKind kind, const char *text)
{
    assert(lines[i].kind == kind);
    if (strcmp(lines[i].text, text) != 0)
    {
        fprintf(stderr, "line %zu: \"%s\", expected \"%s\"\n", i, lines[i].text, text);
        assert(0);
    }
}

int main(void)
{
    /* The title is left out; each heading after the first is set apart by a blank line; changes
     * keep their order; Windows line endings and surrounding spaces are dropped */
    const char *text = "# Changelog\r\n"
                       "\r\n"
                       "## 1.1 (2026-10-22)\r\n"
                       "\r\n"
                       "- Second\r\n"
                       "  - Third  \r\n"
                       "## 1.0 (2026-10-21)\n"
                       "- First release";
    assert(layout(text, 400, 380) == 6);
    expect(0, CHANGELOG_HEADING, "1.1 (2026-10-22)");
    expect(1, CHANGELOG_ITEM, "Second");
    expect(2, CHANGELOG_ITEM, "Third");
    expect(3, CHANGELOG_BLANK, "");
    expect(4, CHANGELOG_HEADING, "1.0 (2026-10-21)");
    expect(5, CHANGELOG_ITEM, "First release");

    /* Plain text stays, and a heading after it is set apart too */
    assert(layout("Every release, newest first.\n## 1.0\n- First\n", 400, 380) == 4);
    expect(0, CHANGELOG_TEXT, "Every release, newest first.");
    expect(1, CHANGELOG_BLANK, "");
    expect(2, CHANGELOG_HEADING, "1.0");

    /* A change wraps between words onto continued lines, each no wider than the change's width;
     * plain text uses the wider one */
    assert(layout("- one two three four five six", 120, 100) == 3);
    expect(0, CHANGELOG_ITEM, "one two");
    expect(1, CHANGELOG_CONTINUED, "three four");
    expect(2, CHANGELOG_CONTINUED, "five six");
    assert(layout("one two three four five six", 140, 100) == 2);
    expect(0, CHANGELOG_TEXT, "one two three");
    expect(1, CHANGELOG_TEXT, "four five six");
    /* Several spaces between words collapse at a break */
    assert(layout("- aaaa    bbbb", 60, 60) == 2);
    expect(0, CHANGELOG_ITEM, "aaaa");
    expect(1, CHANGELOG_CONTINUED, "bbbb");

    /* A word wider than a line is split, never inside a UTF-8 character */
    assert(layout("- ux0:data/vitals/custom-certs.pem", 100, 100) == 4);
    expect(0, CHANGELOG_ITEM, "ux0:data/v");
    expect(1, CHANGELOG_CONTINUED, "itals/cust");
    expect(2, CHANGELOG_CONTINUED, "om-certs.p");
    expect(3, CHANGELOG_CONTINUED, "em");
    assert(layout("- \xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", 30, 30) == 2);
    expect(0, CHANGELOG_ITEM, "\xc3\xa9\xc3\xa9\xc3\xa9");
    expect(1, CHANGELOG_CONTINUED, "\xc3\xa9");

    /* Markdown's escapes are dropped: a backslash before punctuation shows only the punctuation */
    assert(layout("## 1.4 \\(soon\\) v\\4\n- under \\*KERNEL\\_x\\\\ a\\b c\\", 400, 380) == 2);
    expect(0, CHANGELOG_HEADING, "1.4 (soon) v\\4");
    expect(1, CHANGELOG_ITEM, "under *KERNEL_x\\ a\\b c\\");

    /* Only the lines that fit are filled, and the count says so */
    char many[1024] = "";
    for (int i = 0; i < 80; ++i)
        strcat(many, "- x\n");
    assert(vitals_changelog_layout(many, strlen(many), measure, 400, 380, lines, 64) == 64);
    assert(vitals_changelog_layout(many, strlen(many), measure, 400, 380, lines, 0) == 0);
    /* Nothing to lay out */
    assert(layout("", 400, 380) == 0 && layout("\n\n# Changelog\n", 400, 380) == 0);
    assert(vitals_changelog_layout(NULL, 3, measure, 400, 380, lines, 64) == 0);
    assert(vitals_changelog_layout("abc", 3, NULL, 400, 380, lines, 64) == 0);

    /* The changelog the app carries lays out, at the screen's width, into fewer lines than the app
     * keeps, and its first heading is this version's */
    FILE *file = fopen(VITALS_CHANGELOG_FILE, "rb");
    assert(file != NULL);
    static char contents[64 * 1024];
    size_t length = fread(contents, 1, sizeof(contents), file);
    fclose(file);
    assert(length > 0 && length < sizeof(contents));
    static ChangelogLine screen[512];
    size_t count = vitals_changelog_layout(contents, length, measure, 864, 840, screen, 512);
    assert(count > 0 && count < 512);
    size_t heading = 0;
    while (heading < count && screen[heading].kind != CHANGELOG_HEADING)
        ++heading;
    assert(heading < count);
    /* "1.4", or "1.4 (2026-10-24)" once released */
    const size_t version_length = strlen(VITALS_VERSION);
    assert(strncmp(screen[heading].text, VITALS_VERSION, version_length) == 0);
    assert(screen[heading].text[version_length] == '\0' || screen[heading].text[version_length] == ' ');
    for (size_t i = 0; i < count; ++i)
        assert(measure(screen[i].text) <= (screen[i].kind == CHANGELOG_ITEM || screen[i].kind == CHANGELOG_CONTINUED
                                               ? 840 : 864));

    puts("changelog: headings, wrapped changes, plain lines, split words, line limit, the bundled file PASS");
    return 0;
}
