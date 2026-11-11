#include "changelog.h"

#include <string.h>

typedef struct
{
    ChangelogLine *lines;
    size_t capacity, count;
} Layout;

static void add(Layout *layout, ChangelogKind kind, const char *text, size_t length)
{
    if (layout->count < layout->capacity)
    {
        ChangelogLine *line = &layout->lines[layout->count];
        if (length >= sizeof(line->text))
            length = sizeof(line->text) - 1;
        line->kind = kind;
        memcpy(line->text, text, length);
        line->text[length] = '\0';
    }
    ++layout->count;
}

/* Markdown escapes punctuation with a backslash ("\\*KERNEL"); the screen shows it plain */
static int escaped_punctuation(char c)
{
    return c != '\0' && strchr("\\`*_{}[]()#+-.!<>|~", c) != NULL;
}

/* Copies a line's text without Markdown's escapes, into unescaped (which holds the line) */
static size_t unescape(const char *text, size_t length, char *unescaped)
{
    size_t written = 0;
    for (size_t i = 0; i < length; ++i)
    {
        if (text[i] == '\\' && i + 1 < length && escaped_punctuation(text[i + 1]))
            ++i;
        unescaped[written++] = text[i];
    }
    return written;
}

/* 1 when text (length bytes) is no wider than width */
static int fits(const char *text, size_t length, ChangelogMeasure measure, int width)
{
    char line[VITALS_CHANGELOG_LINE_SIZE];
    if (length >= sizeof(line))
        return 0;
    memcpy(line, text, length);
    line[length] = '\0';
    return measure(line) <= width;
}

static int continuation_byte(char c)
{
    return ((unsigned char)c & 0xc0u) == 0x80u;
}

/* Adds text (length bytes) as lines no wider than width, breaking between words; the first line
 * is of kind first, the others of kind rest */
static void wrap(Layout *layout, const char *text, size_t length, ChangelogMeasure measure, int width,
                 ChangelogKind first, ChangelogKind rest)
{
    ChangelogKind kind = first;
    size_t at = 0;

    for (;;)
    {
        while (at < length && text[at] == ' ')
            ++at;
        if (at == length)
            return;
        /* As many whole words as fit */
        size_t taken = 0, next = at, cursor = at;
        while (cursor < length)
        {
            size_t word_end = cursor;
            while (word_end < length && text[word_end] != ' ')
                ++word_end;
            if (!fits(text + at, word_end - at, measure, width))
                break;
            taken = word_end - at;
            next = word_end;
            cursor = word_end;
            while (cursor < length && text[cursor] == ' ')
                ++cursor;
        }
        /* A word wider than a whole line is split, never inside a UTF-8 character */
        if (taken == 0)
        {
            size_t end = at + 1;
            while (end < length && continuation_byte(text[end]))
                ++end;
            for (;;)
            {
                size_t longer = end + 1;
                while (longer < length && continuation_byte(text[longer]))
                    ++longer;
                if (end == length || text[end] == ' ' || !fits(text + at, longer - at, measure, width))
                    break;
                end = longer;
            }
            taken = end - at;
            next = end;
        }
        add(layout, kind, text + at, taken);
        kind = rest;
        at = next;
    }
}

size_t vitals_changelog_layout(const char *text, size_t length, ChangelogMeasure measure, int width,
                               int item_width, ChangelogLine *lines, size_t capacity)
{
    Layout layout = {lines, capacity, 0};
    size_t at = 0;

    if (text == NULL || measure == NULL || lines == NULL)
        return 0;
    while (at < length)
    {
        size_t end = at;
        while (end < length && text[end] != '\n')
            ++end;
        size_t first = at, last = end;
        while (first < last && (text[first] == ' ' || text[first] == '\t' || text[first] == '\r'))
            ++first;
        while (last > first && (text[last - 1] == ' ' || text[last - 1] == '\t' || text[last - 1] == '\r'))
            --last;
        /* The line as it shows, without escapes; longer lines than a screen line are cut */
        char shown[4 * VITALS_CHANGELOG_LINE_SIZE];
        const size_t size = unescape(text + first, last - first < sizeof(shown) ? last - first : sizeof(shown), shown);
        const char *line = shown;
        if (size >= 3 && memcmp(line, "## ", 3) == 0)
        {
            /* A version's heading, set apart from what comes before it */
            if (layout.count > 0)
                add(&layout, CHANGELOG_BLANK, "", 0);
            wrap(&layout, line + 3, size - 3, measure, width, CHANGELOG_HEADING, CHANGELOG_HEADING);
        }
        else if (size >= 2 && line[0] == '-' && line[1] == ' ')
            wrap(&layout, line + 2, size - 2, measure, item_width, CHANGELOG_ITEM, CHANGELOG_CONTINUED);
        /* The document's title is the screen's own */
        else if (size != 0 && !(size >= 2 && line[0] == '#' && line[1] == ' '))
            wrap(&layout, line, size, measure, width, CHANGELOG_TEXT, CHANGELOG_TEXT);
        at = end < length ? end + 1 : end;
    }
    return layout.count < capacity ? layout.count : capacity;
}
