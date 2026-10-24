#ifndef VITALS_APP_CHANGELOG_H
#define VITALS_APP_CHANGELOG_H

#include <stddef.h>

/* CHANGELOG.md laid out as screen lines: "## " lines are a version's heading, "- " lines a change
 * (wrapped onto as many lines as it needs), and any other text a plain line; the "# " title is
 * left out, and so are blank lines, except one before each heading */

#define VITALS_CHANGELOG_LINE_SIZE 160u

typedef enum
{
    CHANGELOG_HEADING,
    /* The first line of a change, drawn after a bullet */
    CHANGELOG_ITEM,
    /* The lines a change wraps onto, drawn level with the first one */
    CHANGELOG_CONTINUED,
    CHANGELOG_TEXT,
    CHANGELOG_BLANK,
} ChangelogKind;

typedef struct
{
    ChangelogKind kind;
    char text[VITALS_CHANGELOG_LINE_SIZE];
} ChangelogLine;

/* How wide text is drawn, in pixels */
typedef int (*ChangelogMeasure)(const char *text);

/* Lays out text (length bytes) into at most capacity lines: plain lines no wider than width, and
 * changes no wider than item_width; a word too wide for a line of its own is split. Returns the
 * number of lines, all of them when they fit and the first capacity otherwise */
size_t vitals_changelog_layout(const char *text, size_t length, ChangelogMeasure measure, int width,
                               int item_width, ChangelogLine *lines, size_t capacity);

#endif
