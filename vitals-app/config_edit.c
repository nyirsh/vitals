#include "config_edit.h"

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

/* The line without the spaces around it */
static void trim(const char *line, size_t length, size_t *start, size_t *end)
{
    *start = 0;
    *end = length;
    while (*start < *end && is_space(line[*start]))
        ++*start;
    while (*end > *start && is_space(line[*end - 1]))
        --*end;
}

/* 1 when text (length characters) is expected, compared without case */
static int same_text(const char *text, size_t length, const char *expected)
{
    size_t i = 0;
    for (; i < length; ++i)
    {
        if (expected[i] == '\0' || lower(text[i]) != lower(expected[i]))
            return 0;
    }
    return expected[i] == '\0';
}

/* 1 when the line is a plugin path whose file name is name; *path and *length give the path */
static int plugin_line_matches(const char *line, size_t length, const char *name, const char **path,
                               size_t *path_length)
{
    size_t start, end, base, name_length = 0;

    trim(line, length, &start, &end);
    /* Blank lines, comments and section headers such as *KERNEL are never plugins */
    if (start == end || line[start] == '#' || line[start] == '*')
        return 0;
    base = end;
    while (base > start && line[base - 1] != '/' && line[base - 1] != ':')
        --base;
    while (name[name_length] != '\0')
        ++name_length;
    if (end - base != name_length)
        return 0;
    for (size_t i = 0; i < name_length; ++i)
    {
        if (lower(line[base + i]) != lower(name[i]))
            return 0;
    }
    *path = line + start;
    *path_length = end - start;
    return 1;
}

size_t vitals_config_remove_plugin(const char *config, size_t size, const char *name, char *output,
                                   size_t *output_size, VitalsConfigFound found, void *context)
{
    size_t start = 0, written = 0, removed = 0;

    while (start < size)
    {
        size_t end = start;
        const char *path;
        size_t path_length;

        while (end < size && config[end] != '\n')
            ++end;
        /* The line including its '\n', when it has one */
        size_t next = end < size ? end + 1 : end;
        if (plugin_line_matches(config + start, end - start, name, &path, &path_length))
        {
            if (found != NULL)
                found(context, path, path_length);
            ++removed;
        }
        else
        {
            for (size_t i = start; i < next; ++i)
                output[written++] = config[i];
        }
        start = next;
    }
    output[written] = '\0';
    *output_size = written;
    return removed;
}

int vitals_config_has_plugin(const char *config, size_t size, const char *section, const char *path)
{
    size_t start = 0;
    int in_section = 0;

    while (start < size)
    {
        size_t end = start;
        while (end < size && config[end] != '\n')
            ++end;
        size_t first, last;
        trim(config + start, end - start, &first, &last);
        const char *line = config + start + first;
        const size_t length = last - first;
        /* A header starts a section; blank lines and comments change nothing */
        if (length != 0 && line[0] == '*')
            in_section = same_text(line, length, section);
        else if (length != 0 && line[0] != '#' && in_section && same_text(line, length, path))
            return 1;
        start = end < size ? end + 1 : end;
    }
    return 0;
}
