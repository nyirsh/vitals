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

/* One line of a config: [start, end) without its '\n', next the start of the line after it, and
 * [first, last) the line without the spaces around it */
typedef struct
{
    size_t start, end, next, first, last;
} ConfigLine;

static void read_line(const char *config, size_t size, size_t at, ConfigLine *line)
{
    size_t end = at;
    while (end < size && config[end] != '\n')
        ++end;
    size_t first, last;
    trim(config + at, end - at, &first, &last);
    *line = (ConfigLine){at, end, end < size ? end + 1 : end, at + first, at + last};
}

static int is_header(const char *config, const ConfigLine *line)
{
    return line->first < line->last && config[line->first] == '*';
}

static int is_header_named(const char *config, const ConfigLine *line, const char *section)
{
    return is_header(config, line) && same_text(config + line->first, line->last - line->first, section);
}

/* A line naming a plugin: neither blank, a comment nor a header */
static int is_plugin_line(const char *config, const ConfigLine *line)
{
    return line->first < line->last && config[line->first] != '#' && config[line->first] != '*';
}

/* Where the first or the last plugin line of the first or the last section headed section is,
 * as found and *line; found is 0 when there is no such section, 1 when it has no plugin line
 * (line is then its header) and 2 otherwise */
static int find_section_line(const char *config, size_t size, const char *section, int last, ConfigLine *line)
{
    int found = 0, in_section = 0;
    ConfigLine current;

    for (size_t at = 0; at < size; at = current.next)
    {
        read_line(config, size, at, &current);
        if (is_header(config, &current))
        {
            if (found && !last)
                break;
            in_section = is_header_named(config, &current, section);
            if (in_section)
            {
                found = 1;
                *line = current;
            }
        }
        else if (in_section && is_plugin_line(config, &current))
        {
            if (found == 1 || last)
            {
                found = 2;
                *line = current;
            }
            if (!last)
                break;
        }
    }
    return found;
}

static int contains(const char *config, size_t size, const char *text)
{
    size_t length = 0;
    while (text[length] != '\0')
        ++length;
    for (size_t at = 0; length != 0 && at + length <= size; ++at)
    {
        size_t i = 0;
        while (i < length && config[at + i] == text[i])
            ++i;
        if (i == length)
            return 1;
    }
    return 0;
}

VitalsConfigPlace vitals_config_plugin_place(const char *config, size_t size, const char *block, const char *section,
                                             const char *path)
{
    ConfigLine line;

    if (!vitals_config_has_plugin(config, size, section, path))
        return VITALS_CONFIG_NOT_LISTED;
    if (block != NULL && contains(config, size, block))
        return VITALS_CONFIG_BLOCK;
    if (find_section_line(config, size, section, 0, &line) == 2 &&
        same_text(config + line.first, line.last - line.first, path))
        return VITALS_CONFIG_FIRST;
    if (find_section_line(config, size, section, 1, &line) == 2 &&
        same_text(config + line.first, line.last - line.first, path))
        return VITALS_CONFIG_LAST;
    return VITALS_CONFIG_ELSEWHERE;
}

int vitals_config_insert_plugin(const char *config, size_t size, const char *section, const char *path, int last,
                                char *output, size_t *output_size)
{
    ConfigLine line;
    int found = 0;

    /* First goes right under the first such header; last goes after the last such section's
     * last plugin, or its header */
    if (last)
        found = find_section_line(config, size, section, 1, &line) != 0;
    else
        for (size_t at = 0; at < size && !found; at = line.next)
        {
            read_line(config, size, at, &line);
            found = is_header_named(config, &line, section);
        }
    if (!found)
        return -1;
    const int windows = line.end > line.start && config[line.end - 1] == '\r';
    const char *ending = windows ? "\r\n" : "\n";
    size_t written = 0;
    for (size_t i = 0; i < line.next; ++i)
        output[written++] = config[i];
    /* The line it follows was the last, with no line break of its own */
    if (line.next == line.end)
        for (const char *c = ending; *c != '\0'; ++c)
            output[written++] = *c;
    for (const char *c = path; *c != '\0'; ++c)
        output[written++] = *c;
    for (const char *c = ending; *c != '\0'; ++c)
        output[written++] = *c;
    for (size_t i = line.next; i < size; ++i)
        output[written++] = config[i];
    output[written] = '\0';
    *output_size = written;
    return 0;
}
