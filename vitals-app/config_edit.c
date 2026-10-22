#include "config_edit.h"

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

/* 1 when the line is a plugin path whose file name is name; *path and *length give the path */
static int plugin_line_matches(const char *line, size_t length, const char *name, const char **path,
                               size_t *path_length)
{
    size_t start = 0, end = length, base, name_length = 0;

    while (start < end && is_space(line[start]))
        ++start;
    while (end > start && is_space(line[end - 1]))
        --end;
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
