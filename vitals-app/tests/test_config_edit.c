#include "config_edit.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct
{
    char paths[4][128];
    unsigned count;
} Found;

static void record(void *context, const char *path, size_t length)
{
    Found *found = context;
    assert(found->count < 4 && length < sizeof(found->paths[0]));
    memcpy(found->paths[found->count], path, length);
    found->paths[found->count][length] = '\0';
    ++found->count;
}

static size_t run(const char *config, char *output, size_t *output_size, Found *found)
{
    memset(found, 0, sizeof(*found));
    return vitals_config_remove_plugin(config, strlen(config), "reAuth.skprx", output, output_size, record, found);
}

int main(void)
{
    char output[1024];
    size_t size;
    Found found;

    /* A typical config: reAuth next to other kernel plugins; everything else stays byte for byte */
    const char *config =
        "# taiHEN config\r\n"
        "*KERNEL\r\n"
        "ur0:tai/nonpdrm.skprx\r\n"
        "ur0:tai/reAuth.skprx\r\n"
        "# VITALS\n"
        "*KERNEL\n"
        "ur0:tai/vitals.skprx\n"
        "\n"
        "*main\n"
        "ur0:tai/henkaku.suprx\n";
    const char *expected =
        "# taiHEN config\r\n"
        "*KERNEL\r\n"
        "ur0:tai/nonpdrm.skprx\r\n"
        "# VITALS\n"
        "*KERNEL\n"
        "ur0:tai/vitals.skprx\n"
        "\n"
        "*main\n"
        "ur0:tai/henkaku.suprx\n";
    assert(run(config, output, &size, &found) == 1);
    assert(strcmp(output, expected) == 0 && size == strlen(expected));
    assert(found.count == 1 && strcmp(found.paths[0], "ur0:tai/reAuth.skprx") == 0);

    /* Any location and case, surrounding spaces, a last line without '\n', several entries */
    config = "*KERNEL\n  ux0:tai/REAUTH.SKPRX \nur0:tai/plugins/reauth.skprx";
    assert(run(config, output, &size, &found) == 2);
    assert(strcmp(output, "*KERNEL\n") == 0);
    assert(found.count == 2 && strcmp(found.paths[0], "ux0:tai/REAUTH.SKPRX") == 0 &&
           strcmp(found.paths[1], "ur0:tai/plugins/reauth.skprx") == 0);
    config = "*KERNEL\nur0:reAuth.skprx\n";
    assert(run(config, output, &size, &found) == 1 && strcmp(found.paths[0], "ur0:reAuth.skprx") == 0);

    /* Kept: comments and sections naming it, other plugins with similar names */
    config =
        "# ur0:tai/reAuth.skprx disabled\n"
        "*reAuth.skprx\n"
        "ur0:tai/reAuth.skprx.bak\n"
        "ur0:tai/notreAuth.skprx\n"
        "ur0:tai/reAuth.suprx\n";
    assert(run(config, output, &size, &found) == 0);
    assert(strcmp(output, config) == 0 && size == strlen(config) && found.count == 0);

    /* Empty input, and no callback */
    assert(run("", output, &size, &found) == 0 && size == 0 && output[0] == '\0');
    config = "*KERNEL\nur0:tai/reAuth.skprx\n";
    assert(vitals_config_remove_plugin(config, strlen(config), "reAuth.skprx", output, &size, NULL, NULL) == 1);
    assert(strcmp(output, "*KERNEL\n") == 0);

    /* A plugin listed in its section: in its own block, or moved into another one, repeated
     * headers included, in any case, with spaces and Windows line endings, or as the last line */
    static const char path[] = "ur0:tai/vitals.skprx";
#define HAS(text) vitals_config_has_plugin(text, strlen(text), "*KERNEL", path)
    assert(HAS("# VITALS\n*KERNEL\nur0:tai/vitals.skprx\n\n*main\nur0:tai/henkaku.suprx\n"));
    assert(HAS("*main\nur0:tai/henkaku.suprx\n*KERNEL\nur0:tai/nonpdrm.skprx\nur0:tai/vitals.skprx\n"));
    assert(HAS("*KERNEL\nur0:tai/a.skprx\n*main\nur0:tai/b.suprx\n*KERNEL\nur0:tai/vitals.skprx\n"));
    assert(HAS("  *kernel \r\n\r\n # a comment\r\n  UR0:TAI/Vitals.SKPRX  \r\n"));
    assert(HAS("*KERNEL\nur0:tai/vitals.skprx"));
    /* Not listed: commented out, in another section, before any header, under another path, or a
     * file whose name only starts the same */
    assert(!HAS("*KERNEL\n# ur0:tai/vitals.skprx\n"));
    assert(!HAS("*KERNEL\n#ur0:tai/vitals.skprx\n"));
    assert(!HAS("*main\nur0:tai/vitals.skprx\n"));
    assert(!HAS("*KERNEL\nur0:tai/a.skprx\n*NPXS10015\nur0:tai/vitals.skprx\n"));
    assert(!HAS("ur0:tai/vitals.skprx\n*KERNEL\n"));
    assert(!HAS("*KERNEL\nux0:tai/vitals.skprx\n"));
    assert(!HAS("*KERNEL\nur0:tai/vitals.skprx.bak\nur0:tai/old_vitals.skprx\n"));
    assert(!HAS("*KERNELS\nur0:tai/vitals.skprx\n"));
    assert(!HAS(""));
#undef HAS
    /* Only the given size is read */
    static const char cut[] = "*KERNEL\nur0:tai/vitals.skprxEXTRA";
    assert(vitals_config_has_plugin(cut, sizeof(cut) - 1 - 5, "*KERNEL", path));
    assert(!vitals_config_has_plugin(cut, sizeof(cut) - 1 - 6, "*KERNEL", path));

    /* Where a plugin is listed: its own block is told first, then the first line of the first
     * section, then the last line of the last one */
    static const char block[] = "# VITALS\n*KERNEL\nur0:tai/vitals.skprx\n\n";
#define PLACE(text) vitals_config_plugin_place(text, strlen(text), block, "*KERNEL", path)
    assert(PLACE("*main\nur0:tai/henkaku.suprx\n") == VITALS_CONFIG_NOT_LISTED);
    assert(PLACE("# VITALS\n*KERNEL\nur0:tai/vitals.skprx\n\n*KERNEL\nur0:tai/a.skprx\n") == VITALS_CONFIG_BLOCK);
    assert(PLACE("*KERNEL\n# first\n\n ur0:tai/vitals.skprx\nur0:tai/a.skprx\n") == VITALS_CONFIG_FIRST);
    assert(PLACE("*KERNEL\nur0:tai/vitals.skprx\n") == VITALS_CONFIG_FIRST);
    assert(PLACE("*KERNEL\nur0:tai/a.skprx\nur0:tai/vitals.skprx\n# done\n*main\nx\n") == VITALS_CONFIG_LAST);
    assert(PLACE("*KERNEL\nur0:tai/a.skprx\n*main\nx\n*KERNEL\nur0:tai/b.skprx\nur0:tai/vitals.skprx\n") ==
           VITALS_CONFIG_LAST);
    assert(PLACE("*KERNEL\nur0:tai/a.skprx\nur0:tai/vitals.skprx\nur0:tai/b.skprx\n") == VITALS_CONFIG_ELSEWHERE);
    /* The last line of a section that isn't the last one is somewhere else */
    assert(PLACE("*KERNEL\nur0:tai/a.skprx\nur0:tai/vitals.skprx\n*KERNEL\nur0:tai/b.skprx\n") ==
           VITALS_CONFIG_ELSEWHERE);
#undef PLACE

    /* Adding a line: first right under the first header, or after the last plugin of the last
     * section (or its header), ending like the line before it; the rest is kept exactly */
    static const char sections[] = "# taiHEN\r\n*KERNEL\r\nur0:tai/a.skprx\r\n# note\r\n\r\n*main\nx\n"
                                   "*KERNEL\nur0:tai/b.skprx\n\n";
    char added[1024];
    size_t added_size = 0;
    assert(vitals_config_insert_plugin(sections, strlen(sections), "*KERNEL", path, 0, added, &added_size) == 0);
    assert(strcmp(added, "# taiHEN\r\n*KERNEL\r\nur0:tai/vitals.skprx\r\nur0:tai/a.skprx\r\n# note\r\n\r\n*main\nx\n"
                         "*KERNEL\nur0:tai/b.skprx\n\n") == 0 && added_size == strlen(added));
    assert(vitals_config_insert_plugin(sections, strlen(sections), "*KERNEL", path, 1, added, &added_size) == 0);
    assert(strcmp(added, "# taiHEN\r\n*KERNEL\r\nur0:tai/a.skprx\r\n# note\r\n\r\n*main\nx\n"
                         "*KERNEL\nur0:tai/b.skprx\nur0:tai/vitals.skprx\n\n") == 0);
    /* An empty section gets it right under its header; a last line without a line break gets one */
    static const char empty[] = "*KERNEL\n# nothing yet\n*main\nx\n";
    assert(vitals_config_insert_plugin(empty, strlen(empty), "*KERNEL", path, 1, added, &added_size) == 0);
    assert(strcmp(added, "*KERNEL\nur0:tai/vitals.skprx\n# nothing yet\n*main\nx\n") == 0);
    static const char unterminated[] = "*KERNEL\nur0:tai/a.skprx";
    assert(vitals_config_insert_plugin(unterminated, strlen(unterminated), "*KERNEL", path, 1, added, &added_size) == 0);
    assert(strcmp(added, "*KERNEL\nur0:tai/a.skprx\nur0:tai/vitals.skprx\n") == 0);
    static const char header_only[] = "*KERNEL";
    assert(vitals_config_insert_plugin(header_only, strlen(header_only), "*KERNEL", path, 0, added, &added_size) == 0);
    assert(strcmp(added, "*KERNEL\nur0:tai/vitals.skprx\n") == 0);
    /* Without such a section nothing is written */
    static const char no_kernel[] = "*main\nx\n";
    assert(vitals_config_insert_plugin(no_kernel, strlen(no_kernel), "*KERNEL", path, 0, added, &added_size) == -1);
    assert(vitals_config_insert_plugin(no_kernel, strlen(no_kernel), "*KERNEL", path, 1, added, &added_size) == -1);
    /* What was added is found where it was put */
    assert(vitals_config_insert_plugin(sections, strlen(sections), "*KERNEL", path, 0, added, &added_size) == 0);
    assert(vitals_config_plugin_place(added, added_size, block, "*KERNEL", path) == VITALS_CONFIG_FIRST);
    assert(vitals_config_insert_plugin(sections, strlen(sections), "*KERNEL", path, 1, added, &added_size) == 0);
    assert(vitals_config_plugin_place(added, added_size, block, "*KERNEL", path) == VITALS_CONFIG_LAST);
    puts("config edit: plugin lines removed by file name; sections, comments and line endings kept PASS");
    return 0;
}
