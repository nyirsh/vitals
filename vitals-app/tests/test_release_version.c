/* Host test of reading a release number from GitHub's and GitLab's release responses and
 * comparing it with the app's */
#include "release_version.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int tag(const char *json, char *out, size_t size)
{
    return vitals_release_tag(json, strlen(json), out, size);
}

static void test_parse(void)
{
    unsigned major = 99, minor = 99;
    assert(vitals_release_parse("1.2", &major, &minor) == 0 && major == 1 && minor == 2);
    assert(vitals_release_parse("0.9", &major, &minor) == 0 && major == 0 && minor == 9);
    assert(vitals_release_parse("12.34", &major, &minor) == 0 && major == 12 && minor == 34);
    const char *bad[] = {"", "1", "1.", ".1", "v1.2", "1.2.0", "1.2-beta", "01.2", "1.02", "100.0", "1.100",
                         "1,2", " 1.2", "1.2 ", "-1.2", NULL};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(vitals_release_parse(bad[i], &major, &minor) != 0);
}

static void test_tag(void)
{
    char out[16];
    /* GitHub: one object; GitLab: an array of them, newest first */
    assert(tag("{\"url\":\"x\",\"tag_name\":\"1.3\",\"name\":\"vitals 1.3\"}", out, sizeof(out)) == 0 &&
           strcmp(out, "1.3") == 0);
    assert(tag("[{\"name\":\"vitals 1.4\",\"tag_name\" : \"1.4\"},{\"tag_name\":\"1.3\"}]", out, sizeof(out)) == 0 &&
           strcmp(out, "1.4") == 0);
    assert(tag("{\n  \"tag_name\":\n  \"2.0\"\n}", out, sizeof(out)) == 0 && strcmp(out, "2.0") == 0);
    /* A "tag_name" quoted inside the release notes is not the real one */
    assert(tag("{\"body\":\"set \\\"tag_name\\\": \\\"9.9\\\"\",\"tag_name\":\"1.5\"}", out, sizeof(out)) == 0 &&
           strcmp(out, "1.5") == 0);
    /* No release, or tags that are not release numbers */
    const char *bad[] = {"", "{}", "[]", "{\"message\":\"Not Found\"}", "{\"tag_name\":\"v1.3\"}",
                         "{\"tag_name\":\"1.3-beta\"}", "{\"tag_name\":1.3}", "{\"tag_name\":\"1.3",
                         "{\"tag_name\":\"1.3\\\"\"}", "{\"tag_name\":\"123456789012345678\"}", "{\"tag_name\"",
                         NULL};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(vitals_release_tag(bad[i], bad[i] ? strlen(bad[i]) : 0, out, sizeof(out)) != 0);
    /* Only the given length is read */
    const char *longer = "{\"tag_name\":\"1.3\"}";
    assert(vitals_release_tag(longer, strlen(longer) - 3, out, sizeof(out)) != 0);
}

static void test_newer(void)
{
    assert(vitals_release_newer("1.3", "1.2") == 1);
    assert(vitals_release_newer("2.0", "1.9") == 1);
    assert(vitals_release_newer("1.10", "1.9") == 1);
    assert(vitals_release_newer("1.2", "1.2") == 0);
    assert(vitals_release_newer("1.1", "1.2") == 0);
    assert(vitals_release_newer("0.9", "1.0") == 0);
    assert(vitals_release_newer("v1.3", "1.2") < 0 && vitals_release_newer("1.3", "dev") < 0);
}

int main(void)
{
    test_parse();
    test_tag();
    test_newer();
    puts("release version: numbers, GitHub and GitLab responses, comparisons PASS");
    return 0;
}
