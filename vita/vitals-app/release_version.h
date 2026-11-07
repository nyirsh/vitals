#ifndef VITALS_APP_RELEASE_VERSION_H
#define VITALS_APP_RELEASE_VERSION_H

#include <stddef.h>

/* Release numbers as VERSION writes them: major.minor, each 0 to 99 without leading zeros */

/* Reads text as a release number; 0, or -1 when it is not one ("v1.2", "1.2-beta", "1.2.0") */
int vitals_release_parse(const char *text, unsigned *major, unsigned *minor);
/* Finds the first "tag_name" in a GitHub or GitLab release response (an object or an array of
 * them) and copies its value to tag; 0, or -1 when there is none or it is not a release number */
int vitals_release_tag(const char *json, size_t length, char *tag, size_t size);
/* 1 when candidate is a newer release than current, 0 when it is not, -1 when either is not a
 * release number */
int vitals_release_newer(const char *candidate, const char *current);

#endif
