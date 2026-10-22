#ifndef VITALS_REDIRECT_LIST_H
#define VITALS_REDIRECT_LIST_H

#include "vitals/host_map.h"
#include "vitals/redirects.h"

/* Reading the host redirect list one line at a time, in pieces of VITALS_REDIRECTS_CHUNK bytes,
 * so its size does not matter; shared by the HTTP provider and vitals-reauth */

/* Longer than any valid pair (two 253-character names and a space between them) */
#define VITALS_REDIRECT_LIST_LINE_LIMIT 512u
/* The working memory the caller lends the reader: one piece and one line */
#define VITALS_REDIRECT_LIST_WORK_SIZE (VITALS_REDIRECTS_CHUNK + VITALS_REDIRECT_LIST_LINE_LIMIT)

#ifdef __cplusplus
extern "C" {
#endif

/* Reads up to size bytes of the list from offset, as vitals_redirects_read does */
typedef int (*VitalsRedirectListRead)(unsigned int offset, void *buffer, unsigned int size);
/* Called for each valid pair, which points into the reader's line buffer and must be copied;
 * returns nonzero to stop reading (the list is full, or the caller failed) */
typedef int (*VitalsRedirectListKeep)(void *context, const VitalsHostRule *rule);

/* Reads the whole list, or until keep asks to stop; work holds VITALS_REDIRECT_LIST_WORK_SIZE
 * bytes. A line longer than the line limit is kept only when the cut fell inside a comment
 * Returns 0, or the read error that ended the list early (the pairs before it were passed on) */
int vitals_redirect_list_read(VitalsRedirectListRead read, char *work, VitalsRedirectListKeep keep,
    void *context);

#ifdef __cplusplus
}
#endif

#endif
