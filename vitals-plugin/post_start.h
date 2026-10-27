#ifndef VITALS_POST_START_H
#define VITALS_POST_START_H

#include <psp2kern/types.h>

#define VITALS_PENDING_BROWSER_LIMIT 8u
#define VITALS_PENDING_BROWSER_PATH_SIZE 256u

int vitals_post_start_init(void);
int vitals_post_start_destroy(void);
int vitals_post_start_defer(SceUID pid, SceUID module, const char *path);
int vitals_post_start_complete(SceUID pid, SceUID module, int native_result);

#endif
