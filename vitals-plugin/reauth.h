#ifndef VITALS_REAUTH_H
#define VITALS_REAUTH_H

#include <psp2kern/types.h>

/* Loads vitals-reauth.suprx (PSN sign-in host redirect) into the shell after it loads its
 * HTTP library, and into apps after they load the Store library (SceNpCommerce2) */

/* Checks that the module is installed; 1 when redirects can be injected */
int vitals_reauth_init(void);
void vitals_reauth_destroy(void);
/* 1 when loading path (the path the process asked for) into pid should be followed by the
 * redirect module; is_libhttp says whether path is Sony's libhttp */
int vitals_reauth_wanted(SceUID pid, const char *path, int is_libhttp);
/* Loads the module into pid unless it is already there; called once the trigger module has
 * started */
int vitals_reauth_inject(SceUID pid);

#endif
