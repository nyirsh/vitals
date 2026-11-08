#ifndef VITALS_MARKER_H
#define VITALS_MARKER_H

/* What vitals' libhttp and libssl carry in their read-only data so the app can tell them from Sony's:
 * they load under Sony's own names and versions (cellHttp_Library, cellSsl_Library 1.1) and from Sony's
 * paths (Cobra maps them), so the app's connection test looks for this in the module its own process
 * loaded (vitals-app/src/check.c), as the Vita's app sees its modules' files. Sony's have none.
 * "vitals-module/<module>/<release>", NUL-ended */
#define VITALS_MARKER_PREFIX "vitals-module/"
#define VITALS_MARKER(module) VITALS_MARKER_PREFIX module "/" VITALS_VERSION

/* In a module's module_start: the marker's address taken, so the linker's --gc-sections keeps it */
#define VITALS_KEEP_MARKER(marker) __asm__ volatile("" : : "r"(marker))

#endif
