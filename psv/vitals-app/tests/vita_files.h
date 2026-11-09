#ifndef VITALS_APP_TEST_VITA_FILES_H
#define VITALS_APP_TEST_VITA_FILES_H

/* The Vita's drives (ur0:, ux0:, vs0:, app0:) as folders under one host directory */
void vita_files_root(const char *directory);
/* The host path of a Vita path */
const char *vita_files_path(const char *vita_path);

/* Fault injection: the given rename (counting from 1) fails; 0 for none */
extern int vita_files_fail_rename;
extern int vita_files_renames;
/* Firmware version reported to the installer */
extern unsigned int vita_files_firmware;

#endif
