#ifndef VITALS_APP_MODULE_VERSION_H
#define VITALS_APP_MODULE_VERSION_H

/* Reads the version in a module's header (its SceModuleInfo) from the module file, a SELF as
 * vita-make-fself writes it, compressed or not; every vitals module carries the release number
 * from VERSION there
 * Returns 0, or a negative error when the file cannot be read or is not such a module */
int vitals_module_version(const char *path, unsigned *major, unsigned *minor);

#endif
