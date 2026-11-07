#ifndef VITALS_MOCK_CLIB_H
#define VITALS_MOCK_CLIB_H
/* Declared as in VitaSDK, so log lines are format-checked */
int sceClibPrintf(const char *format, ...) __attribute__((format(printf, 1, 2)));
#endif
