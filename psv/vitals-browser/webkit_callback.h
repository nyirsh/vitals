#ifndef VITALS_WEBKIT_CALLBACK_H
#define VITALS_WEBKIT_CALLBACK_H

#include <stddef.h>
#include <stdint.h>
#include "vitals/firmware_profiles.h"

/* 3.65 reference constants for regression fixtures
 * Runtime uses the profile table */
#define VITALS_WEBKIT_MODULE_NAME "SceWebKit"
#define VITALS_WEBKIT_TEXT_FILESZ ((size_t)0xAF2E9C)
#define VITALS_WEBKIT_TEXT_MEMSZ ((size_t)0xAF2E9C)
/* Original initialized data extent from native module info; the memory dump includes BSS */
#define VITALS_WEBKIT_DATA_FILESZ ((size_t)0xCE34)
#define VITALS_WEBKIT_DATA_MEMSZ ((size_t)0x115C0)
#define VITALS_WEBKIT_CTX_CALLBACK_OFFSET ((size_t)0x16C7BA)
#define VITALS_WEBKIT_REQUEST_VTABLE_OFFSET ((size_t)0xA98064)
#define VITALS_WEBKIT_REQUEST_SIZE ((size_t)0x4E0)

enum VitalsWebKitCallbackRejectReason {
    VITALS_WEBKIT_REJECT_ARGUMENT = 1,
    VITALS_WEBKIT_REJECT_MODULE_LOOKUP,
    VITALS_WEBKIT_REJECT_MODULE_INFO,
    VITALS_WEBKIT_REJECT_MODULE_NAME,
    VITALS_WEBKIT_REJECT_SEGMENT_ADDRESS,
    VITALS_WEBKIT_REJECT_SEGMENT_GEOMETRY,
    VITALS_WEBKIT_REJECT_CALLBACK_ADDRESS,
    VITALS_WEBKIT_REJECT_CALLBACK_SIGNATURE,
    VITALS_WEBKIT_REJECT_USERDATA_INFO,
    VITALS_WEBKIT_REJECT_USERDATA_RANGE,
    VITALS_WEBKIT_REJECT_USERDATA_ACCESS,
    VITALS_WEBKIT_REJECT_VTABLE_RANGE,
    VITALS_WEBKIT_REJECT_VTABLE_VALUE,
    VITALS_WEBKIT_REJECT_MODULE_IDENTITY
};

static const uint8_t vitals_webkit_ctx_callback_signature[] = {
    0x10, 0xB5, 0x08, 0x1C, 0x11, 0x1C, 0xF1,
    0xF2, 0xA8, 0xE5, 0x00, 0x20, 0x10, 0xBD
};

int vitals_webkit_is_default_ctx_callback(const void *callback, const void *userdata);

#endif
