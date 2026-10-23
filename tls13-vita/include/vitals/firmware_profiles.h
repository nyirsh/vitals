#ifndef VITALS_FIRMWARE_PROFILES_H
#define VITALS_FIRMWARE_PROFILES_H

#include <stddef.h>
#include <stdint.h>

/* SceKernelModulemgr exists in two forms: 3.60 and 3.61 (family 0), and 3.63 and later
 * (family 1); they differ in a few instructions and in the library that exports its functions */
enum {
    VITALS_KERNEL_FAMILY_360,
    VITALS_KERNEL_FAMILY_365,
    VITALS_KERNEL_FAMILY_COUNT
};

typedef struct VitalsKernelProfile {
    uint32_t module_nid;
    size_t text_size, metadata_offset;
    unsigned int family;
} VitalsKernelProfile;

typedef struct VitalsWebKitProfile {
    uint32_t module_nid;
    size_t text_size, data_filesz, data_memsz, metadata_offset;
    size_t callback_offset, vtable_offset;
    const unsigned char *callback_signature;
} VitalsWebKitProfile;

/* vitals supports firmware 3.60 and 3.65 (the installer refuses others)
 * These identify their SceKernelModulemgr and SceWebKit; other firmware is left alone
 * The values come from tls_fixer, which supported a wider range */
static const VitalsKernelProfile vitals_kernel_profiles[] = {
    {0x726c6635, 0xef84, 0xb9d0, VITALS_KERNEL_FAMILY_360}, /* 3.60 */
    {0x781c6f50, 0xf034, 0xba80, VITALS_KERNEL_FAMILY_365}, /* 3.65 */
};

static const unsigned char vitals_webkit_callback_360[] = {
    0x10,0xb5,0x08,0x1c,0x11,0x1c,0xf1,0xf2,0xba,0xe5,0x00,0x20,0x10,0xbd
};
static const unsigned char vitals_webkit_callback_365[] = {
    0x10,0xb5,0x08,0x1c,0x11,0x1c,0xf1,0xf2,0xa8,0xe5,0x00,0x20,0x10,0xbd
};

static const VitalsWebKitProfile vitals_webkit_profiles[] = {
    {0x20163df2,0xaf2ebc,0xce34,0x115c0,0x85fb04,0x16c7b6,0xa98084,vitals_webkit_callback_360}, /* retail 3.60 */
    {0x87f5a440,0xaf2ebc,0xce34,0x115c0,0x85fb04,0x16c7b6,0xa98084,vitals_webkit_callback_360}, /* testkit 3.60 */
    {0x1a29ef0d,0xaf2ebc,0xce34,0x115c0,0x85fb04,0x16c7b6,0xa98084,vitals_webkit_callback_360}, /* devkit 3.60 */
    {0xa33a93f7,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,vitals_webkit_callback_365}, /* retail 3.65 */
    {0xe32c493d,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,vitals_webkit_callback_365}, /* testkit 3.65 */
    {0x8deccd66,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,vitals_webkit_callback_365}, /* devkit 3.65 */
};

static inline uint32_t vitals_profile_u32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
        (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

/* The mapped module-info record remains in RX on hardware
 * Read only inside the native-reported segment; do not add startup module queries */
static inline int vitals_profile_metadata_matches(const unsigned char *text,
    size_t size, size_t offset, const char *name, uint32_t nid) {
    if (text == NULL || offset > size || 0x38u > size - offset) return 0;
    const unsigned char *info = text + offset;
    if (info[31] != 6 || vitals_profile_u32(info + 0x34) != nid) return 0;
    for (size_t i = 0; i < 27; ++i) {
        if (info[4 + i] != (unsigned char)name[i]) return 0;
        if (name[i] == '\0') return 1;
    }
    return 0;
}

static inline const VitalsKernelProfile *vitals_select_kernel_profile(
    const unsigned char *text, size_t size) {
    for (size_t i = 0; i < sizeof(vitals_kernel_profiles) / sizeof(vitals_kernel_profiles[0]); ++i) {
        const VitalsKernelProfile *profile = &vitals_kernel_profiles[i];
        if (size == profile->text_size && vitals_profile_metadata_matches(text, size,
                profile->metadata_offset, "SceKernelModulemgr", profile->module_nid)) return profile;
    }
    return NULL;
}

static inline const VitalsWebKitProfile *vitals_select_webkit_profile(
    const unsigned char *text, size_t filesz, size_t memsz, size_t data_filesz, size_t data_memsz) {
    for (size_t i = 0; i < sizeof(vitals_webkit_profiles) / sizeof(vitals_webkit_profiles[0]); ++i) {
        const VitalsWebKitProfile *profile = &vitals_webkit_profiles[i];
        if (filesz == profile->text_size && memsz == filesz && data_filesz == profile->data_filesz &&
            data_memsz == profile->data_memsz && vitals_profile_metadata_matches(text, filesz,
                profile->metadata_offset, "SceWebKit", profile->module_nid)) return profile;
    }
    return NULL;
}

#endif
