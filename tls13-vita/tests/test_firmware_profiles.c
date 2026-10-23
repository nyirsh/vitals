/* Host test of the firmware identities: each supported firmware's SceKernelModulemgr and SceWebKit
 * are recognised, with the right code family and browser callback, and nothing else is */
#include "vitals/firmware_profiles.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A module image of size bytes whose identity record (at offset) names name and nid */
static unsigned char *image(size_t size, size_t offset, const char *name, uint32_t nid) {
    unsigned char *text = calloc(1, size);
    assert(text != NULL);
    strcpy((char *)text + offset + 4, name);
    text[offset + 31] = 6;
    memcpy(text + offset + 0x34, &nid, sizeof(nid));
    return text;
}

static void test_kernel(void) {
    static const struct {
        uint32_t nid;
        size_t size, offset;
        unsigned int family;
    } supported[] = {
        {UINT32_C(0x726c6635), 0xef84, 0xb9d0, VITALS_KERNEL_FAMILY_360}, /* 3.60 */
        {UINT32_C(0x781c6f50), 0xf034, 0xba80, VITALS_KERNEL_FAMILY_365}, /* 3.65 */
    };
    for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); ++i) {
        unsigned char *text = image(supported[i].size, supported[i].offset, "SceKernelModulemgr", supported[i].nid);
        const VitalsKernelProfile *profile = vitals_select_kernel_profile(text, supported[i].size);
        assert(profile != NULL && profile->family == supported[i].family);
        /* Another size, name or NID is not that firmware */
        assert(vitals_select_kernel_profile(text, supported[i].size - 4) == NULL);
        text[supported[i].offset + 4] = 'X';
        assert(vitals_select_kernel_profile(text, supported[i].size) == NULL);
        free(text);
    }
    /* 3.61 shares 3.60's layout, and 3.67 shares 3.65's, but neither is supported */
    unsigned char *text = image(0xef84, 0xb9d0, "SceKernelModulemgr", UINT32_C(0xa5a80af8));
    assert(vitals_select_kernel_profile(text, 0xef84) == NULL);
    free(text);
    text = image(0xf034, 0xba80, "SceKernelModulemgr", UINT32_C(0x352000c9));
    assert(vitals_select_kernel_profile(text, 0xf034) == NULL);
    free(text);
}

static void test_webkit(void) {
    static const struct {
        uint32_t nid;
        int is_360;
    } supported[] = {
        {UINT32_C(0x20163df2), 1}, {UINT32_C(0x87f5a440), 1}, {UINT32_C(0x1a29ef0d), 1}, /* 3.60 */
        {UINT32_C(0xa33a93f7), 0}, {UINT32_C(0xe32c493d), 0}, {UINT32_C(0x8deccd66), 0}, /* 3.65 */
    };
    for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); ++i) {
        size_t size = supported[i].is_360 ? 0xaf2ebc : 0xaf2e9c;
        size_t offset = supported[i].is_360 ? 0x85fb04 : 0x85fae4;
        unsigned char *text = image(size, offset, "SceWebKit", supported[i].nid);
        const VitalsWebKitProfile *profile = vitals_select_webkit_profile(text, size, size, 0xce34, 0x115c0);
        assert(profile != NULL && profile->module_nid == supported[i].nid);
        assert(profile->callback_signature ==
               (supported[i].is_360 ? vitals_webkit_callback_360 : vitals_webkit_callback_365));
        assert(profile->callback_offset == (supported[i].is_360 ? 0x16c7b6u : 0x16c7bau));
        /* The other firmware's data size is not this one */
        assert(vitals_select_webkit_profile(text, size, size, 0xdb54, 0x122e8) == NULL);
        free(text);
    }
    /* 3.61's WebKit is not supported */
    unsigned char *text = image(0xaf2e9c, 0x85fae4, "SceWebKit", UINT32_C(0x95a02949));
    assert(vitals_select_webkit_profile(text, 0xaf2e9c, 0xaf2e9c, 0xce34, 0x115c0) == NULL);
    free(text);
}

int main(void) {
    test_kernel();
    test_webkit();
    puts("firmware profiles: 3.60 and 3.65 kernels and WebKit, other firmware rejected PASS");
    return 0;
}
