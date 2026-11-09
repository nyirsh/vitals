#include <kernel_mock.h>
#include "hook_guard.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define MODULE_ID 11

_Alignas(4) static unsigned char text[0xf034];
static SceKernelModuleInfo fixture;
static int query_result, query_calls;

typedef struct Site {
    size_t offset;
    const char *hex;
    const char *mask;
} Site;

/* SceKernelModulemgr on each supported firmware: its identity record and the code vitals checks */
typedef struct Firmware {
    const char *name;
    size_t text_size, metadata_offset;
    uint32_t module_nid;
    const Site *sites;
} Firmware;

static const Site sites_365[] = {
    {0x21ec, "2de9f04f4af20407c0f2ae07", "fffffffff0fb008ff0fb008f"},
    {0x21f8, "064689b00c463868904607901bb11b68042b40f0ef80002e00f0b880"
        "18f001054ff00503c0f2010300f0ac809e4200f0b2813046fff74afe0028c0f27b81", NULL},
    {0x2384, "09f060e9064643e7", NULL},
    {0x23f8, "0122002308f09cee054664e7", NULL},
    {0x286c, "2de9f04f4af2040689b0c0f2ae06", "fffffffff0fb008ffffff0fb008f"},
    {0x287a, "0025074634688846ddf84ce09246059599460794129d149cbef1000f25d0def80030102b1cbf", NULL},
    {0x29b2, "0df1140e00204a462b46cde900e051460bf10800fff7f9f88146404608f00cec059b012b1cd0022b15d0b9f1", NULL},
    {0, NULL, NULL},
};
/* 3.60 differs in three calls to code that moved */
static const Site sites_360[] = {
    {0x21ec, "2de9f04f4af20407c0f2ae07", "fffffffff0fb008ff0fb008f"},
    {0x21f8, "064689b00c463868904607901bb11b68042b40f0ef80002e00f0b880"
        "18f001054ff00503c0f2010300f0ac809e4200f0b2813046fff74afe0028c0f27b81", NULL},
    {0x2384, "09f00ae9064643e7", NULL},
    {0x23f8, "0122002308f046ee054664e7", NULL},
    {0x286c, "2de9f04f4af2040689b0c0f2ae06", "fffffffff0fb008ffffff0fb008f"},
    {0x287a, "0025074634688846ddf84ce09246059599460794129d149cbef1000f25d0def80030102b1cbf", NULL},
    {0x29b2, "0df1140e00204a462b46cde900e051460bf10800fff7f9f88146404608f0b6eb059b012b1cd0022b15d0b9f1", NULL},
    {0, NULL, NULL},
};
static const Firmware firmware_365 = {"3.65", 0xf034, 0xba80, UINT32_C(0x781c6f50), sites_365};
static const Firmware firmware_360 = {"3.60", 0xef84, 0xb9d0, UINT32_C(0x726c6635), sites_360};
static const Firmware *firmware = &firmware_365;

static unsigned char hex_byte(const char *hex) {
    unsigned int value;
    assert(sscanf(hex, "%2x", &value) == 1);
    return (unsigned char)value;
}

/* Writes sites into the module image */
static void write_sites(const Site *sites) {
    for (size_t i = 0; sites[i].hex != NULL; ++i) {
        size_t length = strlen(sites[i].hex) / 2;
        assert(sites[i].offset + length <= sizeof(text));
        for (size_t n = 0; n < length; ++n) {
            text[sites[i].offset + n] = hex_byte(sites[i].hex + n * 2);
        }
    }
}

static void reset(void) {
    memset(&fixture, 0, sizeof(fixture));
    memset(text, 0, sizeof(text));
    fixture.size = sizeof(fixture);
    fixture.modid = MODULE_ID;
    fixture.modattr = 7;
    fixture.modver[0] = fixture.modver[1] = 1;
    strcpy(fixture.module_name, "SceKernelModulemgr");
    fixture.start_entry = (void *)((uintptr_t)text + 0x378d);
    fixture.segments[0].size = sizeof(SceKernelSegmentInfo);
    fixture.segments[0].perms = 5;
    fixture.segments[0].vaddr = text;
    fixture.segments[0].memsz = fixture.segments[0].filesz = firmware->text_size;
    /* SceKernelModulemgr's identity record: its name, a type byte and its module NID */
    strcpy((char *)text + firmware->metadata_offset + 4, "SceKernelModulemgr");
    text[firmware->metadata_offset + 31] = 6;
    memcpy(text + firmware->metadata_offset + 0x34, &firmware->module_nid, sizeof(firmware->module_nid));
    write_sites(firmware->sites);
    query_result = query_calls = 0;
}

int ksceKernelGetModuleInfo(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    assert(pid == 0x10005 && module == MODULE_ID);
    assert(info != NULL && info->size == sizeof(*info));
    const unsigned char *raw = (const unsigned char *)info;
    for (size_t i = sizeof(info->size); i < sizeof(*info); ++i) assert(raw[i] == 0);
    ++query_calls;
    if (query_result < 0) return query_result;
    *info = fixture;
    return query_result;
}

static void expect_rejected(void) {
    assert(vitals_validate_loader_hook(MODULE_ID) < 0);
}

/* Every check, on the current firmware's module image */
static void check_firmware(void) {
    reset();
    assert(vitals_validate_loader_hook(0) < 0 && query_calls == 0);
    assert(vitals_validate_loader_hook(-1) < 0 && query_calls == 0);
    assert(vitals_validate_loader_hook(MODULE_ID) == 0 && query_calls == 1);

    reset(); query_result = -123; expect_rejected();
    reset(); fixture.modid = MODULE_ID + 1; expect_rejected();
    reset(); fixture.modattr ^= 1; expect_rejected();
    reset(); fixture.modver[0] = 2; expect_rejected();
    reset(); fixture.modver[1] = 2; expect_rejected();
    reset(); memset(fixture.module_name, 'x', sizeof(fixture.module_name)); expect_rejected();
    reset(); fixture.module_name[18] = 'x'; expect_rejected();
    reset(); fixture.start_entry = text; expect_rejected();
    reset(); fixture.segments[0].vaddr = NULL; expect_rejected();
    reset(); fixture.segments[0].vaddr = (void *)(uintptr_t)1; expect_rejected();
    reset(); fixture.segments[0].size = 0; expect_rejected();
    reset(); fixture.segments[0].filesz -= 1; expect_rejected();
    reset(); fixture.segments[0].filesz += 1; expect_rejected();
    reset(); fixture.segments[0].memsz = 16; expect_rejected();
    reset(); fixture.segments[0].perms = 6; expect_rejected();
    reset(); text[firmware->metadata_offset + 0x34] ^= 1; expect_rejected();
    reset(); text[firmware->metadata_offset + 4] = 'X'; expect_rejected();
    reset(); text[firmware->metadata_offset + 31] = 0; expect_rejected();
    reset(); fixture.segments[0].vaddr = (void *)(UINTPTR_MAX - 7);
    fixture.start_entry = NULL; expect_rejected();

    reset();
    fixture.segments[0].perms |= 0x100000;
    fixture.segments[0].memsz += 0x1000;
    assert(vitals_validate_loader_hook(MODULE_ID) == 0);

    reset();
    const Site *sites = firmware->sites;
    for (size_t i = 0; sites[i].hex != NULL; ++i) {
        size_t length = strlen(sites[i].hex) / 2;
        for (size_t n = 0; n < length; ++n) {
            unsigned char mask = sites[i].mask == NULL ? 0xff : hex_byte(sites[i].mask + n * 2);
            for (unsigned int bit = 1; bit <= 128; bit <<= 1) {
                text[sites[i].offset + n] ^= (unsigned char)bit;
                int result = vitals_validate_loader_hook(MODULE_ID);
                assert((mask & bit) ? result < 0 : result == 0);
                text[sites[i].offset + n] ^= (unsigned char)bit;
            }
        }
    }
    /* Other firmware (here 3.61 and 3.74's identities) is rejected */
    const uint32_t other_nids[] = {UINT32_C(0xa5a80af8), UINT32_C(0x8f483354)};
    for (size_t i = 0; i < sizeof(other_nids) / sizeof(other_nids[0]); ++i) {
        reset();
        memcpy(text + firmware->metadata_offset + 0x34, &other_nids[i], sizeof(other_nids[i]));
        expect_rejected();
    }
    reset();
    assert(vitals_validate_loader_hook(MODULE_ID) == 0);
}

int main(void) {
    firmware = &firmware_365;
    check_firmware();
    firmware = &firmware_360;
    check_firmware();
    /* Each firmware's identity accepts only its own code: the other's calls are rejected */
    firmware = &firmware_360;
    reset();
    write_sites(sites_365);
    expect_rejected();
    firmware = &firmware_365;
    reset();
    write_sites(sites_360);
    expect_rejected();
    puts("kernel hook guard: 3.60 and 3.65 identities and code, other firmware rejected, bounds and relocated "
         "instructions PASS");
    return 0;
}
