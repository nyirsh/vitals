#include "native_module_api.h"
#include <taihen.h>
#include <assert.h>
#include <stdio.h>

static uint32_t identity_nid;
static int fail_index, lookup_count, bad_identity;
static int consumer_query, list_result, info_result, imports_result, copy_result, wrong_import_uid;
static SceSize consumer_count = 1;
static uint16_t consumer_attributes = 0x200;
static int consumer_sharing = 1;
static const char *consumer_name = "shared_http_user";
static uint8_t import_header[0x34];
static uintptr_t import_begin = 0x81010000, import_end = 0x81010034;

static int fake_info(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    assert(pid == 21 && module == 22 && info != NULL);
    if (consumer_query) {
        assert(info->size == sizeof(*info));
        info->modid = 22;
        info->modattr = consumer_attributes;
        strcpy(info->module_name, consumer_name);
        info->segments[0].vaddr = (void *)(uintptr_t)0x81000000;
        return info_result;
    }
    return 31;
}
static int fake_list(SceUID pid, int a, int b, SceUID *modules, SceSize *count) {
    assert(pid == 21 && a == 0xff && b == 1 && modules != NULL && *count == 256);
    if (consumer_query) { modules[0] = 22; *count = consumer_count; return list_result; }
    return 32;
}
static int fake_unload(SceUID pid, SceUID module, int flags, const void *options) {
    assert(pid == 21 && module == 22 && flags == 0 && options == NULL);
    return 33;
}
static int fake_shared(SceUID pid, void *address) {
    assert(pid == 21 && address == (void *)(uintptr_t)0x81000000);
    if (consumer_query) return consumer_sharing;
    return 34;
}
int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    if (consumer_query && pid == 21) {
        assert(strcmp(name, "shared_http_user") == 0 && info->size == sizeof(*info));
        info->modid = wrong_import_uid ? 23 : 22;
        info->imports_start = import_begin; info->imports_end = import_end;
        return imports_result;
    }
    assert(pid == KERNEL_PID && strcmp(name, "SceKernelModulemgr") == 0);
    assert(info->size == sizeof(*info));
    info->module_nid = identity_nid;
    strcpy(info->name, bad_identity ? "unknown" : name);
    return 0;
}
/* Each firmware family's library and function IDs: 3.60 and 3.61, then 3.63 and later */
static int family_360;
int module_get_export_func(SceUID pid, const char *name, uint32_t library, uint32_t function, uintptr_t *address) {
    static const uint32_t nids[2][4] = {{0xdaa90093,0xb72c75a4,0xfca9fdb1,0xf1de6949},
                                        {0xd269f915,0x97cf7b4e,0x5972e2cc,0x99890202}};
    uintptr_t targets[] = {(uintptr_t)fake_info,(uintptr_t)fake_list,(uintptr_t)fake_unload,
        (uintptr_t)fake_shared};
    assert(pid == KERNEL_PID && strcmp(name, "SceKernelModulemgr") == 0);
    assert(library == (family_360 ? UINT32_C(0xc445fa63) : UINT32_C(0x92c9ffc2)));
    int i = lookup_count++;
    assert(i < 4 && function == nids[family_360][i]);
    if (i == fail_index) return -123;
    *address = targets[i];
    return 0;
}
static void forwarding(void) {
    consumer_query = 0;
    SceKernelModuleInfo info;
    SceUID modules[256]; SceSize count = 256;
    assert(vitals_native_module_info(21,22,&info) == 31);
    assert(vitals_native_module_list(21,0xff,1,modules,&count) == 32);
    assert(vitals_native_module_unload(21,22,0,NULL) == 33);
    assert(vitals_native_module_shared(21,(void *)(uintptr_t)0x81000000) == 34);
}
int ksceKernelCopyFromUserProc(SceUID pid, void *destination, const void *source, SceSize size) {
    assert(pid == 21 && consumer_query && size == 20 && (uintptr_t)source == import_begin);
    if (copy_result < 0) return copy_result;
    memcpy(destination, import_header, size);
    return 0;
}
static void consumer_checks(void) {
    VitalsNativeHttpConsumer consumer;
    consumer_query = 1;
    memset(import_header, 0, sizeof(import_header));
    import_header[0] = 0x34;
    uint32_t library = UINT32_C(0xe8f15cde);
    memcpy(import_header + 16, &library, 4);
    assert(vitals_native_http_shared_consumer(21, &consumer) == 1);
    assert(consumer.module == 22 && consumer.library == library && consumer.attributes == 0x200);
    assert(strcmp(consumer.name, "shared_http_user") == 0);
    library = UINT32_C(0xcaf5f2e9); memcpy(import_header + 16, &library, 4);
    assert(vitals_native_http_shared_consumer(21, NULL) == 1);
    import_header[0] = 0x24; import_end = import_begin + 0x24;
    memcpy(import_header + 12, &library, 4);
    assert(vitals_native_http_shared_consumer(21, NULL) == 1);
    library = 0x12345678; memcpy(import_header + 12, &library, 4);
    assert(vitals_native_http_shared_consumer(21, NULL) == 0);
    consumer_attributes = 0x1000; consumer_sharing = 0;
    library = UINT32_C(0xe8f15cde); memcpy(import_header + 12, &library, 4);
    assert(vitals_native_http_shared_consumer(21, NULL) == 0);
    consumer_attributes = 0x200; consumer_sharing = -9;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    consumer_sharing = 2;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    consumer_sharing = 1;
    consumer_name = "SceLibHttp";
    assert(vitals_native_http_shared_consumer(21, NULL) == 0);
    /* Adrenaline's PSP emulator keeps Sony's library, found by its module whatever bubble
     * started it; its imports are not read (the import lookup would reject its name) */
    consumer_name = "ScePspemu";
    library = 0x12345678; memcpy(import_header + 12, &library, 4);
    assert(vitals_native_http_shared_consumer(21, &consumer) == 1);
    assert(consumer.module == 22 && consumer.step == 6 && strcmp(consumer.name, "ScePspemu") == 0);
    library = UINT32_C(0xe8f15cde); memcpy(import_header + 12, &library, 4);
    consumer_name = "shared_http_user";
    import_header[0] = 0;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    import_header[0] = 0x24;
    import_end = import_begin + 19;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    import_end = import_begin - 1;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    import_end = import_begin + 65537;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    import_end = import_begin + 0x34; import_header[0] = 0x34;
    library = UINT32_C(0xe8f15cde); memcpy(import_header + 16, &library, 4);
    wrong_import_uid = 1;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    wrong_import_uid = 0; copy_result = -9;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    copy_result = 0; imports_result = -9;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    imports_result = 0; info_result = -9;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    info_result = 0; list_result = -9;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    list_result = 0; consumer_count = 256;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    consumer_count = 0;
    assert(vitals_native_http_shared_consumer(21, NULL) < 0);
    consumer_count = 1; consumer_query = 0;
}
int main(void) {
    assert(vitals_native_module_info(0,0,NULL) < 0);
    {
        identity_nid = 0x781c6f50; bad_identity = 0;
        lookup_count = 0; fail_index = -1;
        assert(vitals_native_module_api_init() == 0 && lookup_count == 4);
        forwarding();
        consumer_checks();
        for (fail_index = 0; fail_index < 4; ++fail_index) {
            lookup_count = 0;
            assert(vitals_native_module_api_init() < 0);
            assert(vitals_native_module_info(0,0,NULL) < 0);
            assert(vitals_native_module_list(0,0,0,NULL,NULL) < 0);
            assert(vitals_native_module_unload(0,0,0,NULL) < 0);
            assert(vitals_native_module_shared(0,NULL) < 0);
            assert(vitals_native_http_shared_consumer(21, NULL) < 0);
        }
    }
    /* 3.60 finds the same functions in its own library, under its own IDs */
    identity_nid = 0x726c6635; family_360 = 1;
    lookup_count = 0; fail_index = -1;
    assert(vitals_native_module_api_init() == 0 && lookup_count == 4);
    forwarding();
    consumer_checks();
    fail_index = 2; lookup_count = 0;
    assert(vitals_native_module_api_init() < 0 && vitals_native_module_info(0,0,NULL) < 0);
    family_360 = 0; fail_index = -1;
    /* Other firmware (here 3.61, 3.63 and 3.74) is rejected before any lookup */
    const uint32_t other_identities[] = {0xa5a80af8, 0xb87084f7, 0x8f483354, 0};
    for (size_t i = 0; i < sizeof(other_identities)/sizeof(other_identities[0]); ++i) {
        identity_nid = other_identities[i]; lookup_count = 0;
        assert(vitals_native_module_api_init() < 0 && lookup_count == 0);
    }
    identity_nid = 0x781c6f50; bad_identity = 1;
    assert(vitals_native_module_api_init() < 0 && lookup_count == 0);
    puts("native module APIs: 3.60 and 3.65 exports, other firmware rejected, forwarding and failed publication PASS");
    return 0;
}
