#include "test_loader.c"

#define NAME_NOT_FOUND ((int32_t)UINT32_C(0x90010002))

static int target_name_result, provider_name_result = NAME_NOT_FOUND;
static int target_name_uid = 188, provider_name_uid = 199;
static int wrong_target_name, wrong_provider_name, missing_target_nul, missing_provider_nul;
static unsigned int name_target_calls, name_provider_calls;

int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    assert(pid == 99 && !locked && info->size == sizeof(*info));
    require_query_workspace(info, sizeof(*info));
    assert(info->modid == 0 && info->name[sizeof(info->name) - 1] == 0);
    /* The browser engine, then the provider */
    int target = strcmp(name, "ScePsp2Compat") == 0;
    assert(target || strcmp(name, "vitals") == 0);
    if (target) ++name_target_calls;
    else ++name_provider_calls;
    int result = target ? target_name_result : provider_name_result;
    if (result != 0) return result;
    info->modid = target ? target_name_uid : provider_name_uid;
    int bad_name = target ? wrong_target_name : wrong_provider_name;
    strcpy(info->name, bad_name ? "different" : name);
    if (target ? missing_target_nul : missing_provider_nul) memset(info->name, 'x', sizeof(info->name));
    return 0;
}

