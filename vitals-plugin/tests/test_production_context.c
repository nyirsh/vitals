#include "test_name_query.c"

static void clean_context(void) {
    assert(!query_live && query_allocations == query_frees);
    assert(!workspace_live && allocations == frees && open_descriptors == 0);
    assert(!argument_live && argument_allocations == argument_frees);
    assert(!locked);
}

int main(void) {
    reset();
    assert(vitals_kernel_loader_init() == 0);
    assert(vitals_kernel_loader_ready() && vitals_kernel_browser_loader_ready());
    runtime_namespace_required = 1;
    const char *paths[] = {"vs0:/data/external/vitals/native/vitals_http.suprx",
        "wb0:/vitals/vitals.suprx"};
    for (unsigned int target = 0; target < 2; ++target) {
        expected_path = paths[target];
        unsigned int before_loads = (unsigned int)loads, before_stack = stack_calls;
        unsigned int before_queries = target_queries;
        int result = target ? vitals_kernel_inject_browser_for_pid(99, 88, expected_path)
            : vitals_kernel_inject_for_pid(99, 88);
        assert(result == 0 && (unsigned int)loads == before_loads + 1);
        assert(stack_calls == before_stack + 1 && target_queries == before_queries + 1);
        clean_context();
        provider_name_result = 0;
        result = target ? vitals_kernel_inject_browser_for_pid(99, 88, expected_path)
            : vitals_kernel_inject_for_pid(99, 88);
        assert(result == 0 && (unsigned int)loads == before_loads + 1);
        clean_context();
        provider_name_result = -42;
        result = target ? vitals_kernel_inject_browser_for_pid(99, 88, expected_path)
            : vitals_kernel_inject_for_pid(99, 88);
        assert(result < 0 && (unsigned int)loads == before_loads + 1);
        clean_context();
        provider_name_result = NAME_NOT_FOUND;
        stack_skip = 1;
        result = target ? vitals_kernel_inject_browser_for_pid(99, 88, expected_path)
            : vitals_kernel_inject_for_pid(99, 88);
        assert(result < 0 && (unsigned int)loads == before_loads + 1);
        clean_context();
        stack_skip = 0;
    }
    assert(name_target_calls == 6 && name_provider_calls == 6);
    assert(namespace_provider_opens == 0 && namespace_hash_opens == 1 && global_provider_stats == 1);
    assert(libc_queries == 0);
    expected_path = paths[0];
    unsigned int before_loads = (unsigned int)loads, before_arguments = argument_allocations;
    libc_result = NAME_NOT_FOUND;
    assert(vitals_kernel_inject_for_pid(99, 88) == 0);
    assert((unsigned int)loads == before_loads + 1 && argument_allocations == before_arguments + 1);
    clean_context();
    libc_result = -42;
    assert(vitals_kernel_inject_for_pid(99, 88) == 0);
    clean_context();
    libc_result = 0; wrong_libc_name = 1;
    assert(vitals_kernel_inject_for_pid(99, 88) == 0);
    clean_context();
    wrong_libc_name = 0; libc_uid = 0;
    assert(vitals_kernel_inject_for_pid(99, 88) == 0);
    clean_context();
    libc_uid = 177;
    assert((unsigned int)loads == before_loads + 4 && libc_queries == 0);
    assert(vitals_kernel_inject_for_pid(99, 88) == 0 && (unsigned int)loads == before_loads + 5);
    clean_context();
    reset();
    assert(vitals_kernel_loader_init() == 0);
    expected_path = paths[0];
    before_loads = (unsigned int)loads;
    unsigned int before_query_allocations = query_allocations, before_stack_calls = stack_calls;
    /* The browser's two processes never get the HTTP provider */
    const char *excluded_titles[] = {"NPXS10003", "NPXS10083"};
    const unsigned int excluded = sizeof(excluded_titles) / sizeof(*excluded_titles);
    for (size_t i = 0; i < excluded; ++i) {
        process_title = excluded_titles[i];
        assert(vitals_kernel_inject_for_pid(99, 88) == 0);
        assert((unsigned int)loads == before_loads && query_allocations == before_query_allocations);
        assert(process_title_queries == i + 1 && stack_calls == before_stack_calls);
        clean_context();
    }
    process_title_error = -77;
    assert(vitals_kernel_inject_for_pid(99, 88) == -77);
    assert((unsigned int)loads == before_loads && query_allocations == before_query_allocations);
    assert(stack_calls == before_stack_calls);
    clean_context();
    /* The process exclusion applies only to HTTP, even with a failed title lookup */
    expected_path = paths[1];
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert((unsigned int)loads == before_loads + 1 && process_title_queries == excluded + 1);
    clean_context();
    process_title_error = 0;
    process_title = "TLSFIXAPP";
    expected_path = paths[0];
    assert(vitals_kernel_inject_for_pid(99, 88) == 0);
    assert((unsigned int)loads == before_loads + 2 && process_title_queries == excluded + 2);
    clean_context();
    reset();
    test_extended_stack_contract();
    test_query_workspace_failures();
    test_workspace_failures();
    test_loader_failure_paths();
    puts("normal providers: native stack, narrow lookup, duplicate/failure gates and both targets PASS");
    return 0;
}
