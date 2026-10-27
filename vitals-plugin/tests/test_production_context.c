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
    assert(vitals_kernel_browser_loader_ready());
    runtime_namespace_required = 1;
    expected_path = "wb0:/vitals/vitals.suprx";
    unsigned int before_loads = (unsigned int)loads, before_stack = stack_calls;
    unsigned int before_queries = target_queries;
    /* Injected once, on the native stack, after one narrow lookup of the target */
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert((unsigned int)loads == before_loads + 1);
    assert(stack_calls == before_stack + 1 && target_queries == before_queries + 1);
    clean_context();
    /* Already resident: nothing loaded again */
    provider_name_result = 0;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert((unsigned int)loads == before_loads + 1);
    clean_context();
    /* A failed lookup is not taken for absence */
    provider_name_result = -42;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    assert((unsigned int)loads == before_loads + 1);
    clean_context();
    /* A native-stack call that never ran fails */
    provider_name_result = NAME_NOT_FOUND;
    stack_skip = 1;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    assert((unsigned int)loads == before_loads + 1);
    clean_context();
    stack_skip = 0;
    assert(name_target_calls == 3 && name_provider_calls == 3);
    assert(namespace_provider_opens == 0 && namespace_hash_opens == 1 && global_provider_stats == 1);
    reset();
    test_extended_stack_contract();
    test_query_workspace_failures();
    test_workspace_failures();
    test_loader_failure_paths();
    puts("browser provider: native stack, narrow lookup, duplicate/failure gates PASS");
    return 0;
}
