#include "test_name_query.c"

static void clean_context(void) {
    assert(!query_live && query_allocations == query_frees);
    assert(!workspace_live && allocations == frees && open_descriptors == 0);
    assert(!argument_live && argument_allocations == argument_frees);
    assert(!locked);
}

/* libssl is loaded into the process before the provider, unless it is there; without it there is
 * no provider */
static void test_libssl_first(void) {
    reset();
    assert(vitals_kernel_loader_init() == 0);
    provider_name_result = NAME_NOT_FOUND;
    ssl_name_result = NAME_NOT_FOUND;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert(ssl_loads == 1 && loads == 1);
    clean_context();
    ssl_name_result = 0;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert(ssl_loads == 1 && loads == 2);
    ssl_name_result = NAME_NOT_FOUND;
    ssl_load_error = 1;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == -457);
    ssl_load_error = 0;
    ssl_start_error = 1;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && ssl_unloads == 1);
    ssl_start_error = 0;
    ssl_name_result = -42;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    ssl_name_result = NAME_NOT_FOUND;
    assert(loads == 2 && ssl_loads == 3);
    clean_context();
    reset();
}

int main(void) {
    reset();
    assert(vitals_kernel_loader_init() == 0);
    assert(vitals_kernel_browser_loader_ready());
    runtime_namespace_required = 1;
    expected_path = "sd062e8855c978:/cert/CA_LIST.cer";
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
    /* Nothing is opened in the process's own view: the engine and the provider are both in the
     * system's, in ux0:data/vitals/system */
    assert(namespace_provider_opens == 0 && namespace_hash_opens == 0 && global_provider_stats == 1);
    reset();
    test_extended_stack_contract();
    test_query_workspace_failures();
    test_workspace_failures();
    test_loader_failure_paths();
    test_provider_appears_later();
    test_libssl_first();
    puts("browser provider: native stack, narrow lookup, duplicate/failure gates PASS");
    return 0;
}
