#include "provider.h"
#include "cert_hooks.h"
#include "diagnostics.h"
#include "host_redirect.h"
#include "transport.h"
#include "user_runtime.h"
#include "mapped_signature.h"
#include "private_mapping.h"

#include <psp2/kernel/modulemgr.h>
#include <psp2common/kernel/modulemgr.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint8_t g_create_bytes[] = {
    0x2D, 0xE9, 0xF0, 0x41, 0x88, 0xB0, 0x49, 0xF6, 0x00,
    0x18, 0xC8, 0xF2, 0x01, 0x18, 0xD8, 0xF8, 0x00, 0x20,
};
static const uint8_t g_connect_bytes[] = {
    0x70, 0xB5, 0x04, 0x1C, 0x06, 0xF0, 0x77, 0xFE,
};
static const uint8_t g_map_io_bytes[] = {
    0x70, 0xB5, 0x04, 0x1C, 0x20, 0x6C,
};
static const uint8_t g_read_bytes[] = {
    0x2D, 0xE9, 0xF0, 0x41, 0x14, 0x1C, 0x0D, 0x1C, 0x06, 0x1C, 0x10,
    0xF0, 0x84, 0xE9, 0x07, 0x1C, 0x00, 0x2F, 0x1E, 0xDB, 0x40, 0xF2,
    0xDC, 0x50, 0x22, 0x1C, 0x82, 0x42, 0x01, 0xD9, 0x40, 0xF2, 0xDC,
    0x52, 0x30, 0x6C, 0x29, 0x1C, 0x10, 0xF0, 0x86, 0xE9,
};
static const uint8_t g_write_bytes[] = {
    0x2D, 0xE9, 0xF0, 0x41, 0x14, 0x1C, 0x0D, 0x1C, 0x06, 0x1C, 0x10,
    0xF0, 0x58, 0xE9, 0x07, 0x1C, 0x00, 0x2F, 0x1E, 0xDB, 0x40, 0xF2,
    0xDC, 0x50, 0x22, 0x1C, 0x82, 0x42, 0x01, 0xD9, 0x40, 0xF2, 0xDC,
    0x52, 0x30, 0x6C, 0x29, 0x1C, 0x10, 0xF0, 0x7A, 0xEA,
};
static const uint8_t g_shutdown_bytes[] = {
    0x10, 0xB5, 0x04, 0x1C, 0x10, 0xF0, 0x2E, 0xE9,
};

static const VitalsMaskedSignature g_libhttp_signatures[] = {
    {
        .name = "create",
        .offset = VITALS_HOOK_CREATE_OFFSET,
        .bytes = g_create_bytes,
        .mask = "xxxxxx????????xxxx",
        .length = sizeof(g_create_bytes),
    },
    {
        .name = "connect",
        .offset = VITALS_HOOK_CONNECT_OFFSET,
        .bytes = g_connect_bytes,
        .mask = "xxxx???x",
        .length = sizeof(g_connect_bytes),
    },
    {
        .name = "map_io",
        .offset = VITALS_HOOK_MAP_IO_OFFSET,
        .bytes = g_map_io_bytes,
        .mask = "xxxxxx",
        .length = sizeof(g_map_io_bytes),
    },
    {
        .name = "read",
        .offset = VITALS_HOOK_READ_OFFSET,
        .bytes = g_read_bytes,
        .mask = "???xxxxxxx???xxxxxxx???xxxxxxx???xxxxx???x",
        .length = sizeof(g_read_bytes),
    },
    {
        .name = "write",
        .offset = VITALS_HOOK_WRITE_OFFSET,
        .bytes = g_write_bytes,
        .mask = "???xxxxxxx???xxxxxxx???xxxxxxx???xxxxx???x",
        .length = sizeof(g_write_bytes),
    },
    {
        .name = "shutdown",
        .offset = VITALS_HOOK_SHUTDOWN_OFFSET,
        .bytes = g_shutdown_bytes,
        .mask = "xxxx???x",
        .length = sizeof(g_shutdown_bytes),
    },
};

static const VitalsModuleDescriptor g_libhttp_descriptor = {
    .text_size = VITALS_LIBHTTP_TEXT_SIZE,
    .signatures = g_libhttp_signatures,
    .signature_count = sizeof(g_libhttp_signatures) / sizeof(g_libhttp_signatures[0]),
};

enum {
    HOOK_CREATE = 0,
    HOOK_CONNECT,
    HOOK_MAP_IO,
    HOOK_READ,
    HOOK_WRITE,
    HOOK_SHUTDOWN,
};

VitalsProviderGlobal g_vitals_http;

typedef int (*VitalsCreateContinuation)(void *request, int socket);
typedef int (*VitalsConnectContinuation)(void *request);
typedef int (*VitalsMapIoContinuation)(void *connection, int result);
typedef int (*VitalsReadContinuation)(void *connection, void *buffer, unsigned int length);
typedef int (*VitalsWriteContinuation)(void *connection, const void *buffer, unsigned int length);
typedef int (*VitalsShutdownContinuation)(void *connection);

static void *next_hook_function(tai_hook_ref_t reference) {
    struct _tai_hook_user *current = (struct _tai_hook_user *)reference;
    struct _tai_hook_user *next = (struct _tai_hook_user *)current->next;

    return next == NULL ? current->old : next->func;
}

static int hook_create(void *request, int socket) {
    VITALS_VERBOSE("event=hook.enter hook=create request=%08X socket=%d state=%d",
        (unsigned int)(uintptr_t)request, socket, g_vitals_http.state);
    int handled;
    int result = vitals_transport_create(request, socket, &handled);

    if (handled) {
        VITALS_VERBOSE("event=hook.return hook=create backend=provider request=%08X rc=%08X",
            (unsigned int)(uintptr_t)request, result);
        return result;
    }
    VITALS_LOG("event=fallback hook=create backend=sony request=%08X setup_rc=%08X",
        (unsigned int)(uintptr_t)request, result);
    result = ((VitalsCreateContinuation)next_hook_function(
        g_vitals_http.hook_refs[HOOK_CREATE]))(request, socket);
    VITALS_VERBOSE("event=hook.return hook=create backend=sony request=%08X rc=%08X",
        (unsigned int)(uintptr_t)request, result);
    return result;
}

static int hook_connect(void *request) {
    VITALS_VERBOSE("event=hook.enter hook=connect request=%08X", (unsigned int)(uintptr_t)request);
    int handled;
    int result = vitals_transport_connect(request, &handled);

    if (handled) {
        VITALS_VERBOSE("event=hook.return hook=connect backend=provider request=%08X rc=%08X",
            (unsigned int)(uintptr_t)request, result);
        return result;
    }
    VITALS_LOG("event=fallback hook=connect backend=sony request=%08X",
        (unsigned int)(uintptr_t)request);
    result = ((VitalsConnectContinuation)next_hook_function(
        g_vitals_http.hook_refs[HOOK_CONNECT]))(request);
    VITALS_VERBOSE("event=hook.return hook=connect backend=sony request=%08X rc=%08X",
        (unsigned int)(uintptr_t)request, result);
    return result;
}

static int hook_map_io(void *connection, int result) {
    int handled;
    int mapped = vitals_transport_map_io(connection, result, &handled);
    VITALS_VERBOSE("event=hook.map_io connection=%08X input=%08X mapped=%08X owned=%d",
        (unsigned int)(uintptr_t)connection, result, mapped, handled);

    if (handled) {
        return mapped;
    }
    return ((VitalsMapIoContinuation)next_hook_function(
        g_vitals_http.hook_refs[HOOK_MAP_IO]))(connection, result);
}

static int hook_read(void *connection, void *buffer, unsigned int length) {
    int handled;
    int result = vitals_transport_read(connection, buffer, length, &handled);
    VITALS_VERBOSE("event=hook.io direction=read connection=%08X requested=%u rc=%08X owned=%d",
        (unsigned int)(uintptr_t)connection, length, result, handled);

    if (handled) {
        return result;
    }
    return ((VitalsReadContinuation)next_hook_function(
        g_vitals_http.hook_refs[HOOK_READ]))(connection, buffer, length);
}

static int hook_write(void *connection, const void *buffer, unsigned int length) {
    int handled;
    int result = vitals_transport_write(connection, buffer, length, &handled);
    VITALS_VERBOSE("event=hook.io direction=write connection=%08X requested=%u rc=%08X owned=%d",
        (unsigned int)(uintptr_t)connection, length, result, handled);

    if (handled) {
        return result;
    }
    return ((VitalsWriteContinuation)next_hook_function(
        g_vitals_http.hook_refs[HOOK_WRITE]))(connection, buffer, length);
}

static int hook_shutdown(void *connection) {
    int handled;
    int result = vitals_transport_shutdown(connection, &handled);
    VITALS_VERBOSE("event=hook.shutdown connection=%08X rc=%08X owned=%d",
        (unsigned int)(uintptr_t)connection, result, handled);

    if (handled) {
        return result;
    }
    return ((VitalsShutdownContinuation)next_hook_function(
        g_vitals_http.hook_refs[HOOK_SHUTDOWN]))(connection);
}

typedef struct VitalsHookInstallDescriptor {
    size_t offset;
    const void *function;
} VitalsHookInstallDescriptor;

static const VitalsHookInstallDescriptor g_hook_install_descriptors[] = {
    {VITALS_HOOK_CREATE_OFFSET, hook_create},
    {VITALS_HOOK_CONNECT_OFFSET, hook_connect},
    {VITALS_HOOK_MAP_IO_OFFSET, hook_map_io},
    {VITALS_HOOK_READ_OFFSET, hook_read},
    {VITALS_HOOK_WRITE_OFFSET, hook_write},
    {VITALS_HOOK_SHUTDOWN_OFFSET, hook_shutdown},
};

int vitals_http_validate_start_args(SceSize argc, const void *args, VitalsStartArgs *out) {
    if (args == NULL || out == NULL || argc != sizeof(*out)) {
        return -1;
    }

    memcpy(out, args, sizeof(*out));
    if (out->magic != VITALS_START_MAGIC ||
        out->version != VITALS_START_VERSION ||
        out->libhttp_modid < 0 ||
        out->reserved != 0) {
        memset(out, 0, sizeof(*out));
        return -1;
    }

    return 0;
}

int vitals_http_validate_module(
    int32_t modid,
    uintptr_t *text_address,
    size_t *text_size,
    uintptr_t *data_address,
    size_t *data_size) {
    SceKernelModuleInfo info;
    size_t failed_signature = SIZE_MAX;
    size_t failed_byte = SIZE_MAX;
    int result;

    if (modid < 0 || text_address == NULL || text_size == NULL ||
        data_address == NULL || data_size == NULL) {
        return -1;
    }

    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    result = sceKernelGetModuleInfo(modid, &info);
    VITALS_VERBOSE("event=module.info uid=%08X rc=%08X name=%.28s text=%08X file=%u mem=%u "
        "data=%08X file=%u mem=%u", modid, result, info.module_name,
        (unsigned int)(uintptr_t)info.segments[0].vaddr, info.segments[0].filesz,
        info.segments[0].memsz, (unsigned int)(uintptr_t)info.segments[1].vaddr,
        info.segments[1].filesz, info.segments[1].memsz);
    if (result < 0 || strcmp(info.module_name, "SceLibHttp") != 0) {
        return -1;
    }
    if (info.segments[0].vaddr == NULL ||
        info.segments[0].filesz != VITALS_LIBHTTP_TEXT_SIZE ||
        info.segments[0].memsz != VITALS_LIBHTTP_TEXT_SIZE) {
        return -1;
    }
    if ((uintptr_t)info.segments[0].vaddr >= UINT32_C(0xE0000000)) {
        VITALS_LOG("event=module.gate reason=shared_text");
        return -1;
    }
    if (info.segments[1].vaddr == NULL ||
        info.segments[1].filesz != VITALS_LIBHTTP_DATA_FILE_SIZE ||
        info.segments[1].memsz != VITALS_LIBHTTP_DATA_MEMORY_SIZE) {
        return -1;
    }
    if (vitals_require_private_mapping(info.segments[0].vaddr, info.segments[0].memsz, 1) != 0 ||
        vitals_require_private_mapping(info.segments[1].vaddr, info.segments[1].memsz, 0) != 0) {
        VITALS_LOG("event=module.gate reason=nonprivate_mapping");
        return -1;
    }
    if (!vitals_http_create_mov_pair_valid(
            (const uint8_t *)info.segments[0].vaddr + VITALS_HOOK_CREATE_OFFSET,
            sizeof(g_create_bytes))) {
        VITALS_LOG("event=module.gate reason=create_mov_opcode_or_register");
        return VITALS_MODULE_GATE_SIGNATURE_MISMATCH;
    }

    result = vitals_validate_module_text(
        (const uint8_t *)info.segments[0].vaddr,
        info.segments[0].filesz,
        &g_libhttp_descriptor,
        &failed_signature,
        &failed_byte);
    if (result != VITALS_MODULE_GATE_OK) {
        VITALS_LOG("event=module.gate rc=%08X failed_signature=%u failed_byte=%u",
            result, (unsigned int)failed_signature, (unsigned int)failed_byte);
#if VITALS_DEBUG >= 2
        if (failed_signature < g_libhttp_descriptor.signature_count &&
            failed_byte < g_libhttp_signatures[failed_signature].length) {
            const VitalsMaskedSignature *sig = &g_libhttp_signatures[failed_signature];
            VITALS_VERBOSE("event=module.gate.byte offset=%08X expected=%02X actual=%02X",
                (unsigned int)(sig->offset + failed_byte), sig->bytes[failed_byte],
                ((const uint8_t *)info.segments[0].vaddr)[sig->offset + failed_byte]);
        }
#endif
        return result;
    }

    if (vitals_cert_policy_bind(&g_vitals_http.cert_policy,
                               info.segments[0].vaddr, info.segments[0].filesz) != 0) {
        VITALS_LOG("certificate callback policy import mismatch");
        return -1;
    }

    *text_address = (uintptr_t)info.segments[0].vaddr;
    *text_size = info.segments[0].filesz;
    *data_address = (uintptr_t)info.segments[1].vaddr;
    *data_size = info.segments[1].memsz;
    return 0;
}

int vitals_http_install_hooks(void) {
    size_t index;

    for (index = 0; index < VITALS_HOOK_COUNT; ++index) {
        const VitalsHookInstallDescriptor *descriptor = &g_hook_install_descriptors[index];
        int hook_id = taiHookFunctionOffset(
            &g_vitals_http.hook_refs[index],
            g_vitals_http.libhttp_modid,
            0,
            descriptor->offset,
            1,
            descriptor->function);
        VITALS_VERBOSE("event=hook.install kind=offset index=%u name=%s offset=%08X rc=%08X",
            (unsigned int)index, g_libhttp_signatures[index].name,
            (unsigned int)descriptor->offset, hook_id);
        if (hook_id < 0) {
            vitals_http_release_hooks();
            return hook_id;
        }
        g_vitals_http.hook_ids[index] = hook_id;
    }

    return 0;
}

void vitals_http_release_hooks(void) {
    size_t index = VITALS_HOOK_COUNT;

    while (index > 0) {
        --index;
        if (g_vitals_http.hook_ids[index] >= 0) {
            taiHookRelease(
                g_vitals_http.hook_ids[index],
                g_vitals_http.hook_refs[index]);
            g_vitals_http.hook_ids[index] = -1;
            memset(&g_vitals_http.hook_refs[index], 0, sizeof(g_vitals_http.hook_refs[index]));
        }
    }
}

int module_start(SceSize argc, const void *args) {
    VitalsStartArgs start_args;
    size_t index;
    VITALS_VERBOSE("event=module.start argc=%u", (unsigned int)argc);
    memset(&g_vitals_http, 0, sizeof(g_vitals_http));
    for (index = 0; index < VITALS_HOOK_COUNT; ++index) {
        g_vitals_http.hook_ids[index] = -1;
    }
    g_vitals_http.state = VITALS_PROVIDER_STARTING;

    if (vitals_http_validate_start_args(argc, args, &start_args) < 0) {
        VITALS_LOG("invalid start arguments");
        g_vitals_http.state = VITALS_PROVIDER_STOPPED;
        (void)vitals_user_runtime_destroy();
        return SCE_KERNEL_START_FAILED;
    }

    g_vitals_http.libhttp_modid = start_args.libhttp_modid;
    VITALS_VERBOSE("event=start.args target=%08X magic=%08X version=%u",
        start_args.libhttp_modid, start_args.magic, start_args.version);
    if (vitals_http_validate_module(
            start_args.libhttp_modid,
            &g_vitals_http.text_address,
            &g_vitals_http.text_size,
            &g_vitals_http.data_address,
            &g_vitals_http.data_size) < 0) {
        VITALS_LOG("mapped libhttp validation failed: modid=0x%08X", start_args.libhttp_modid);
        g_vitals_http.state = VITALS_PROVIDER_STOPPED;
        (void)vitals_user_runtime_destroy();
        return SCE_KERNEL_START_FAILED;
    }
    g_vitals_http.global_https_options_address =
        g_vitals_http.data_address + VITALS_LIBHTTP_GLOBAL_HTTPS_OPTIONS_OFFSET;
    int runtime_result = vitals_user_runtime_init();
    VITALS_VERBOSE("event=runtime.init backend=SceLibKernel rc=%08X heap_bytes=%u",
        runtime_result, (unsigned int)VITALS_HTTP_HEAP_BYTES);
    if (runtime_result < 0) return SCE_KERNEL_START_FAILED;

    {
        VITALS_VERBOSE("event=global.init.enter");
        int result = vitals_transport_global_init();
        VITALS_VERBOSE("event=global.init.return rc=%08X", result);
        if (result != 0) {
            VITALS_LOG("global TLS initialization failed: 0x%08X", result);
            g_vitals_http.state = VITALS_PROVIDER_STOPPED;
            (void)vitals_user_runtime_destroy();
            return SCE_KERNEL_START_FAILED;
        }
    }

    {
        VITALS_VERBOSE("event=certificate.hooks.enter");
        int result = vitals_cert_hooks_install();
        VITALS_VERBOSE("event=certificate.hooks.return rc=%08X", result);
        if (result < 0) {
            VITALS_LOG("certificate hook installation failed: 0x%08X", result);
            (void)vitals_transport_global_destroy();
            g_vitals_http.state = VITALS_PROVIDER_STOPPED;
            (void)vitals_user_runtime_destroy();
            return SCE_KERNEL_START_FAILED;
        }
    }

    {
        VITALS_VERBOSE("event=transport.hooks.enter");
        int result = vitals_http_install_hooks();
        VITALS_VERBOSE("event=transport.hooks.return rc=%08X", result);
        if (result < 0) {
            VITALS_LOG("transport hook installation failed: 0x%08X", result);
            vitals_cert_hooks_release();
            (void)vitals_transport_global_destroy();
            g_vitals_http.state = VITALS_PROVIDER_STOPPED;
            (void)vitals_user_runtime_destroy();
            return SCE_KERNEL_START_FAILED;
        }
    }

    /* Host redirects are optional and never stop the provider */
    vitals_host_redirect_install();

    VITALS_LOG(
        "active: libhttp=0x%08X text=0x%08X data=0x%08X",
        g_vitals_http.libhttp_modid,
        (unsigned int)g_vitals_http.text_address,
        (unsigned int)g_vitals_http.data_address);
    g_vitals_http.state = VITALS_PROVIDER_ACTIVE;
    VitalsRuntimeStats runtime_stats = {0};
    (void)vitals_user_runtime_stats(&runtime_stats);
    VITALS_LOG("event=runtime.ready capacity=%u used=%u peak=%u allocations=%u",
        runtime_stats.capacity, runtime_stats.used, runtime_stats.peak, runtime_stats.outstanding);
    vitals_user_runtime_report("ready", 1);
    VITALS_LOG("build %s %s", __DATE__, __TIME__);
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
    (void)argc;
    (void)args;
    /* Empty registries do not exclude threads entering hooks or executing their continuations */
    VITALS_LOG("hot unload rejected; provider is resident until process exit");
    return SCE_KERNEL_STOP_FAIL;
}

/* The Vita loader enters through _start; macOS, where only the host tests build, has no aliases */
#if !defined(__APPLE__)
int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));
#endif
