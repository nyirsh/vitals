#include "network.h"

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <stdint.h>
#include <stdlib.h>

#define NET_MEMORY (1024 * 1024)
/* sceNetCtl's own timeout error, given when no connection came in time */
#define ERROR_TIMED_OUT 0x80431068

static void *net_memory;
static int net_loaded, net_ready, ctl_ready, net_result = 1;

int network_start(int (*stop)(void))
{
    if (net_result <= 0)
        return net_result;
    int rc = 0;
    if (!ctl_ready)
    {
        if (!net_loaded && sceSysmoduleIsLoaded(SCE_SYSMODULE_NET) != SCE_SYSMODULE_LOADED)
        {
            rc = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
            if (rc < 0)
                goto done;
            net_loaded = 1;
        }
        if (!net_ready)
        {
            net_memory = malloc(NET_MEMORY);
            if (!net_memory)
            {
                rc = -1;
                goto done;
            }
            SceNetInitParam net = {net_memory, NET_MEMORY, 0};
            rc = sceNetInit(&net);
            if (rc < 0)
                goto done;
            net_ready = 1;
        }
        rc = sceNetCtlInit();
        if (rc < 0)
            goto done;
        ctl_ready = 1;
    }
    uint64_t deadline = (uint64_t)sceKernelGetSystemTimeWide() / 1000 + 10000;
    for (;;)
    {
        int state = 0;
        rc = sceNetCtlInetGetState(&state);
        if (rc < 0 || state == SCE_NETCTL_STATE_CONNECTED)
            break;
        if (stop != NULL && stop())
            return -1;
        if ((uint64_t)sceKernelGetSystemTimeWide() / 1000 > deadline)
        {
            rc = (int)ERROR_TIMED_OUT;
            break;
        }
        sceKernelDelayThread(50000);
    }
done:
    net_result = rc < 0 ? rc : 0;
    return net_result;
}

void network_stop(void)
{
    if (ctl_ready)
        sceNetCtlTerm();
    if (net_ready)
        sceNetTerm();
    if (net_loaded)
        sceSysmoduleUnloadModule(SCE_SYSMODULE_NET);
    free(net_memory);
    net_memory = NULL;
    ctl_ready = net_ready = net_loaded = 0;
    net_result = 1;
}
