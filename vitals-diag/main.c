/*
 * vitals-diag: a temporary diagnostic, not part of vitals' releases
 *
 * The kernel plugin loads Sony's own libhttp into the PS Store (NPXS10002) when
 * ur0:data/vitals-diag/lhttp.suprx exists, and this module into it once SceNpCommerce2 has
 * started. This module hooks every SceHttp import of the process's modules and logs each call,
 * its arguments, its result and what it wrote back, in the same terms as vitals-http's Full debug
 * output, so the two logs can be compared. It also sends PSN sign-in to its new host, as
 * vitals-reauth did, since Sony's libhttp doesn't read redirects.txt.
 */

#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/threadmgr.h>
#include <taihen.h>

#include <stdint.h>

#include "hooks.h"
#include "ssl_hooks.h"

#define LOG(format, ...) sceClibPrintf("vitals-diag: " format "\n", ##__VA_ARGS__)

#define SCE_HTTP_LIBRARY_NID 0xE8F15CDE
#define OLD_HOST "native.np.ac.playstation.net"
#define NEW_HOST "native-vita.np.ac.playstation.net"
/* Modules whose imports are hooked: the process's own modules that import SceHttp or libssl.
 * Shared system modules are left alone: hooking them stops other processes from linking libhttp */
#define SLOTS 12
#define SSL_SLOTS 4
#define MODULES_MAX 128

typedef uint32_t (*Forward)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

/* Initialized, so the data segment isn't empty (an empty one overlaps the code in the SELF) */
static volatile unsigned g_build = 10;
static SceUID g_hooks[SLOTS][DIAG_FUNCTION_COUNT];
static tai_hook_ref_t g_refs[SLOTS][DIAG_FUNCTION_COUNT];

static int same(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b)
        ++a, ++b;
    return *a == *b;
}

static int starts(const char *text, const char *prefix)
{
    while (*prefix != '\0' && *text == *prefix)
        ++text, ++prefix;
    return *prefix == '\0';
}

static unsigned length_of(const char *text)
{
    unsigned length = 0;
    while (text[length] != '\0')
        ++length;
    return length;
}

/* A URL on the old PSN host, rewritten to the new one in buffer; NULL when it isn't one */
static const char *redirect_url(const char *url, char *buffer, unsigned capacity)
{
    static const char *const schemes[] = {"https://", "http://"};
    for (unsigned s = 0; s < 2; ++s) {
        unsigned scheme = length_of(schemes[s]);
        if (!starts(url, schemes[s]) || !starts(url + scheme, OLD_HOST))
            continue;
        const char *rest = url + scheme + sizeof(OLD_HOST) - 1;
        if (*rest != '\0' && *rest != '/' && *rest != ':' && *rest != '?')
            continue;
        if (scheme + sizeof(NEW_HOST) - 1 + length_of(rest) + 1 > capacity)
            return 0;
        sceClibSnprintf(buffer, capacity, "%s%s%s", schemes[s], NEW_HOST, rest);
        return buffer;
    }
    return 0;
}

/* Whether a header line's name has "token" in it, any case */
static int names_token(const char *line, unsigned length)
{
    for (unsigned i = 0; i + 5 <= length && line[i] != ':'; ++i) {
        unsigned j = 0;
        while (j < 5 && (line[i + j] | 0x20) == "token"[j])
            ++j;
        if (j == 5)
            return 1;
    }
    return 0;
}

static void log_hex(const char *label, const unsigned char *data, unsigned size)
{
    char hex[2 * 32 + 1];
    unsigned shown = size < 32 ? size : 32;
    for (unsigned i = 0; i < shown; ++i)
        sceClibSnprintf(hex + 2 * i, 3, "%02X", data[i]);
    hex[2 * shown] = '\0';
    LOG("  %s %s%s", label, hex, size > shown ? "..." : "");
}

/* One call: arguments in a[], what it returned in result; outputs read after the call */
static void log_call(unsigned index, const uint32_t *a, uint32_t result)
{
    const char *name = g_functions[index].name;
    const int rc = (int)result;
    if (same(name, "sceHttpCreateTemplate"))
        LOG("%s(agent=%s ver=%d proxy=%d) rc=%08X", name, a[0] ? (const char *)a[0] : "(null)", (int)a[1], (int)a[2], result);
    else if (same(name, "sceHttpCreateConnection"))
        LOG("%s(tmpl=%d host=%s scheme=%s port=%u keepalive=%d) rc=%08X", name, (int)a[0], (const char *)a[1],
            (const char *)a[2], a[3] & 0xffff, (int)a[4], result);
    else if (same(name, "sceHttpCreateConnectionWithURL"))
        LOG("%s(tmpl=%d url=%s keepalive=%d) rc=%08X", name, (int)a[0], (const char *)a[1], (int)a[2], result);
    else if (same(name, "sceHttpCreateRequest") || same(name, "sceHttpCreateRequestWithURL"))
        LOG("%s(conn=%d method=%d target=%s length=%u) rc=%08X", name, (int)a[0], (int)a[1], (const char *)a[2], a[4],
            result);
    else if (same(name, "sceHttpCreateRequest2") || same(name, "sceHttpCreateRequestWithURL2"))
        LOG("%s(conn=%d method=%s target=%s length=%u) rc=%08X", name, (int)a[0], (const char *)a[1],
            (const char *)a[2], a[4], result);
    else if (same(name, "sceHttpAddRequestHeader") || same(name, "sceHttpAddRequestHeaderRaw"))
        LOG("%s(id=%d %s length=%u mode=%u) rc=%08X", name, (int)a[0], a[1] ? (const char *)a[1] : "(null)",
            a[2] ? length_of((const char *)a[2]) : 0, a[3], result);
    else if (same(name, "sceHttpRemoveRequestHeader"))
        LOG("%s(id=%d %s) rc=%08X", name, (int)a[0], a[1] ? (const char *)a[1] : "(null)", result);
    else if (same(name, "sceHttpSendRequest"))
        LOG("%s(req=%d size=%u) rc=%08X", name, (int)a[0], a[2], result);
    else if (same(name, "sceHttpGetStatusCode"))
        LOG("%s(req=%d) rc=%08X status=%d", name, (int)a[0], result, rc >= 0 && a[1] ? *(const int *)a[1] : 0);
    else if (same(name, "sceHttpGetAllResponseHeaders")) {
        const char *header = rc >= 0 && a[1] ? *(const char *const *)a[1] : 0;
        unsigned size = rc >= 0 && a[2] ? *(const unsigned *)a[2] : 0;
        LOG("%s(req=%d) rc=%08X size=%u", name, (int)a[0], result, size);
        /* The text, a line at a time, as vitals-http logs it ("got ...") */
        for (unsigned at = 0; header != 0 && at < size && header[at] != '\0';) {
            unsigned end = at;
            while (end < size && header[end] != '\n' && header[end] != '\0')
                ++end;
            unsigned line = end > at && header[end - 1] == '\r' ? end - 1 - at : end - at;
            if (line != 0) {
                if (starts(header + at, "Set-Cookie:") || starts(header + at, "Cookie:") ||
                    starts(header + at, "Authorization:") || names_token(header + at, line))
                    LOG("  got %.10s... (%u bytes)", header + at, line);
                else
                    LOG("  got %.*s", (int)line, header + at);
            }
            at = end + 1;
        }
        if (header != 0 && size != 0)
            LOG("  last byte 0x%02X, NUL at %u", (unsigned char)header[size - 1], length_of(header));
    } else if (same(name, "sceHttpParseResponseHeader")) {
        const char *value = rc >= 0 && a[3] ? *(const char *const *)a[3] : 0;
        unsigned value_length = rc >= 0 && a[4] ? *(const unsigned *)a[4] : 0;
        LOG("%s(len=%u field=%s) rc=%d value_offset=%d length=%u", name, a[1], (const char *)a[2], rc,
            value ? (int)(value - (const char *)a[0]) : -1, value_length);
    } else if (same(name, "sceHttpReadData")) {
        LOG("%s(req=%d size=%u) rc=%d", name, (int)a[0], a[2], rc);
        /* Only short bodies: a longer one may hold a token */
        if (rc > 0 && rc <= 32)
            log_hex("data", (const unsigned char *)a[1], (unsigned)rc);
    } else if (same(name, "sceHttpGetResponseContentLength"))
        LOG("%s(req=%d) rc=%08X length=%u", name, (int)a[0], result,
            rc >= 0 && a[1] ? (unsigned)*(const unsigned long long *)a[1] : 0);
    /* Only sizes: the Store escapes the account's email and password */
    else if (same(name, "sceHttpUriEscape"))
        LOG("%s(length=%u prepare=%u out=%s require=%s) rc=%08X", name, length_of((const char *)a[3]), a[2],
            a[0] ? "yes" : "no", a[1] ? "yes" : "no", result);
    else
        LOG("%s(%08X %08X %08X %08X %08X) rc=%08X", name, a[0], a[1], a[2], a[3], a[4], result);
}

/* Every hook: the PSN host swapped on the way in, then the call, then the log */
static uint32_t forward(unsigned slot, unsigned index, uint32_t *a)
{
    char url[512];
    uint32_t nid = g_functions[index].nid;
    const char *name = g_functions[index].name;
    if (same(name, "sceHttpCreateConnection") && a[1] != 0 && same((const char *)a[1], OLD_HOST)) {
        LOG("redirect %s -> %s", OLD_HOST, NEW_HOST);
        a[1] = (uint32_t)NEW_HOST;
    }
    if ((same(name, "sceHttpCreateConnectionWithURL") && a[1] != 0) ||
        ((same(name, "sceHttpCreateRequestWithURL") || same(name, "sceHttpCreateRequestWithURL2")) && a[2] != 0)) {
        unsigned arg = same(name, "sceHttpCreateConnectionWithURL") ? 1 : 2;
        const char *rewritten = redirect_url((const char *)a[arg], url, sizeof(url));
        if (rewritten != 0) {
            LOG("redirect %s -> %s", (const char *)a[arg], rewritten);
            a[arg] = (uint32_t)rewritten;
        }
    }
    (void)nid;
    uint32_t result = TAI_CONTINUE(uint32_t, g_refs[slot][index], a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    log_call(index, a, result);
    return result;
}

/* One hook function per module slot and SceHttp function, each with its own reference */
#define DEFINE_HOOK(slot, index)                                                                    \
    static uint32_t hook_##slot##_##index(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, \
                                          uint32_t a5, uint32_t a6, uint32_t a7)                    \
    {                                                                                               \
        uint32_t a[8] = {a0, a1, a2, a3, a4, a5, a6, a7};                                           \
        return forward(slot, index, a);                                                             \
    }
#define DEFINE_HOOK_0(index) DEFINE_HOOK(0, index)
#define DEFINE_HOOK_1(index) DEFINE_HOOK(1, index)
#define DEFINE_HOOK_2(index) DEFINE_HOOK(2, index)
#define DEFINE_HOOK_3(index) DEFINE_HOOK(3, index)
#define DEFINE_HOOK_4(index) DEFINE_HOOK(4, index)
#define DEFINE_HOOK_5(index) DEFINE_HOOK(5, index)
#define DEFINE_HOOK_6(index) DEFINE_HOOK(6, index)
#define DEFINE_HOOK_7(index) DEFINE_HOOK(7, index)
#define DEFINE_HOOK_8(index) DEFINE_HOOK(8, index)
#define DEFINE_HOOK_9(index) DEFINE_HOOK(9, index)
#define DEFINE_HOOK_10(index) DEFINE_HOOK(10, index)
#define DEFINE_HOOK_11(index) DEFINE_HOOK(11, index)
DIAG_HOOKS(DEFINE_HOOK_0)
DIAG_HOOKS(DEFINE_HOOK_1)
DIAG_HOOKS(DEFINE_HOOK_2)
DIAG_HOOKS(DEFINE_HOOK_3)
DIAG_HOOKS(DEFINE_HOOK_4)
DIAG_HOOKS(DEFINE_HOOK_5)
DIAG_HOOKS(DEFINE_HOOK_6)
DIAG_HOOKS(DEFINE_HOOK_7)
DIAG_HOOKS(DEFINE_HOOK_8)
DIAG_HOOKS(DEFINE_HOOK_9)
DIAG_HOOKS(DEFINE_HOOK_10)
DIAG_HOOKS(DEFINE_HOOK_11)

#define LIST_HOOK_0(index) (const void *)hook_0_##index,
#define LIST_HOOK_1(index) (const void *)hook_1_##index,
#define LIST_HOOK_2(index) (const void *)hook_2_##index,
#define LIST_HOOK_3(index) (const void *)hook_3_##index,
#define LIST_HOOK_4(index) (const void *)hook_4_##index,
#define LIST_HOOK_5(index) (const void *)hook_5_##index,
#define LIST_HOOK_6(index) (const void *)hook_6_##index,
#define LIST_HOOK_7(index) (const void *)hook_7_##index,
#define LIST_HOOK_8(index) (const void *)hook_8_##index,
#define LIST_HOOK_9(index) (const void *)hook_9_##index,
#define LIST_HOOK_10(index) (const void *)hook_10_##index,
#define LIST_HOOK_11(index) (const void *)hook_11_##index,
static const void *const g_hook_functions[SLOTS][DIAG_FUNCTION_COUNT] = {
    {DIAG_HOOKS(LIST_HOOK_0)},  {DIAG_HOOKS(LIST_HOOK_1)},  {DIAG_HOOKS(LIST_HOOK_2)},
    {DIAG_HOOKS(LIST_HOOK_3)},  {DIAG_HOOKS(LIST_HOOK_4)},  {DIAG_HOOKS(LIST_HOOK_5)},
    {DIAG_HOOKS(LIST_HOOK_6)},  {DIAG_HOOKS(LIST_HOOK_7)},  {DIAG_HOOKS(LIST_HOOK_8)},
    {DIAG_HOOKS(LIST_HOOK_9)},  {DIAG_HOOKS(LIST_HOOK_10)}, {DIAG_HOOKS(LIST_HOOK_11)},
};

static SceUID g_ssl_hooks[SSL_SLOTS][DIAG_SSL_COUNT];
static tai_hook_ref_t g_ssl_refs[SSL_SLOTS][DIAG_SSL_COUNT];

/* A libssl call: logged with its first five words and result */
static uint32_t ssl_forward(unsigned slot, unsigned index, const uint32_t *a)
{
    uint32_t result = TAI_CONTINUE(uint32_t, g_ssl_refs[slot][index], a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    LOG("ssl %s(%08X %08X %08X %08X %08X) rc=%08X", g_ssl_functions[index].name, a[0], a[1], a[2], a[3], a[4], result);
    return result;
}

#define DEFINE_SSL_HOOK(slot, index)                                                                \
    static uint32_t ssl_hook_##slot##_##index(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,     \
                                              uint32_t a4, uint32_t a5, uint32_t a6, uint32_t a7)     \
    {                                                                                               \
        uint32_t a[8] = {a0, a1, a2, a3, a4, a5, a6, a7};                                           \
        return ssl_forward(slot, index, a);                                                         \
    }
#define DEFINE_SSL_HOOK_0(index) DEFINE_SSL_HOOK(0, index)
#define DEFINE_SSL_HOOK_1(index) DEFINE_SSL_HOOK(1, index)
#define DEFINE_SSL_HOOK_2(index) DEFINE_SSL_HOOK(2, index)
#define DEFINE_SSL_HOOK_3(index) DEFINE_SSL_HOOK(3, index)
DIAG_SSL_HOOKS(DEFINE_SSL_HOOK_0)
DIAG_SSL_HOOKS(DEFINE_SSL_HOOK_1)
DIAG_SSL_HOOKS(DEFINE_SSL_HOOK_2)
DIAG_SSL_HOOKS(DEFINE_SSL_HOOK_3)
#define LIST_SSL_HOOK_0(index) (const void *)ssl_hook_0_##index,
#define LIST_SSL_HOOK_1(index) (const void *)ssl_hook_1_##index,
#define LIST_SSL_HOOK_2(index) (const void *)ssl_hook_2_##index,
#define LIST_SSL_HOOK_3(index) (const void *)ssl_hook_3_##index,
static const void *const g_ssl_hook_functions[SSL_SLOTS][DIAG_SSL_COUNT] = {
    {DIAG_SSL_HOOKS(LIST_SSL_HOOK_0)}, {DIAG_SSL_HOOKS(LIST_SSL_HOOK_1)},
    {DIAG_SSL_HOOKS(LIST_SSL_HOOK_2)}, {DIAG_SSL_HOOKS(LIST_SSL_HOOK_3)},
};

static unsigned hook_ssl_module(unsigned slot, const char *module)
{
    unsigned hooked = 0;
    for (unsigned i = 0; i < DIAG_SSL_COUNT; ++i) {
        g_ssl_hooks[slot][i] = taiHookFunctionImport(&g_ssl_refs[slot][i], module, g_ssl_functions[i].library,
                                                     g_ssl_functions[i].nid, g_ssl_hook_functions[slot][i]);
        if (g_ssl_hooks[slot][i] >= 0)
            ++hooked;
    }
    return hooked;
}

/* ---- NP: every function the module imports from a SceNp* library, found in its import table ---- */

#define NP_MAX 256
typedef uint64_t (*Forward64)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
static struct
{
    char module[32];
    const char *library;
    uint32_t library_nid, nid;
    SceUID hook;
    tai_hook_ref_t ref;
} g_np[NP_MAX];
static unsigned g_np_count;

/* What a buffer holds, with every byte masked: '*' printable, '.' zero, '#' anything else; shows
 * which fields are filled and how long, never what they say */
static void log_shape(const char *label, const unsigned char *data, unsigned size)
{
    /* No further than the end of the buffer's page: the next one may not be mapped */
    unsigned left = 0x1000u - ((uintptr_t)data & 0xFFFu);
    if (size > left)
        size = left;
    char line[64 + 1];
    for (unsigned at = 0; at < size; at += 64) {
        unsigned n = size - at < 64 ? size - at : 64;
        for (unsigned i = 0; i < n; ++i) {
            unsigned char c = data[at + i];
            line[i] = c == 0 ? '.' : c >= 0x20 && c < 0x7f ? '*' : '#';
        }
        line[n] = '\0';
        LOG("  %s +%03X %s", label, at, line);
    }
}

static uintptr_t g_c2_text, g_c2_data;
static void log_contexts(const char *when);

/* Both result registers are kept, as some NP functions return 64-bit values */
static uint64_t np_forward(unsigned index, const uint32_t *a)
{
    int commerce = same(g_np[index].library, "SceNpCommerce2");
    uint64_t result = TAI_CONTINUE(uint64_t, g_np[index].ref, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    LOG("np %s %s/%08X(%08X %08X %08X %08X) rc=%08X", g_np[index].module, g_np[index].library, g_np[index].nid, a[0],
        a[1], a[2], a[3], (uint32_t)result);
    if (commerce && g_c2_data != 0)
        log_contexts("after");
    /* The account call the Store makes before it fails: the shape of what it wrote back */
    if (g_np[index].nid == 0xB24FC028) {
        if (a[0] >= 0x81000000u && a[0] < 0xA0000000u)
            log_shape("arg0", (const unsigned char *)a[0], 256);
        if (a[1] >= 0x81000000u && a[1] < 0xA0000000u)
            log_shape("arg1", (const unsigned char *)a[1], 256);
    }
    return result;
}

#define DEFINE_NP_HOOK(index)                                                                          \
    static uint64_t np_hook_##index(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,     \
                                    uint32_t a5, uint32_t a6, uint32_t a7)                               \
    {                                                                                                  \
        uint32_t a[8] = {a0, a1, a2, a3, a4, a5, a6, a7};                                              \
        return np_forward(index, a);                                                                   \
    }
#define NP_HOOKS(X) \
    X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15) \
    X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31) \
    X(32) X(33) X(34) X(35) X(36) X(37) X(38) X(39) X(40) X(41) X(42) X(43) X(44) X(45) X(46) X(47) \
    X(48) X(49) X(50) X(51) X(52) X(53) X(54) X(55) X(56) X(57) X(58) X(59) X(60) X(61) X(62) X(63) \
    X(64) X(65) X(66) X(67) X(68) X(69) X(70) X(71) X(72) X(73) X(74) X(75) X(76) X(77) X(78) X(79) \
    X(80) X(81) X(82) X(83) X(84) X(85) X(86) X(87) X(88) X(89) X(90) X(91) X(92) X(93) X(94) X(95) \
    X(96) X(97) X(98) X(99) X(100) X(101) X(102) X(103) X(104) X(105) X(106) X(107) X(108) X(109) X(110) X(111) \
    X(112) X(113) X(114) X(115) X(116) X(117) X(118) X(119) X(120) X(121) X(122) X(123) X(124) X(125) X(126) X(127) \
    X(128) X(129) X(130) X(131) X(132) X(133) X(134) X(135) X(136) X(137) X(138) X(139) X(140) X(141) X(142) X(143) \
    X(144) X(145) X(146) X(147) X(148) X(149) X(150) X(151) X(152) X(153) X(154) X(155) X(156) X(157) X(158) X(159) \
    X(160) X(161) X(162) X(163) X(164) X(165) X(166) X(167) X(168) X(169) X(170) X(171) X(172) X(173) X(174) X(175) \
    X(176) X(177) X(178) X(179) X(180) X(181) X(182) X(183) X(184) X(185) X(186) X(187) X(188) X(189) X(190) X(191) \
    X(192) X(193) X(194) X(195) X(196) X(197) X(198) X(199) X(200) X(201) X(202) X(203) X(204) X(205) X(206) X(207) \
    X(208) X(209) X(210) X(211) X(212) X(213) X(214) X(215) X(216) X(217) X(218) X(219) X(220) X(221) X(222) X(223) \
    X(224) X(225) X(226) X(227) X(228) X(229) X(230) X(231) X(232) X(233) X(234) X(235) X(236) X(237) X(238) X(239) \
    X(240) X(241) X(242) X(243) X(244) X(245) X(246) X(247) X(248) X(249) X(250) X(251) X(252) X(253) X(254) X(255)
NP_HOOKS(DEFINE_NP_HOOK)
#define LIST_NP_HOOK(index) (const void *)np_hook_##index,
static const void *const g_np_hook_functions[NP_MAX] = {NP_HOOKS(LIST_NP_HOOK)};

static uint32_t read32(uintptr_t address)
{
    return *(const uint32_t *)address;
}

/* Commerce2's context, session and request lifecycle, as the Store imports it */
static int commerce_logged(uint32_t nid)
{
    static const uint32_t nids[] = {
        0xAA090F5E, /* creates a context */
        0x1EC16D19, /* destroys a context */
        0x25C58D33, 0x8F24F115, 0x1B0B5798, 0x7DE103BB, 0x00F16110,
        0xA4464754, /* sceNpCommerce2DestroyReq */
        0xE7486A60, /* sceNpCommerce2AbortReq */
        0xC73F209A, /* sceNpCommerce2Init */
        0xB99958AE, /* sceNpCommerce2Term */
        0x586B0599, /* sceNpCommerce2GetShortfallOfLibhttpPool */
        0xBA5A5784, /* sceNpCommerce2GetShortfallOfLibsslPool */
    };
    for (unsigned i = 0; i < sizeof(nids) / sizeof(nids[0]); ++i)
        if (nids[i] == nid)
            return 1;
    return 0;
}

/* Walks the module's import table (records of 0x24 or 0x34 bytes) and hooks every function of the
 * SceNpManager and SceNpCommon libraries */
static void hook_np_imports(const char *module)
{
    tai_module_info_t info;
    info.size = sizeof(info);
    if (taiGetModuleInfo(module, &info) < 0)
        return;
    unsigned before = g_np_count;
    for (uintptr_t at = info.imports_start; at + 0x24 <= info.imports_end;) {
        uint16_t size = *(const uint16_t *)at, count = *(const uint16_t *)(at + 6);
        uint32_t library, name, nids;
        if (size == 0x34) {
            library = read32(at + 0x10);
            name = read32(at + 0x14);
            nids = read32(at + 0x1C);
        } else if (size == 0x24) {
            library = read32(at + 0x0C);
            name = read32(at + 0x10);
            nids = read32(at + 0x14);
        } else
            break;
        /* NpManager's and NpCommon's: the sign-in and account functions; of Commerce2's own API,
         * only the context, session and request calls, as hooking all of it crashed the Store */
        int commerce = name != 0 && same((const char *)name, "SceNpCommerce2");
        if (name != 0 && (commerce || same((const char *)name, "SceNpManager") || same((const char *)name, "SceNpCommon")))
            for (unsigned i = 0; i < count && g_np_count < NP_MAX; ++i) {
                unsigned n = g_np_count;
                if (commerce && !commerce_logged(read32(nids + 4 * i)))
                    continue;
                /* A copy: the caller's name is in a buffer that doesn't outlive the scan */
                unsigned c = 0;
                for (; c < sizeof(g_np[n].module) - 1 && module[c] != '\0'; ++c)
                    g_np[n].module[c] = module[c];
                g_np[n].module[c] = '\0';
                g_np[n].library = (const char *)name;
                g_np[n].library_nid = library;
                g_np[n].nid = read32(nids + 4 * i);
                g_np[n].hook = taiHookFunctionImport(&g_np[n].ref, module, library, g_np[n].nid, g_np_hook_functions[n]);
                if (g_np[n].hook >= 0)
                    ++g_np_count;
            }
        at += size;
    }
    LOG("hooked %s: %u NP imports", module, g_np_count - before);
}

/* ---- Commerce2's own context list, from the inside (3.65's SceNpCommerce2 only) ---- */

/* Offsets in SceNpCommerce2's code and data, from a dump of 3.65's: the context lookup, removal and
 * destroy-all functions, and the head of the context list */
#define C2_LOOKUP 0x1D75Eu
#define C2_REMOVE 0x1D826u
#define C2_DESTROY_ALL 0x1D8BCu
#define C2_LIST_HEAD 0x98u
static SceUID g_c2_hooks[3] = {-1, -1, -1};
static tai_hook_ref_t g_c2_refs[3];

/* Every context: its id, references, flags (1: being destroyed) and type */
static void log_contexts(const char *when)
{
    uintptr_t at = *(const uint32_t *)(g_c2_data + C2_LIST_HEAD);
    if (at == 0)
        LOG("  c2 %s: no contexts", when);
    for (unsigned n = 0; at != 0 && n < 8; ++n, at = *(const uint32_t *)at)
        LOG("  c2 %s: ctx id=%u refs=%u flags=%X type=%u requests=%08X", when, *(const uint32_t *)(at + 12),
            *(const uint32_t *)(at + 4), *(const uint32_t *)(at + 16), *(const uint32_t *)(at + 0x538),
            *(const uint32_t *)(at + 32));
}

static uint32_t caller_offset(void *lr)
{
    return (uint32_t)((uintptr_t)lr - g_c2_text);
}

static int c2_lookup_hook(uint32_t manager, uint32_t id, uint32_t out, uint32_t check)
{
    void *lr = __builtin_return_address(0);
    int result = TAI_CONTINUE(int, g_c2_refs[0], manager, id, out, check);
    if (result < 0) {
        LOG("c2 lookup(id=%u check=%u) rc=%08X from +%05X thread=%08X", id, check, result, caller_offset(lr),
            sceKernelGetThreadId());
        log_contexts("after");
    }
    return result;
}

static int c2_remove_hook(uint32_t manager, uint32_t id)
{
    void *lr = __builtin_return_address(0);
    LOG("c2 remove(id=%u) from +%05X thread=%08X", id, caller_offset(lr), sceKernelGetThreadId());
    log_contexts("before");
    int result = TAI_CONTINUE(int, g_c2_refs[1], manager, id);
    LOG("c2 remove(id=%u) rc=%08X", id, result);
    return result;
}

static int c2_destroy_all_hook(uint32_t manager)
{
    void *lr = __builtin_return_address(0);
    LOG("c2 destroy all from +%05X thread=%08X", caller_offset(lr), sceKernelGetThreadId());
    log_contexts("before");
    return TAI_CONTINUE(int, g_c2_refs[2], manager);
}

/* Hooks the three, once the code at each offset is what the dump had there */
static void hook_commerce_internals(void)
{
    tai_module_info_t tai;
    SceKernelModuleInfo info;
    tai.size = sizeof(tai);
    sceClibMemset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    if (taiGetModuleInfo("SceNpCommerce2", &tai) < 0 || sceKernelGetModuleInfo(tai.modid, &info) < 0)
        return;
    g_c2_text = (uintptr_t)info.segments[0].vaddr;
    g_c2_data = (uintptr_t)info.segments[1].vaddr;
    static const struct
    {
        uint32_t offset, first;
        const void *hook;
    } targets[3] = {
        {C2_LOOKUP, 0x41F0E92Du, (const void *)c2_lookup_hook},
        {C2_REMOVE, 0x4FF0E92Du, (const void *)c2_remove_hook},
        {C2_DESTROY_ALL, 0x43F0E92Du, (const void *)c2_destroy_all_hook},
    };
    for (unsigned i = 0; i < 3; ++i) {
        uint32_t first = *(const uint16_t *)(g_c2_text + targets[i].offset) |
                         (uint32_t)*(const uint16_t *)(g_c2_text + targets[i].offset + 2) << 16;
        if (info.segments[0].memsz <= targets[i].offset || first != targets[i].first) {
            LOG("c2 internals: +%05X holds %08X, not hooked", targets[i].offset, first);
            continue;
        }
        g_c2_hooks[i] = taiHookFunctionOffset(&g_c2_refs[i], tai.modid, 0, targets[i].offset, 1, targets[i].hook);
    }
    LOG("c2 internals: text=%08X data=%08X hooks %08X %08X %08X", (unsigned)g_c2_text, (unsigned)g_c2_data,
        g_c2_hooks[0], g_c2_hooks[1], g_c2_hooks[2]);
    log_contexts("now");
}

/* Hooks every SceHttp import of the module; how many took */
static unsigned hook_module(unsigned slot, const char *module)
{
    unsigned hooked = 0;
    for (unsigned i = 0; i < DIAG_FUNCTION_COUNT; ++i) {
        g_hooks[slot][i] = taiHookFunctionImport(&g_refs[slot][i], module, SCE_HTTP_LIBRARY_NID,
                                                 g_functions[i].nid, g_hook_functions[slot][i]);
        if (g_hooks[slot][i] >= 0)
            ++hooked;
    }
    return hooked;
}

/* The modules already looked at (by module UID), and the next free slots */
static SceUID g_seen[MODULES_MAX];
static unsigned g_seen_count, g_slots_used, g_ssl_slots_used;

/* Hooks every module of the process not yet hooked that imports SceHttp */
static void scan(void)
{
    SceUID modules[MODULES_MAX];
    SceSize count = MODULES_MAX;
    if (sceKernelGetModuleList(0xff, modules, &count) < 0)
        return;
    for (SceSize m = 0; m < count && g_seen_count < MODULES_MAX; ++m) {
        unsigned seen = 0;
        for (unsigned s = 0; s < g_seen_count; ++s)
            seen |= g_seen[s] == modules[m];
        if (seen)
            continue;
        g_seen[g_seen_count++] = modules[m];
        SceKernelModuleInfo info;
        sceClibMemset(&info, 0, sizeof(info));
        info.size = sizeof(info);
        /* Only the Store's two resident modules: a shared system module's hooks stop other
         * processes from linking libhttp, and a module unloaded with hooks on it (a dialog plugin)
         * panics the kernel */
        if (sceKernelGetModuleInfo(modules[m], &info) < 0 ||
            !(same(info.module_name, "SceNpCommerce2") || same(info.module_name, "SceStoreBrowser") ||
              same(info.module_name, "SceShell")))
            continue;
        if (g_slots_used < SLOTS) {
            unsigned hooked = hook_module(g_slots_used, info.module_name);
            if (hooked != 0) {
                LOG("hooked %s: %u SceHttp imports", info.module_name, hooked);
                ++g_slots_used;
            }
        }
        if (g_ssl_slots_used < SSL_SLOTS) {
            unsigned hooked = hook_ssl_module(g_ssl_slots_used, info.module_name);
            if (hooked != 0) {
                LOG("hooked %s: %u libssl imports", info.module_name, hooked);
                ++g_ssl_slots_used;
            }
        }
        /* NP only in the Store's modules: the shell calls NP far too often */
        if (!same(info.module_name, "SceShell"))
            hook_np_imports(info.module_name);
    }
}

int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));
int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    for (unsigned s = 0; s < SLOTS; ++s)
        for (unsigned i = 0; i < DIAG_FUNCTION_COUNT; ++i)
            g_hooks[s][i] = -1;
    for (unsigned s = 0; s < SSL_SLOTS; ++s)
        for (unsigned i = 0; i < DIAG_SSL_COUNT; ++i)
            g_ssl_hooks[s][i] = -1;
    LOG("start: build=%u", g_build);
    scan();
    hook_commerce_internals();
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    for (unsigned s = 0; s < SLOTS; ++s)
        for (unsigned i = 0; i < DIAG_FUNCTION_COUNT; ++i)
            if (g_hooks[s][i] >= 0)
                taiHookRelease(g_hooks[s][i], g_refs[s][i]);
    for (unsigned s = 0; s < SSL_SLOTS; ++s)
        for (unsigned i = 0; i < DIAG_SSL_COUNT; ++i)
            if (g_ssl_hooks[s][i] >= 0)
                taiHookRelease(g_ssl_hooks[s][i], g_ssl_refs[s][i]);
    for (unsigned i = 0; i < g_np_count; ++i)
        taiHookRelease(g_np[i].hook, g_np[i].ref);
    for (unsigned i = 0; i < 3; ++i)
        if (g_c2_hooks[i] >= 0)
            taiHookRelease(g_c2_hooks[i], g_c2_refs[i]);
    return SCE_KERNEL_STOP_SUCCESS;
}
