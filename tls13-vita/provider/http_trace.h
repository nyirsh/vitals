#ifndef VITALS_HTTP_TRACE_H
#define VITALS_HTTP_TRACE_H

/* Trace of a game's public sceHttp calls on the debug console, from debug level 1 */
#if defined(VITALS_DEBUG) && VITALS_DEBUG >= 1
void vitals_http_trace_install(void);
void vitals_http_trace_release(void);
#else
static inline void vitals_http_trace_install(void) {}
static inline void vitals_http_trace_release(void) {}
#endif

#endif
