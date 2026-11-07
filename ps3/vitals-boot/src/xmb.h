#ifndef VITALS_BOOT_XMB_H
#define VITALS_BOOT_XMB_H

/* vitals' TLS for the XMB itself (xmb.c): what this boot did, for the popup */
enum {
	XMB_NONE,      /* not tried: vitals' libssl isn't on (tls.off, or not installed) */
	XMB_ON,        /* the XMB's 114 SSL functions go to vitals' libssl */
	XMB_OFF,       /* xmb-tls.off is there (xmb-http.off, for the HTTP state) */
	XMB_LEFT_OUT,  /* the last boot didn't end properly */
	XMB_OTHER,     /* not 4.93's XMB, as tools/vsh_ssl.py read it: nothing written */
	XMB_TOO_LATE,  /* the XMB had started SSL already: nothing written */
	XMB_FAILED,    /* see vitals.log; the XMB's own SSL-C stays */
	XMB_DRY_RUN,   /* built with VITALS_XMB_DRY_RUN: checked and loaded, nothing written */
	XMB_PENDING,   /* its thread is loading vitals' libssl */
	XMB_NEEDS_TLS  /* HTTP only: the XMB's SSL stays its own (xmb-tls.off), so its libhttp does */
};

/* Puts vitals' libssl in the XMB's SSL-C's place, unless xmb-tls.off is there or cut_short (the last
 * boot didn't end properly): the checks here, the loading and the writing on a thread of its own
 * (XMB_PENDING), as a module can't load another from its module_start; else one of the above */
int vitals_xmb_start(int cut_short);
/* What it did: XMB_PENDING while the thread runs */
int vitals_xmb_state(void);
/* The same for the XMB's libhttp, which follows its SSL (XMB_NONE when it wasn't tried: no libhttp
 * of vitals', or the XMB's SSL not vitals') */
int vitals_xmb_http_state(void);

#endif
