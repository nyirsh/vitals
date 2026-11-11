/* The boot notification's TLS and HTTP lines when the XMB's own TLS is built in (VITALS_XMB): included
 * by vitals-boot/src/boot.c at the place they're used, on its Text, add, concern, g_ssl, g_http and
 * g_xmb. Its own build's lines, without the XMB, are boot.c's */

/* Why the XMB's TLS isn't on, after "Games only" or "Off": nothing when Options turned it off */
static void add_xmb_reason(Text *text)
{
	switch (g_xmb) {
	case XMB_LEFT_OUT:
		add(text, " (XMB: the console wasn't turned off properly)");
		break;
	case XMB_OTHER:
		add(text, " (XMB: not 4.93's)");
		break;
	case XMB_TOO_LATE:
		add(text, " (XMB: it started its own first)");
		break;
	case XMB_DRY_RUN:
		add(text, " (XMB: dry run, see vitals.log)");
		break;
	case XMB_PENDING:
		add(text, " (XMB: still loading)");
		break;
	case XMB_FAILED:
		add(text, " (XMB failed, see vitals.log)");
		concern(TROUBLE);
		break;
	default:
		break;
	}
}

/* The TLS line: games' (libssl's redirection) and the XMB's own together: On when both are, Games
 * only or XMB only when one is, Off when neither, with why when it wasn't Options */
static void add_tls(Text *text)
{
	if (g_xmb == XMB_PENDING)
		g_xmb = vitals_xmb_state();
	int games = g_ssl == ON, xmb = g_xmb == XMB_ON;
	add(text, "\nTLS: ");
	if (games && xmb) {
		add(text, "On");
		return;
	}
	concern(CAUTION);
	if (games) {
		add(text, "Games only");
		add_xmb_reason(text);
	} else if (xmb) {
		add(text, "XMB only");
		add_games_reason(text);
	} else {
		add(text, "Off");
		/* Not installed says it for both */
		add_games_reason(text);
		if (g_ssl != OFF_MISSING)
			add_xmb_reason(text);
	}
}

/* The HTTP line, as the TLS one: games' (libhttp's redirection) and the XMB's own together */
static void add_http(Text *text)
{
	int xmb_state = vitals_xmb_http_state();
	int games = g_http == ON, xmb = xmb_state == XMB_ON;
	add(text, "\nHTTP: ");
	if (games && xmb) {
		add(text, "On");
		return;
	}
	concern(CAUTION);
	const char *why = xmb_state == XMB_FAILED     ? " (XMB failed, see vitals.log)"
	                  : xmb_state == XMB_TOO_LATE ? " (XMB: it started its own first)"
	                  : xmb_state == XMB_OTHER    ? " (XMB: not 4.93's)"
	                  : xmb_state == XMB_PENDING  ? " (XMB: still loading)"
	                  : xmb_state == XMB_DRY_RUN  ? " (XMB: dry run, see vitals.log)"
	                  : xmb_state == XMB_LEFT_OUT ? " (XMB: the console wasn't turned off properly)"
	                  : xmb_state == XMB_NEEDS_TLS ? " (XMB: its TLS is Sony's)"
	                                              : "";
	if (xmb_state == XMB_FAILED)
		concern(TROUBLE);
	if (games) {
		add(text, "Games only");
		add(text, why);
	} else if (xmb) {
		add(text, "XMB only");
	} else {
		add(text, g_http == OFF_MISSING ? "Off (not installed)" : g_http == OFF_FAILED ? "Off (not mapped, see vitals.log)" : "Off");
		if (g_http != OFF_MISSING && g_http != OFF_FAILED)
			add(text, why);
	}
}
