/* The vitals app, the same on every console (app.h): one menu to install, update, reinstall or remove
 * vitals, turn its parts on and off and pick its debug output, update its certificates, run the
 * connection test and read the changelog and the credits. What's under it is each console's
 * (console.h, platform.h, check.h) */

#include "app.h"

#include "vitals/log.h"
#include "changelog.h"
#include "check.h"
#include "console.h"
#include "switches.h"
#include "font.h"
#include "input.h"
#include "platform.h"
#include "release_check.h"
#include "release_version.h"
#include "ui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum Action {
	ACTION_INSTALL,
	ACTION_UPDATE,
	ACTION_REINSTALL,
	ACTION_UNINSTALL,
	ACTION_CERTIFICATES,
	ACTION_OPTIONS,
	ACTION_TEST,
	ACTION_CHANGELOG,
	ACTION_CREDITS,
	ACTION_EXIT
};

/* The Install item's description is the console's (console_words) */
static const AppMenuItem action_items[] = {
    [ACTION_INSTALL] = {"Install", NULL, NULL, 0},
    [ACTION_UPDATE] = {"Update", "Replaces the installed vitals with the version this app carries", NULL, 0},
    [ACTION_REINSTALL] = {"Reinstall", "Use this to either update versions or fix a broken installation", NULL, 0},
    [ACTION_UNINSTALL] = {"Uninstall", "Removes all of the installed files", NULL, 0},
    [ACTION_CERTIFICATES] = {"Update certificates", "Downloads the latest trusted websites certificates", NULL, 0},
    [ACTION_OPTIONS] = {"Options", "Turns each part of vitals on or off, and picks the debug output", NULL, 0},
    [ACTION_TEST] = {"Test connections", "Checks that everything is working as expected", NULL, 0},
    [ACTION_CHANGELOG] = {"Changelog", "What changed in each version of vitals", NULL, 0},
    [ACTION_CREDITS] = {"Credits", "The people and projects vitals is built on", NULL, 0},
    [ACTION_EXIT] = {"Exit", "", NULL, 0},
};

static AppMenuItem item(enum Action action)
{
	AppMenuItem i = action_items[action];
	if (action == ACTION_INSTALL)
		i.description = console_words()->install_description;
	return i;
}

static const char *const debug_names[VITALS_DEBUG_LEVEL_COUNT] = {"Off", "Basic debug", "Full debug"};

static uint32_t *canvas;
static unsigned held = ~0u;
static unsigned confirm_button = PAD_CROSS, back_button = PAD_CIRCLE;
/* debug_level is the installed level, -1 without an install; known_level the level the console has
 * recorded, which an install keeps, 0 when none is */
static int installed, outdated, debug_level = -1, debug_choice, known_level;
static char installed_version[16];
static char certificates_updated[40];
/* The certificates on the console are more than three months old */
static int certificates_stale;

/* A newer published release than this app, once the console's check found one; NULL otherwise */
static const char *newer_release(void)
{
	const char *latest = release_check_latest();
	return latest != NULL && vitals_release_newer(latest, VITALS_VERSION) == 1 ? latest : NULL;
}

static AppStatus status(void)
{
	AppStatus s = {installed, outdated, installed_version,
	               installed && !outdated && debug_level > 0 ? debug_names[debug_level] : NULL, console_system_text(),
	               newer_release(), release_check_searching()};
	return s;
}

static void refresh_state(void)
{
	installed = vitals_install_detect();
	int level = 0, known = vitals_install_read(installed_version, sizeof(installed_version), &level) == 0;
	if (!known) {
		installed_version[0] = '\0';
		level = 0;
	}
	outdated = installed && strcmp(installed_version, VITALS_VERSION) != 0;
	debug_level = installed ? level : -1;
	VITALS_LOG_ALWAYS("state: installed %d, version \"%s\", outdated %d, debug %d", installed, installed_version, outdated, level);
	/* An install, reinstall or update keeps the debug output the console has, whenever it's known,
	 * also for an install the app doesn't count as complete */
	known_level = known ? level : 0;
	debug_choice = known_level;
	vitals_certificates_date(certificates_updated, sizeof(certificates_updated), &certificates_stale);
}

/* Buttons newly pressed since the last call, with the sticks */
static unsigned read_presses(PadState *state)
{
	PadState now = platform_pad_read();
	unsigned pressed = now.buttons & ~held;
	held = now.buttons;
	if (state != NULL)
		*state = now;
	return pressed;
}

/* ---- operations ---- */

#define TASK_MAX_LINES 64
static char task_lines[TASK_MAX_LINES][160];
static const char *task_line_pointers[TASK_MAX_LINES];
static AppTask task;

/* While an operation runs: the console must stay on */
static AppHint waiting_hint;

static void wait_hint(void)
{
	static char text[64];
	snprintf(text, sizeof(text), "Please wait and keep your %s turned on.", console_words()->name);
	waiting_hint = (AppHint){APP_GLYPH_NONE, APP_GLYPH_NONE, text};
	task.hints = &waiting_hint;
	task.hint_count = 1;
}

static void draw_task(void)
{
	task.status = status();
	app_draw_task(canvas, &task);
	platform_present(canvas);
}

static void task_note(const char *line)
{
	if (task.count == TASK_MAX_LINES) {
		memmove(task_lines[0], task_lines[1], sizeof(task_lines[0]) * (TASK_MAX_LINES - 1));
		--task.count;
	}
	snprintf(task_lines[task.count++], sizeof(task_lines[0]), "%s", line);
	draw_task();
}

/* Runs an operation, shows how it went, and offers a reboot when it needs one */
static int run_operation(enum Action action)
{
	static const char *const titles[] = {
	    [ACTION_INSTALL] = "Installing vitals",       [ACTION_UPDATE] = "Updating vitals",
	    [ACTION_REINSTALL] = "Reinstalling vitals",   [ACTION_UNINSTALL] = "Uninstalling vitals",
	    [ACTION_CERTIFICATES] = "Updating certificates",
	};
	char status_line[120];
	for (unsigned i = 0; i < TASK_MAX_LINES; ++i)
		task_line_pointers[i] = task_lines[i];
	task = (AppTask){.title = titles[action], .lines = task_line_pointers, .state = CHECK_RUNNING, .status_line = "Working..."};
	wait_hint();
	draw_task();
	/* The test's thread and libraries are done with first, so nothing of vitals' is in use */
	vitals_check_stop();
	int result;
	if (action == ACTION_UNINSTALL)
		result = vitals_uninstall_run(task_note);
	else if (action == ACTION_CERTIFICATES)
		result = vitals_update_certificates(task_note);
	else
		result = vitals_install_run(debug_choice, task_note);
	int reboot = result >= 0 && action != ACTION_CERTIFICATES;
	/* START reboots, as on the Options screen */
	static const AppHint reboot_hints[] = {{APP_GLYPH_START, APP_GLYPH_NONE, "Reboot now"}, {APP_GLYPH_BACK, APP_GLYPH_NONE, "Later"}};
	task.hints = NULL;
	task.hint_count = 0;
	if (result >= 0) {
		task.state = CHECK_PASS;
		task.status_line = reboot ? (action == ACTION_UNINSTALL ? "Done. Reboot the console to stop vitals."
		                                                        : "Done. Reboot the console to start vitals.")
		                          : "Done. Games started from now on use it.";
		if (reboot) {
			task.hints = reboot_hints;
			task.hint_count = 2;
		}
	} else {
		snprintf(status_line, sizeof(status_line), "Failed (0x%08X). Nothing needs a reboot.", (unsigned)result);
		task.state = CHECK_FAIL;
		task.status_line = status_line;
	}
	VITALS_LOG_ALWAYS("%s: %d", titles[action], result);
	refresh_state();
	draw_task();
	for (;;) {
		if (platform_exit_requested())
			return -1;
		unsigned pressed = read_presses(NULL);
		if (reboot && (pressed & PAD_START)) {
			task.status_line = "Rebooting...";
			draw_task();
			vitals_reboot();
		}
		if (pressed & back_button)
			return 0;
		platform_sleep_ms(30);
	}
}

/* ---- Options: the console's switches (console.h) and the debug output ---- */

/* At most this many switches, then the debug output */
#define SWITCH_MAX 8

#define APPLY_REBOOT_SECONDS 3

/* What Options chose, written while its steps show as an operation's do: each switch that changed,
 * then the debug output's builds when the level changed; when all of it worked, the console reboots
 * after APPLY_REBOOT_SECONDS. Returns -1 when the system asks the app to quit, else 0 (after a
 * failure, once Back is pressed) */
static int run_apply_options(unsigned switch_count, const unsigned *state, const unsigned *saved, unsigned log_state,
                             unsigned log_saved)
{
	for (unsigned i = 0; i < TASK_MAX_LINES; ++i)
		task_line_pointers[i] = task_lines[i];
	task = (AppTask){.title = "Applying options", .lines = task_line_pointers, .state = CHECK_RUNNING, .status_line = "Working..."};
	wait_hint();
	draw_task();
	vitals_check_stop();
	int result = 0, changed = 0;
	char line[160];
	for (unsigned i = 0; i < switch_count && result >= 0; ++i) {
		if (state[i] == saved[i])
			continue;
		changed = 1;
		int rc = switch_apply(console_switch(i), state[i], console_flag_set, line, sizeof(line));
		task_note(line);
		VITALS_LOG_ALWAYS("options: %s (0x%08X)", line, (unsigned)rc);
		if (rc != 0)
			result = rc;
	}
	if (result >= 0 && log_state != log_saved) {
		changed = 1;
		result = switch_apply(console_log_switch(), log_state, console_flag_set, line, sizeof(line));
		task_note(line);
		VITALS_LOG_ALWAYS("options: %s (0x%08X)", line, (unsigned)result);
	}
	if (result >= 0 && debug_choice != debug_level) {
		changed = 1;
		result = vitals_install_set_debug_level(debug_choice, task_note);
		VITALS_LOG_ALWAYS("options: debug output %d: %d", debug_choice, result);
	}
	if (!changed)
		task_note("Nothing changed");
	refresh_state();
	task.hints = NULL;
	task.hint_count = 0;
	if (result != 0) {
		static char failed[120];
		snprintf(failed, sizeof(failed), "Failed (0x%08X). No reboot was requested.", (unsigned)result);
		task.state = CHECK_FAIL;
		task.status_line = failed;
		draw_task();
		for (;;) {
			if (platform_exit_requested())
				return -1;
			if (read_presses(NULL) & back_button)
				return 0;
			platform_sleep_ms(30);
		}
	}
	task.state = CHECK_PASS;
	static const AppHint rebooting = {APP_GLYPH_NONE, APP_GLYPH_NONE, "The console reboots by itself."};
	task.hints = &rebooting;
	task.hint_count = 1;
	task.status_line = "Done. Rebooting in 3 seconds...";
	draw_task();
	for (unsigned waited = 0; waited < APPLY_REBOOT_SECONDS * 1000; waited += 50) {
		if (platform_exit_requested())
			return -1;
		platform_sleep_ms(50);
	}
	VITALS_LOG_ALWAYS("options: reboot");
	vitals_reboot();
	return 0;
}

/* The Options screen: Left and Right go through a switch's states (On, then the others, Off last) and
 * the debug output's levels here only; START applies all of it and reboots (run_apply_options), and
 * Back leaves the console as it was. A choice that is the one on the console now says "(current)" */
static int run_options(void)
{
	unsigned switch_count = console_switch_count();
	if (switch_count > SWITCH_MAX)
		switch_count = SWITCH_MAX;
	/* The switches, then the debug output, then where its lines go while it isn't Off */
	const ConsoleSwitch *logs = console_log_switch();
	const unsigned debug_option = switch_count, log_option = switch_count + 1;
	unsigned selected = 0, log_saved = switch_state(logs, console_flag_exists), log_state = log_saved;
	int redraw = 1;
	CheckScrollRepeat repeat = {0};
	/* What the console has (saved) and what this screen has chosen (state) */
	unsigned saved[SWITCH_MAX], state[SWITCH_MAX];
	for (unsigned i = 0; i < switch_count; ++i)
		saved[i] = state[i] = switch_state(console_switch(i), console_flag_exists);
	for (;;) {
		const unsigned option_count = debug_choice != 0 ? log_option + 1 : log_option;
		AppMenuItem items[SWITCH_MAX + 2];
		for (unsigned i = 0; i < switch_count; ++i) {
			const ConsoleSwitch *s = console_switch(i);
			const ConsoleSwitchState *chosen = &s->states[state[i]];
			items[i] = (AppMenuItem){s->label, chosen->meaning, chosen->name, state[i] == saved[i], state[i] == 0,
			                         state[i] + 1 == s->state_count,
			                         chosen->tone == CONSOLE_TONE_RED      ? APP_TONE_RED
			                         : chosen->tone == CONSOLE_TONE_ORANGE ? APP_TONE_ORANGE
			                                                               : APP_TONE_USUAL,
			                         NULL, 0};
		}
		items[debug_option] = (AppMenuItem){"Debug output", console_words()->debug_purposes[debug_choice], debug_names[debug_choice],
		                                    debug_choice == debug_level, debug_choice == 0,
		                                    debug_choice == VITALS_DEBUG_LEVEL_COUNT - 1,
		                                    debug_choice == 2   ? APP_TONE_RED
		                                    : debug_choice == 1 ? APP_TONE_ORANGE
		                                                        : APP_TONE_USUAL,
		                                    NULL, 0};
		const ConsoleSwitchState *log_chosen = &logs->states[log_state];
		items[log_option] = (AppMenuItem){logs->label, log_chosen->meaning, log_chosen->name, log_state == log_saved, log_state == 0,
		                                  log_state + 1 == logs->state_count, APP_TONE_USUAL, NULL, 0};
		if (redraw) {
			static const AppHint hints[] = {
			    {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Choose"},
			    {APP_GLYPH_START, APP_GLYPH_NONE, "Apply and reboot"},
			    {APP_GLYPH_BACK, APP_GLYPH_NONE, "Back"},
			};
			AppOptions view = {status(), items, option_count, selected, hints, sizeof(hints) / sizeof(hints[0])};
			app_draw_options(canvas, &view);
			platform_present(canvas);
			redraw = 0;
		}
		if (platform_exit_requested())
			return -1;
		PadState pad;
		unsigned pressed = read_presses(&pad);
		int direction = check_scroll_direction(pad.buttons & PAD_UP, pad.buttons & PAD_DOWN, pad.left_y, pad.right_y);
		int steps = check_scroll_repeat(&repeat, direction, platform_now_ms());
		if (steps != 0) {
			int next = (int)selected + steps;
			selected = next < 0 ? 0 : next >= (int)option_count ? option_count - 1 : (unsigned)next;
			redraw = 1;
		}
		/* Left and Right stop at the ends: a switch's states in order (On first), the levels in order */
		if (selected < switch_count && (pressed & PAD_LEFT) && state[selected] > 0) {
			--state[selected];
			redraw = 1;
		}
		if (selected < switch_count && (pressed & PAD_RIGHT) && state[selected] + 1 < console_switch(selected)->state_count) {
			++state[selected];
			redraw = 1;
		}
		if (selected == debug_option && (pressed & PAD_LEFT) && debug_choice > 0) {
			--debug_choice;
			redraw = 1;
		}
		if (selected == debug_option && (pressed & PAD_RIGHT) && debug_choice < VITALS_DEBUG_LEVEL_COUNT - 1) {
			++debug_choice;
			redraw = 1;
		}
		if (selected == log_option && (pressed & PAD_LEFT) && log_state > 0) {
			--log_state;
			redraw = 1;
		}
		if (selected == log_option && (pressed & PAD_RIGHT) && log_state + 1 < logs->state_count) {
			++log_state;
			redraw = 1;
		}
		if (pressed & PAD_START) {
			if (run_apply_options(switch_count, state, saved, log_state, log_saved) < 0)
				return -1;
			/* After a failure: what the console has now */
			for (unsigned i = 0; i < switch_count; ++i)
				saved[i] = state[i] = switch_state(console_switch(i), console_flag_exists);
			log_saved = log_state = switch_state(logs, console_flag_exists);
			redraw = 1;
		}
		if (pressed & back_button) {
			/* Nothing applied: the level the console has */
			debug_choice = known_level;
			return 0;
		}
		platform_sleep_ms(16);
	}
}

/* ---- the connection test ---- */

static int run_test(int autotest)
{
	static CheckService view, last_view;
	char notice[120] = "", last_notice[120] = "x";
	vitals_check_start();
	int page = 0, leaving = 0, last_page = -1, last_busy = -1, busy = 1;
	/* While a run goes, the page follows the test that's running, until Square or a scroll takes over */
	int following = 1;
	unsigned scroll = 0, last_scroll = ~0u;
	CheckScrollRepeat repeat = {0};
	for (;;) {
		if (platform_exit_requested()) {
			vitals_check_stop();
			return -1;
		}
		PadState pad;
		unsigned pressed = read_presses(&pad);
		int direction = check_scroll_direction(pad.buttons & PAD_UP, pad.buttons & PAD_DOWN, pad.left_y, pad.right_y);
		int steps = check_scroll_repeat(&repeat, direction, platform_now_ms());
		busy = vitals_check_poll(&view, notice, sizeof(notice));
		if (pressed & back_button) {
			leaving = 1;
			if (busy)
				vitals_check_cancel();
		}
		if (autotest && !busy && view.complete) {
			VITALS_LOG_ALWAYS("autotest: done, report %d", vitals_check_save_report());
			leaving = 1;
		}
		if (leaving && !busy)
			break;
		if (pressed & PAD_TRIANGLE)
			vitals_check_cancel();
		/* The report is saved only when asked, for a run that finished without being cancelled */
		if (!busy && (pressed & PAD_START))
			(void)vitals_check_save_report();
		if (pressed & PAD_SQUARE) {
			page = (page + 1) % CHECK_PAGE_COUNT;
			scroll = 0;
			following = 0;
		}
		if (steps)
			following = 0;
		unsigned item;
		int running = following ? check_follow(&view, &item) : -1;
		if (running >= 0) {
			if (running != page)
				scroll = 0;
			page = running;
			/* The running host in view: the list moves only once it's past the last line shown */
			unsigned visible = page == CHECK_PAGE_REDIRECTS ? CHECK_VISIBLE_REDIRECTS
			                   : page == CHECK_PAGE_DNS     ? CHECK_VISIBLE_DNS
			                                                : CHECK_VISIBLE_BADSSL;
			if (item < scroll)
				scroll = item;
			else if (item >= scroll + visible)
				scroll = item - visible + 1;
		}
		/* The cipher list, the badssl.com list, the redirects and the DNS rules scroll */
		if (page == CHECK_PAGE_DNS)
			scroll = check_scroll_move(scroll, steps, view.dns_count, CHECK_VISIBLE_DNS);
		else if (page == CHECK_PAGE_REDIRECTS)
			scroll = check_scroll_move(scroll, steps, view.redirect_count, CHECK_VISIBLE_REDIRECTS);
		else if (page == CHECK_PAGE_CERTIFICATES)
			scroll = check_scroll_move(scroll, steps, CHECK_BADSSL_COUNT, CHECK_VISIBLE_BADSSL);
		else
			scroll = check_scroll_move(scroll, page == CHECK_PAGE_CIPHERS ? steps : 0, view.handshake.cipher_count,
			                           CHECK_VISIBLE_CIPHERS);
		if (!busy && !leaving && (pressed & confirm_button)) {
			vitals_check_start();
			busy = 1;
			following = 1;
		}
		if (last_page != page || last_scroll != scroll || last_busy != busy || strcmp(last_notice, notice) != 0 ||
		    memcmp(&last_view, &view, sizeof(view)) != 0) {
			check_draw(canvas, &view, page, scroll, busy, notice);
			platform_present(canvas);
			last_view = view;
			last_page = page;
			last_scroll = scroll;
			last_busy = busy;
			snprintf(last_notice, sizeof(last_notice), "%s", notice);
		}
		platform_sleep_ms(30);
	}
	vitals_check_stop();
	return 0;
}

/* ---- the changelog and the credits: the app's CHANGELOG.md and CREDITS.md, laid out as the
 * changelog's lines ("## " headings, "- " items) and scrolled ---- */

#define DOCUMENT_MAX_SIZE (64u * 1024u)
#define DOCUMENT_MAX_LINES 512u

typedef struct {
	const char *title, *file, *missing;
	ChangelogLine lines[DOCUMENT_MAX_LINES];
	unsigned count;
} Document;

static Document changelog = {"Changelog", "CHANGELOG.md", "The changelog is missing from this app.", {{0}}, 0};
static Document credits = {"Credits", "CREDITS.md", "The credits are missing from this app.", {{0}}, 0};

/* In layout pixels, measured at the size it's drawn at (ui.c) */
static int document_width(const char *text)
{
	return app_text_width(text, APP_CHANGELOG_TEXT_SIZE);
}

static void document_load(Document *document)
{
	if (document->count != 0)
		return;
	char *text = malloc(DOCUMENT_MAX_SIZE);
	long length = -1;
	if (text != NULL) {
		char path[320];
		console_app_file(document->file, path, sizeof(path));
		length = platform_read_file(path, text, DOCUMENT_MAX_SIZE);
	}
	if (length > 0)
		document->count = (unsigned)vitals_changelog_layout(text, (size_t)length, document_width, APP_CHANGELOG_WIDTH,
		                                                     APP_CHANGELOG_ITEM_WIDTH, document->lines, DOCUMENT_MAX_LINES);
	free(text);
	if (document->count == 0) {
		document->lines[0].kind = CHANGELOG_TEXT;
		snprintf(document->lines[0].text, sizeof(document->lines[0].text), "%s", document->missing);
		document->count = 1;
	}
}

static int run_document(Document *document)
{
	unsigned scroll = 0, last_scroll = ~0u;
	CheckScrollRepeat repeat = {0};
	document_load(document);
	for (;;) {
		if (platform_exit_requested())
			return -1;
		PadState pad;
		unsigned pressed = read_presses(&pad);
		if (pressed & back_button)
			return 0;
		int direction = check_scroll_direction(pad.buttons & PAD_UP, pad.buttons & PAD_DOWN, pad.left_y, pad.right_y);
		scroll = check_scroll_move(scroll, check_scroll_repeat(&repeat, direction, platform_now_ms()), document->count,
		                           APP_CHANGELOG_VISIBLE_LINES);
		if (scroll != last_scroll) {
			AppChangelog view = {status(), document->title, document->lines, document->count, scroll};
			app_draw_changelog(canvas, &view);
			platform_present(canvas);
			last_scroll = scroll;
		}
		platform_sleep_ms(30);
	}
}

/* ---- the menu ---- */

static void run_menu(void)
{
	/* A system vitals isn't made for: a warning above the menu, and nothing to install */
	int supported = console_supported();
	int allowed = !supported && console_unsupported_allowed();
	static char warning_text[160];
	const char *warning_title = NULL;
	if (!supported) {
		warning_title = allowed ? "Unsupported system: installing anyway (unsupported.ok)" : "This system isn't supported";
		snprintf(warning_text, sizeof(warning_text), "%s. vitals is made for %s%s", console_system_text(),
		         console_words()->made_for, allowed ? ": for testing only" : ", so it can't be installed here");
	}
	VITALS_LOG_ALWAYS("console: %s, %s%s", console_system_text(), supported ? "supported" : "not supported",
	        allowed ? ", unsupported.ok there" : "");
	unsigned selected = 0;
	/* Install, Update, Reinstall and Uninstall are one item, its choice the operation: those that
	 * apply now, most important first; Left and Right pick one */
	enum Action operations[4];
	unsigned operation = 0;
	int refresh = 1, redraw = 1;
	CheckScrollRepeat repeat = {0};
	uint64_t started = platform_now_ms(), last_shown = started;
	/* The new-release check starts once the menu has been up 3 seconds, past the PS3's first frames;
	 * the menu is drawn again when it finds one */
	int release_check = 0;
	const char *shown_release = NULL;
	int shown_searching = 1;
	for (;;) {
		if (refresh) {
			refresh_state();
			refresh = 0;
			redraw = 1;
			operation = 0;
		}
		/* On a system vitals isn't made for, nothing is installed (unless the user asked to anyway,
		 * for testing): only Uninstall, the test and the documents */
		int may_install = supported || allowed;
		unsigned operation_count = 0;
		if (!installed && may_install)
			operations[operation_count++] = ACTION_INSTALL;
		if (installed && outdated && may_install)
			operations[operation_count++] = ACTION_UPDATE;
		if (installed && may_install)
			operations[operation_count++] = ACTION_REINSTALL;
		if (installed)
			operations[operation_count++] = ACTION_UNINSTALL;
		if (operation >= operation_count)
			operation = 0;
		enum Action actions[9];
		AppMenuItem items[9];
		unsigned count = 0;
		if (operation_count > 0)
			actions[count++] = operations[operation];
		if (installed) {
			actions[count++] = ACTION_CERTIFICATES;
			if (!outdated && may_install)
				actions[count++] = ACTION_OPTIONS;
		}
		actions[count++] = ACTION_TEST;
		actions[count++] = ACTION_CHANGELOG;
		actions[count++] = ACTION_CREDITS;
		actions[count++] = ACTION_EXIT;
		if (selected >= count)
			selected = count - 1;
		for (unsigned i = 0; i < count; ++i) {
			items[i] = item(actions[i]);
			/* When the certificates were last updated, next to the item that updates them */
			if (actions[i] == ACTION_CERTIFICATES) {
				items[i].value = certificates_updated;
				items[i].value_alert = certificates_stale;
			}
		}
		/* With more than one operation, the item reads as a choice, its description the chosen one's */
		if (operation_count > 1 && actions[0] == operations[operation])
			items[0] = (AppMenuItem){"Installation", item(operations[operation]).description,
			                         action_items[operations[operation]].label, 0, operation == 0,
			                         operation + 1 == operation_count,
			                         operations[operation] == ACTION_UNINSTALL ? APP_TONE_ORANGE : APP_TONE_USUAL, NULL, 0};
		if (redraw) {
			AppHome home = {status(), warning_title, warning_text, items, count, selected, NULL, 0};
			app_draw_home(canvas, &home);
			platform_present(canvas);
			redraw = 0;
		}
		if (platform_exit_requested())
			break;
		PadState pad;
		unsigned pressed = read_presses(&pad);
		/* For the first 3 seconds, the menu shown again every 250 ms: on the PS3 the first frame,
		 * flipped right after the video set-up, stays black until the next one */
		uint64_t now = platform_now_ms();
		if (now - started < 3000 && now - last_shown >= 250) {
			platform_show_again();
			last_shown = now;
		}
		if (!release_check && now - started >= 3000) {
			release_check_start();
			release_check = 1;
		}
		if (newer_release() != shown_release || release_check_searching() != shown_searching) {
			shown_release = newer_release();
			shown_searching = release_check_searching();
			redraw = 1;
		}
		int direction = check_scroll_direction(pad.buttons & PAD_UP, pad.buttons & PAD_DOWN, pad.left_y, pad.right_y);
		int steps = check_scroll_repeat(&repeat, direction, now);
		if (steps != 0) {
			int next = (int)selected + steps;
			selected = next < 0 ? 0 : next >= (int)count ? count - 1 : (unsigned)next;
			redraw = 1;
		}
		/* Left and Right stop at the first and the last operation */
		if (selected == 0 && operation_count > 1 && (pressed & PAD_LEFT) && operation > 0) {
			--operation;
			redraw = 1;
		}
		if (selected == 0 && operation_count > 1 && (pressed & PAD_RIGHT) && operation + 1 < operation_count) {
			++operation;
			redraw = 1;
		}
		if (pressed & back_button)
			break;
		if (pressed & confirm_button) {
			enum Action action = actions[selected];
			VITALS_LOG_ALWAYS("menu: %s", action_items[action].label);
			int rc = 0;
			if (action == ACTION_EXIT)
				break;
			/* The check never runs alongside the test or an operation; reading the documents needs
			 * no network, so it goes on */
			if (action != ACTION_CHANGELOG && action != ACTION_CREDITS)
				release_check_stop();
			if (action == ACTION_TEST)
				rc = run_test(0);
			else if (action == ACTION_CHANGELOG)
				rc = run_document(&changelog);
			else if (action == ACTION_CREDITS)
				rc = run_document(&credits);
			else if (action == ACTION_OPTIONS)
				rc = run_options();
			else
				rc = run_operation(action);
			if (rc < 0)
				break;
			refresh = 1;
		}
		platform_sleep_ms(16);
	}
}

int app_main(int autotest)
{
	canvas = malloc(CHECK_WIDTH * CHECK_HEIGHT * sizeof(*canvas));
	if (canvas == NULL) {
		VITALS_LOG_ALWAYS("no memory for the canvas");
		return 1;
	}
	int rc = platform_display_init();
	if (rc < 0) {
		VITALS_LOG_ALWAYS("the display didn't start (%d)", rc);
		return 1;
	}
	/* Drawn where the console shows it from, when it can: nothing to scale or copy. Its size may be
	 * the screen's own, which ui.c draws the layout at; the app's own canvas is always the layout's */
	if (platform_canvas() != NULL) {
		free(canvas);
		canvas = platform_canvas();
		int canvas_width, canvas_height;
		platform_canvas_size(&canvas_width, &canvas_height);
		check_canvas_set(canvas_width, canvas_height);
	}
	rc = check_font_init();
	if (rc < 0) {
		VITALS_LOG_ALWAYS("the font didn't start (0x%08X)", (unsigned)rc);
		return 1;
	}
	rc = platform_pad_init();
	if (rc != 0)
		VITALS_LOG_ALWAYS("pads: 0x%08X", (unsigned)rc);
	if (platform_circle_confirms()) {
		confirm_button = PAD_CIRCLE;
		back_button = PAD_CROSS;
		app_set_circle_confirms(1);
	}
	if (autotest) {
		VITALS_LOG_ALWAYS("autotest: running the connection test");
		run_test(1);
	} else
		run_menu();
	VITALS_LOG_ALWAYS("exiting%s", platform_exit_requested() ? ", as the system asked" : "");
	release_check_stop();
	vitals_check_stop();
	console_close();
	check_font_close();
	platform_display_close();
	return 0;
}
