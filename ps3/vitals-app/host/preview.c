/* Draws each of the app's screens with made-up data into BMPs, on a Mac (font_host.c), to look at
 * the layout without a console: preview <folder> [1080|vita], 1080 drawing them at 1920x1080, as a
 * 1080 console does (names ending in -1080), and vita at the Vita's 960x544 (ending in -vita). The
 * data is the PS3's */

#include "changelog.h"
#include "font.h"
#include "check_model.h"
#include "ui.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t canvas[1920 * 1080];
static const char *suffix = "";

static void put32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)v, p[1] = (unsigned char)(v >> 8), p[2] = (unsigned char)(v >> 16), p[3] = (unsigned char)(v >> 24);
}

static void save(const char *folder, const char *name)
{
	char path[1024];
	snprintf(path, sizeof(path), "%s/%s%s.bmp", folder, name, suffix);
	FILE *file = fopen(path, "wb");
	if (file == NULL) {
		perror(path);
		exit(1);
	}
	const unsigned width = (unsigned)check_canvas_width(), height = (unsigned)check_canvas_height();
	unsigned row = width * 3, size = row * height;
	unsigned char head[54] = {'B', 'M'};
	put32(head + 2, 54 + size);
	put32(head + 10, 54);
	put32(head + 14, 40);
	put32(head + 18, width);
	put32(head + 22, height);
	head[26] = 1;
	head[28] = 24;
	put32(head + 34, size);
	fwrite(head, 1, sizeof(head), file);
	static unsigned char line[1920 * 3];
	for (int y = (int)height - 1; y >= 0; --y) {
		for (int x = 0; x < (int)width; ++x) {
			uint32_t px = canvas[y * (int)width + x];
			line[x * 3] = (unsigned char)px, line[x * 3 + 1] = (unsigned char)(px >> 8), line[x * 3 + 2] = (unsigned char)(px >> 16);
		}
		fwrite(line, 1, row, file);
	}
	fclose(file);
	printf("%s\n", path);
}

static int measure(const char *text)
{
	return app_text_width(text, APP_CHANGELOG_TEXT_SIZE);
}

int main(int argc, char **argv)
{
	if (argc != 2 && !(argc == 3 && (strcmp(argv[2], "1080") == 0 || strcmp(argv[2], "vita") == 0))) {
		fprintf(stderr, "usage: %s <folder> [1080|vita]\n", argv[0]);
		return 2;
	}
	if (argc == 3 && strcmp(argv[2], "1080") == 0) {
		check_canvas_set(1920, 1080);
		suffix = "-1080";
	} else if (argc == 3) {
		check_canvas_set(960, 544);
		suffix = "-vita";
	}
	if (check_font_init() < 0)
		return 1;
	const char *out = argv[1];

	static const AppMenuItem fresh[] = {
	    {"Install", "Lets games and apps connect to modern secure (TLS 1.2 and 1.3) sites", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	    {"Test connections", "Checks that everything is working as expected", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	    {"Changelog", "What changed in each version of vitals", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	    {"Exit", "", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	};
	AppHome home = {{0, 0, "", NULL, "4.93 CEX, Cobra 8.5"}, NULL, NULL, fresh, 4, 0, NULL, 0};
	app_draw_home(canvas, &home);
	save(out, "home-not-installed");

	/* An unsupported system: nothing to install */
	AppHome unsupported = {{0, 0, "", NULL, "4.92 CEX, PS3HEN 3.4.1"},
	                       "This system isn't supported",
	                       "4.92 CEX, PS3HEN 3.4.1. vitals is made for 4.93 CEX with Cobra, so it can't be installed here",
	                       fresh + 1, 3, 0, NULL, 0};
	app_draw_home(canvas, &unsupported);
	save(out, "home-unsupported");

	static const AppMenuItem installed[] = {
	    {"Installation", "Removes all of the installed files", "Uninstall", 0, 0, 1, APP_TONE_ORANGE, NULL, 0},
	    {"Update certificates", "Downloads the latest trusted websites certificates", NULL, 0, 0, 0, APP_TONE_USUAL, "2026-07-03", 1},
	    {"Options", "Turns each part of vitals on or off, and picks the debug output", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	    {"Test connections", "Checks that everything is working as expected", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	    {"Changelog", "What changed in each version of vitals", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	    {"Credits", "The people and projects vitals is built on", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	    {"Exit", "", NULL, 0, 0, 0, APP_TONE_USUAL, NULL, 0},
	};
	static const AppHint operating[] = {
	    {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Choose"},
	    {APP_GLYPH_CONFIRM, APP_GLYPH_NONE, "Select"},
	    {APP_GLYPH_BACK, APP_GLYPH_NONE, "Exit"},
	};
	AppHome home2 = {{1, 0, "2.0", "Basic debug", "4.93 CEX, Cobra 8.5"}, NULL, NULL, installed, 7, 0, operating, 3};
	app_draw_home(canvas, &home2);
	save(out, "home-installed");

	static const AppMenuItem options[] = {
	    {"TLS", "vitals TLS enabled", "On", 1, 1, 0, APP_TONE_USUAL, NULL, 0},
	    {"HTTP", "Sony HTTP enabled", "Off", 1, 0, 1, APP_TONE_RED, NULL, 0},
	    {"DNS rules", "vitals DNS rules disabled", "Off", 0, 0, 1, APP_TONE_RED, NULL, 0},
	    {"Redirects", "vitals redirects enabled", "On", 1, 1, 0, APP_TONE_USUAL, NULL, 0},
	    {"Debug output", "Logs calls and connections to /dev_hdd0/vitals/logs/vitals.log", "Basic debug", 1, 0, 0, APP_TONE_ORANGE, NULL, 0},
	};
	static const AppHint switching[] = {
	    {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Choose"},
	    {APP_GLYPH_START, APP_GLYPH_NONE, "Apply and reboot"},
	    {APP_GLYPH_BACK, APP_GLYPH_NONE, "Back"},
	};

	AppOptions screen = {{1, 0, "2.0", "Basic debug", "4.93 CEX, Cobra 8.5"}, options, 5, 0, switching, 3};
	app_draw_options(canvas, &screen);
	save(out, "options");
	screen.selected = 4;
	app_draw_options(canvas, &screen);
	save(out, "options-debug");
	static const char *const applying[] = {"DNS rules off: wrote /dev_hdd0/vitals/flags/dns.off",
	                                       "Debug output: Full debug",
	                                       "Copied libssl-debug2.sprx to /dev_hdd0/vitals/system/libssl.sprx",
	                                       "Copied libhttp-debug2.sprx to /dev_hdd0/vitals/system/libhttp.sprx",
	                                       "Copied vitals_boot-debug2.sprx to /dev_hdd0/plugins/vitals_boot.sprx",
	                                       "Copied vitals_dns-debug2.bin to /dev_hdd0/vitals/system/vitals_dns.bin",
	                                       "The log will be /dev_hdd0/vitals/logs/vitals.log"};
	static const AppHint rebooting = {APP_GLYPH_NONE, APP_GLYPH_NONE, "The console reboots by itself."};
	AppTask apply = {{1, 0, "2.0", "Full debug", "4.93 CEX, Cobra 8.5"}, "Applying options", applying, 7, CHECK_PASS, "Done. Rebooting in 3 seconds...",
	                 &rebooting, 1};
	app_draw_task(canvas, &apply);
	save(out, "options-applying");

	static const char *const lines[] = {"Copying libssl.sprx to /dev_hdd0/vitals/system/libssl.sprx",
	                                    "Copying vitals_boot.sprx to /dev_hdd0/plugins/vitals_boot.sprx",
	                                    "Copying Mozilla's certificates to /dev_hdd0/vitals/system/cacert.pem",
	                                    "Adding vitals to /dev_hdd0/boot_plugins.txt"};
	static const AppHint waiting = {APP_GLYPH_NONE, APP_GLYPH_NONE, "Please wait and keep your PS3 turned on."};
	AppTask task = {{0, 0, "", NULL, "4.93 CEX, Cobra 8.5"}, "Installing vitals", lines, 4, CHECK_RUNNING, "Working...", &waiting, 1};
	app_draw_task(canvas, &task);
	save(out, "task-running");
	static const AppHint done[] = {{APP_GLYPH_START, APP_GLYPH_NONE, "Reboot now"}, {APP_GLYPH_BACK, APP_GLYPH_NONE, "Later"}};
	AppTask finished = {{1, 0, "2.0", NULL, "4.93 CEX, Cobra 8.5"}, "Installing vitals", lines, 4, CHECK_PASS,
	                    "Done. Reboot the console to start vitals.", done, 2};
	app_draw_task(canvas, &finished);
	save(out, "task-done");

	/* The changelog as the app shows it: the repository's CHANGELOG.md, which make app copies into the
	 * package, read from where make preview runs (ps3/) */
	{
		static char text[16384];
		FILE *file = fopen("../CHANGELOG.md", "rb");
		size_t length = file != NULL ? fread(text, 1, sizeof(text), file) : 0;
		if (file != NULL)
			fclose(file);
		static ChangelogLine laid[128];
		size_t count = vitals_changelog_layout(text, length, measure, APP_CHANGELOG_WIDTH, APP_CHANGELOG_ITEM_WIDTH,
		                                       laid, 128);
		AppChangelog view = {{1, 0, "2.0", NULL, "4.93 CEX, Cobra 8.5"}, "Changelog", laid, (unsigned)count, 0};
		app_draw_changelog(canvas, &view);
		save(out, "changelog");
	}

	/* The credits as the app shows them: the repository's CREDITS.md, read from where make preview runs */
	{
		static char text[16384];
		FILE *file = fopen("CREDITS.md", "rb");
		size_t length = file != NULL ? fread(text, 1, sizeof(text), file) : 0;
		if (file != NULL)
			fclose(file);
		static ChangelogLine credit_lines[128];
		size_t credit_count = vitals_changelog_layout(text, length, measure, APP_CHANGELOG_WIDTH, APP_CHANGELOG_ITEM_WIDTH,
		                                              credit_lines, 128);
		AppChangelog credits = {{1, 0, "2.0", NULL, "4.93 CEX, Cobra 8.5"}, "Credits", credit_lines, (unsigned)credit_count, 0};
		app_draw_changelog(canvas, &credits);
		save(out, "credits");
	}

	static CheckService s;
	memset(&s, 0, sizeof(s));
	s.started = 1;
	s.vitals_enabled = 1;
	for (unsigned v = 0; v < 4; ++v) {
		CheckResult *r = &s.protocols[v];
		if (v < 2) {
			r->error = (int)0x80710b00;
			check_protocol_judge(v, r);
		} else {
			r->http_code = 200;
			snprintf(r->cipher, sizeof(r->cipher), v == 3 ? "TLS_AES_256_GCM_SHA384" : "ECDHE-RSA-AES256-GCM-SHA384");
			check_protocol_judge(v, r);
		}
		r->elapsed_ms = 300 + v * 40;
	}
	s.connection.state = CHECK_PASS;
	s.handshake.valid = 1;
	snprintf(s.handshake.cipher.name, sizeof(s.handshake.cipher.name), "TLS_CHACHA20_POLY1305_SHA256");
	s.handshake.cipher.id = 0x1303;
	snprintf(s.handshake.version.name, sizeof(s.handshake.version.name), "TLS 1.3");
	snprintf(s.handshake.group.name, sizeof(s.handshake.group.name), "x25519");
	static const char *const suites[] = {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256",
	                                     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	                                     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"};
	for (unsigned i = 0; i < 6; ++i) {
		snprintf(s.handshake.ciphers[i].name, sizeof(s.handshake.ciphers[i].name), "%s", suites[i]);
		s.handshake.ciphers[i].id = 0x1301 + i;
	}
	s.handshake.cipher_count = 6;
	for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i) {
		CheckResult *r = &s.badssl[i];
		const CheckBadssl *test = check_badssl(i);
		if (i < 8) {
			r->http_code = test->refuse ? 0 : 200;
			r->verify_error = test->refuse ? 0x800 : 0;
			r->error = test->refuse ? (int)0x80710b00 : 0;
			check_badssl_judge(test, r);
			r->elapsed_ms = 400 + i * 13;
		} else
			r->state = i == 8 ? CHECK_RUNNING : CHECK_WAIT;
	}
	/* Two redirects: one through, one whose new server doesn't answer, and one still waiting */
	static const char *const redirect_hosts[][2] = {{"soundshapes.psvita.online.scea.com", "sound.ture.fish"},
	                                                 {"old.game.example", "new.game.example"},
	                                                 {"motorstorm.example", "community.example"}};
	s.redirect_count = 3;
	s.libhttp_active = 1;
	for (unsigned i = 0; i < s.redirect_count; ++i) {
		snprintf(s.redirects[i].from, sizeof(s.redirects[i].from), "%s", redirect_hosts[i][0]);
		snprintf(s.redirects[i].to, sizeof(s.redirects[i].to), "%s", redirect_hosts[i][1]);
	}
	s.redirects[0].result.http_code = 200;
	s.redirects[0].result.elapsed_ms = 512;
	check_redirect_judge(&s.redirects[0].result);
	s.redirects[1].result.error = (int)0x80710093;
	s.redirects[1].result.elapsed_ms = 15003;
	check_redirect_judge(&s.redirects[1].result);
	static const char *const dns_rules[][2] = {{"ads.example", "block"},
	                                           {"lan.game.example", "192.168.1.20"},
	                                           {"master.game.example", "revival.example"},
	                                           {"stats.game.example", "block"}};
	s.dns_count = 4;
	for (unsigned i = 0; i < s.dns_count; ++i) {
		snprintf(s.dns[i].from, sizeof(s.dns[i].from), "%s", dns_rules[i][0]);
		snprintf(s.dns[i].to, sizeof(s.dns[i].to), "%s", dns_rules[i][1]);
	}
	CheckLookup none = {0, 1, 0, {{0}}}, lan = {1, 0, 1, {{192, 168, 1, 20}}}, revival = {1, 0, 1, {{203, 0, 113, 7}}};
	check_dns_judge("block", &none, &none, &s.dns[0].result);
	s.dns[0].result.elapsed_ms = 31;
	check_dns_judge("192.168.1.20", &lan, &none, &s.dns[1].result);
	s.dns[1].result.elapsed_ms = 28;
	check_dns_judge("revival.example", &revival, &revival, &s.dns[2].result);
	s.dns[2].result.elapsed_ms = 64;
	s.dns[3].result.state = CHECK_RUNNING;
	check_draw(canvas, &s, CHECK_PAGE_DNS, 0, 1, "");
	save(out, "test-dns");
	check_draw(canvas, &s, CHECK_PAGE_CIPHERS, 0, 1, "");
	save(out, "test-ciphers");
	check_draw(canvas, &s, CHECK_PAGE_REQUESTS, 0, 1, "");
	save(out, "test-requests");
	check_draw(canvas, &s, CHECK_PAGE_CERTIFICATES, 0, 1, "");
	save(out, "test-certificates");
	check_draw(canvas, &s, CHECK_PAGE_REDIRECTS, 0, 1, "");
	save(out, "test-redirects");
	check_draw(canvas, &s, CHECK_PAGE_HANDSHAKE, 0, 1, "");
	save(out, "test-handshake");
	s.complete = 1;
	check_draw(canvas, &s, CHECK_PAGE_CERTIFICATES, 0, 0, "");
	save(out, "test-finished");
	check_font_close();
	return 0;
}
