#ifndef VITALS_APP_APP_H
#define VITALS_APP_APP_H

/* The vitals app, the same on every console: installs, updates or removes vitals, turns its parts on
 * and off and picks its debug output, updates its certificates, runs the connection test, and shows
 * the changelog and the credits, all from one menu. Each console's main() calls it, after setting up
 * what console.h needs */

/* Runs the app until the user or the system ends it: 0, or 1 when the screen or the font didn't
 * start. With autotest, only the connection test runs: its report is saved once it's done, and the
 * app ends (a run with no one at the pad, in an emulator) */
int app_main(int autotest);

#endif
