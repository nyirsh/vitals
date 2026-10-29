# Each component builds with its own Makefile; this one only calls them
#   vitals-plugin/  kernel plugin (vitals.skprx)
#   tls13-vita/     the browser's TLS provider (option: DEBUG)
#   vitals-http/    libhttp written from scratch, with tls13-vita's TLS (libhttp.suprx; options:
#                   TLS_HEAP_KIB, USER_AGENT, DEBUG)
#   vitals-ssl/     libssl written from scratch (libssl.suprx; option: DEBUG); a skeleton, built
#                   only by `make vitals-ssl`, and not packaged
#   vitals-app/     the vitals app and vitals-app.vpk (builds the plugin, tls13-vita and vitals-http
#                   first)
# Command-line options such as `make TLS_HEAP_KIB=256` reach the components automatically
# Every debug level of the providers and redirect is built and packaged; the app switches between
# them
# Every CMake build also writes compile_commands.json, which .vscode uses for code navigation
COMPONENTS = vitals-plugin tls13-vita vitals-http vitals-ssl vitals-app

# The app builds the plugin, providers and redirect it packages, so they are not listed again
all: vitals-app

$(COMPONENTS):
	$(MAKE) -C $@

# Runs every component's host tests, then the checks on the shared files at the root (tests/);
# it stops at the first failure and needs no VitaSDK
test:
	$(foreach component,$(COMPONENTS),$(MAKE) -C $(component) test &&) true
	python3 -m unittest discover -s tests -p 'test_*.py'

# Refreshes the app's bundled Mozilla certificates
update-certs:
	$(MAKE) -C vitals-app update-certs

# Releases a version: `make version 1.5` checks that the changelog's newest entry is 1.5, sets
# VERSION, runs the tests, then commits, tags 1.5 and pushes the branch and the tag to origin
# (tools/release.py)
# The words after version are its arguments, not things to build; the script takes exactly one
ifeq (version,$(firstword $(MAKECMDGOALS)))
RELEASE_ARGUMENTS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
$(foreach argument,$(RELEASE_ARGUMENTS),$(eval $(argument):;@:))
endif
version:
	python3 tools/release.py $(RELEASE_ARGUMENTS)

clean:
	$(foreach component,$(COMPONENTS),$(MAKE) -C $(component) clean;)

.PHONY: all clean test update-certs version $(COMPONENTS)
