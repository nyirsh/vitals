# Each component builds with its own Makefile; this one only calls them
#   vitals-plugin/  kernel plugin (vitals.skprx)
#   tls13-vita/     TLS providers (options: HTTP_HEAP_KIB, DEBUG)
#   vitals-reauth/  PSN sign-in host redirect (vitals-reauth.suprx)
#   vitals-app/     the vitals app and vitals-app.vpk (builds the three above first)
# Command-line options such as `make HTTP_HEAP_KIB=256` reach the components automatically
# Every debug level of the providers and redirect is built and packaged; the app switches between
# them
# Every CMake build also writes compile_commands.json, which .vscode uses for code navigation
COMPONENTS = vitals-plugin tls13-vita vitals-reauth vitals-app

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

clean:
	$(foreach component,$(COMPONENTS),$(MAKE) -C $(component) clean;)

.PHONY: all clean test update-certs $(COMPONENTS)
