# Each component builds with its own Makefile; this one only calls them
#   vitals-plugin/  kernel plugin (vitals.skprx)
#   vitals-ssl/     libssl written from scratch (libssl.suprx; option: DEBUG), installed as the
#                   system's libssl
#   tls13-vita/     the browser's TLS provider, on vitals-ssl (option: DEBUG)
#   vitals-http/    libhttp written from scratch, importing vitals-ssl as Sony's imports libssl
#                   (libhttp.suprx; options: TLS_HEAP_KIB, USER_AGENT, DEBUG)
#   vitals-app/     the vitals app and vitals-app.vpk (builds the plugin, vitals-ssl, tls13-vita and
#                   vitals-http first)
# Command-line options such as `make TLS_HEAP_KIB=256` reach the components automatically
# Every debug level of the providers and redirect is built and packaged; the app switches between
# them
# Every CMake build also writes compile_commands.json, which .vscode uses for code navigation
COMPONENTS = vitals-plugin vitals-ssl tls13-vita vitals-http vitals-app

# The app builds the plugin, providers and redirect it packages, so they are not listed again
all: vitals-app

$(COMPONENTS):
	$(MAKE) -C $@

# Runs every component's host tests; it stops at the first failure and needs no VitaSDK
test:
	$(foreach component,$(COMPONENTS),$(MAKE) -C $(component) test &&) true

# Refreshes the app's bundled Mozilla certificates
update-certs:
	$(MAKE) -C vitals-app update-certs

clean:
	$(foreach component,$(COMPONENTS),$(MAKE) -C $(component) clean;)

.PHONY: all clean test update-certs $(COMPONENTS)
