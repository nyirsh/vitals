# Each component builds with its own Makefile; this one only calls them
#   vitals-boot/    kernel plugin (vitals.skprx; option: DEBUG), with vitals-dns/ built in
#   vitals-dns/     the DNS rules (dns.txt), part of the kernel plugin: no Makefile of its own, its
#                   tests are vitals-boot's
#   vitals-ssl/     libssl written from scratch (libssl.suprx; option: DEBUG), installed as the
#                   system's libssl
#   vitals-browser/ the browser's TLS provider (vitals.suprx), on vitals-ssl (option: DEBUG)
#   vitals-http/    libhttp written from scratch, importing vitals-ssl as Sony's imports libssl
#                   (libhttp.suprx; options: TLS_HEAP_KIB, USER_AGENT, DEBUG)
#   vitals-app/     the vitals app and vitals-app.vpk (builds the plugin, vitals-ssl, vitals-browser
#                   and vitals-http first)
#   common/         the code they share (headers, core library, runtime): tests only
# Command-line options such as `make TLS_HEAP_KIB=256` reach the components automatically
# Every debug level of the providers and redirect is built and packaged; the app switches between
# them
# Every CMake build also writes compile_commands.json, which .vscode uses for code navigation
#   make upload-app         builds the app and puts its VPK in the Vita's ux0:data/vitals/, for
#                           VitaShell to install (tools/vita_comms.py)
#   make plugin|ssl|http|browser|app [DEBUG=N]   one module (the PS3's names), with what it links first
#   make pull               pulls the newest published image (vitasdk/vitasdk:latest)
#   make editor             VS Code's navigation and errors with the image's headers (after make)
#   make preview            the app's screens on this Mac with made-up data (../ps3/build/preview/)
#   make log                prints vitals.log, and keeps it in ../fetched/psv/
#   make app-log            prints the app's vitals-app.log, and keeps it in ../fetched/psv/
#   make fetch              the logs, the app's test reports and the crash dumps, into ../fetched/psv/
#   make status             what's on the Vita now
# The Vita is VITA_HOST in the repository's .env (cp ../.env.example ../.env), or make's or the environment's VITA_HOST
COMPONENTS = common vitals-boot vitals-ssl vitals-browser vitals-http vitals-app

# Built in VitaSDK's Docker image, as the PS3's is in its own (docker pulls it the first time; make
# pull gets a newer one; IMAGE= for another tag). The host tests and the console tools run here
IMAGE ?= vitasdk/vitasdk:latest
REPOSITORY = $(abspath $(CURDIR)/..)
# The repository at the same path inside, so compile_commands.json stays right for .vscode
DOCKER = docker run --rm -v "$(REPOSITORY)":"$(REPOSITORY)" -w "$(CURDIR)" $(IMAGE) sh -lc
# The options that reach the components, as the container has no make above it to inherit them from
OPTIONS = $(if $(DEBUG),DEBUG=$(DEBUG)) $(if $(TLS_HEAP_KIB),TLS_HEAP_KIB=$(TLS_HEAP_KIB)) $(if $(USER_AGENT),"USER_AGENT=$(USER_AGENT)") $(if $(BUILD_DIR),BUILD_DIR=$(BUILD_DIR))

ifeq ($(filter 0 1 2,$(or $(DEBUG),0)),)
$(error DEBUG must be 0, 1 or 2)
endif

# The Vita: on make's command line (make status VITA_HOST=...), else tools/vita_comms.py reads ../.env
$(foreach v,VITA_HOST VITA_PORT,$(if $($(v)),$(eval export $(v))))

# The app builds the plugin, providers and redirect it packages, so they are not listed again
all: vitals-app

$(COMPONENTS):
	$(DOCKER) 'make -C $@ $(OPTIONS)'

# Runs every component's host tests, on this machine; it stops at the first failure and needs no VitaSDK
test:
	$(foreach component,$(COMPONENTS),$(MAKE) -C $(component) test &&) true

# Refreshes both apps' Mozilla certificates
update-certs:
	$(MAKE) -C vitals-app update-certs

# One module, by the PS3's names. At any level they link the release builds' stubs, built first
stubs-plugin:
	$(DOCKER) 'make -C vitals-boot $(OPTIONS) DEBUG=0'
stubs-ssl: stubs-plugin
	$(DOCKER) 'make -C vitals-ssl $(OPTIONS) DEBUG=0'

plugin:
	$(DOCKER) 'make -C vitals-boot $(OPTIONS)'
ssl: stubs-plugin
	$(DOCKER) 'make -C vitals-ssl $(OPTIONS)'
http: stubs-ssl
	$(DOCKER) 'make -C vitals-http $(OPTIONS)'
browser: stubs-ssl
	$(DOCKER) 'make -C vitals-browser $(OPTIONS)'
app: vitals-app

# Drawn by the PS3's preview, which has the Vita's size too
preview:
	$(MAKE) -C ../ps3 preview

# VS Code without the SDK on this machine: the image's headers, and each file's flags (after make)
editor:
	python3 ../shared/tools/editor_setup.py psv --image $(IMAGE)

pull:
	docker pull $(IMAGE)

upload-app: vitals-app
	python3 tools/vita_comms.py app

log app-log fetch status:
	python3 tools/vita_comms.py $@

clean:
	$(foreach component,$(COMPONENTS),$(MAKE) -C $(component) clean;)

.PHONY: all clean test update-certs upload-app log app-log fetch status preview pull editor plugin ssl http browser app stubs-plugin stubs-ssl $(COMPONENTS)
