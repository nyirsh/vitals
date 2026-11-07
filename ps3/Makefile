# vitals-ps3's builds, as the Vita's vitals Makefile has them; everything is built in build/, the
# console modules in the vitals-ps3-sdk Docker image, nyirsh/vitals-ps3-sdk from Docker Hub (docker
# pulls it the first time; make pull gets a newer one; github.com/nyirsh/vitals-ps3-sdk builds it)
#   make                    libssl and the boot plugin, release (build/vitals-ssl, build/vitals-boot)
#   make DEBUG=1            libssl with a debug log of calls and what each connection does: the CA
#                           store, the handshake, which CA the chain comes from or why it was
#                           refused, the server's alerts and closing, the pool (build/vitals-ssl-debug1)
#   make DEBUG=2            also every read and write and the HTTP headers that go by, secrets as
#                           their length (build/vitals-ssl-debug2)
#   make http [DEBUG=N] [USER_AGENT=...]   vitals' libhttp (build/vitals-http, or -debugN: 1 calls,
#                           connections and handshakes, 2 also getters, reads and headers, secrets as
#                           their length); USER_AGENT replaces "libhttp/4.9.3-000 (CellOS)" in the
#                           default agent, as the Vita's (useragent.txt on the console overrides it)
#   make plugin [DEBUG=N] [XMB=1] [XMB_DRY_RUN=1]
#                           the boot plugin (build/vitals-boot, or -debugN: 1 what happened at boot,
#                           2 also addresses, codes and times); XMB=1 builds in vitals' TLS for the
#                           XMB itself, off otherwise (it crashes games: -xmb, for
#                           working on it, never packaged); XMB_DRY_RUN=1 checks the XMB and loads
#                           vitals' libssl into it without patching it (-xmb-dry-run, never packaged);
#                           XMB_DRY_RUN=keep also leaves it loaded, for what its memory alone does
#                           (-xmb-keep); XMB_DRY_RUN=watch loads nothing and only watches the XMB's
#                           free memory (-xmb-watch)
#   make dns-plugin [DEBUG=N]   vitals' DNS kernel plugin, build/vitals-dns/vitals_dns.bin (the raw
#                           image Cobra loads, checked to be the same wherever it's linked), or
#                           -debugN's (1 what it did, 2 also where it is)
#   make http-probe         the libhttp probe (build/http-probe); tools/http_probe.sh runs it in RPCS3
#   make app [SIGNED=1]     the vitals app, build/vitals-app/vitals-app.pkg: the three debug levels'
#                           builds of libssl, libhttp, the boot plugin and the DNS kernel plugin, Mozilla's CA bundle, the example
#                           redirects.txt and dns.txt and the changelog inside
#   make update-certs       refreshes the app's Mozilla CA bundle (vitals-app/assets/) from curl,
#                           checked against curl's SHA-256; review and commit the result
#   make preview            the app's screens drawn on this Mac with made-up data (build/preview/)
#   make test               the host tests (this machine's compiler, Python 3 and openssl): libssl's,
#                           the libhttp probe against vitals' libhttp and libssl (PS3DK's cell/http
#                           and cell/ssl headers copied out of the SDK image first), the app's
#                           (vitals-app/tests)
#   make rpcs3 APP=<app.elf> [DEBUG=N] [SECONDS=60]   runs the app in RPCS3 with that libssl in Sony's place
#   make install [DEBUG=N] [SIGNED=1]   puts that libssl and libhttp, the boot plugin, the DNS
#                           kernel plugin, Mozilla's CA bundle and the example lists on the console
#                           (tools/ps3_comms.py); not SIGNED=1 on a console: the PlayStation Store
#                           app hangs on a black screen loading the real-signed libssl and libhttp
#   make uninstall, make reboot, make log, make status   tools/ps3_comms.py's
#   make upload-app [SIGNED=1]   builds the app and puts it in the console's /dev_hdd0/packages/
#   make pull               pulls the newest published image (nyirsh/vitals-ps3-sdk:latest)
# The console is PS3_HOST in .env (cp .env.example .env), or make's or the environment's PS3_HOST

DEBUG ?= 0
SIGNED ?= 0
USER_AGENT ?= libhttp/4.9.3-000 (CellOS)
SECONDS ?= 60
# The build image, as published (also ghcr.io/nyirsh/vitals-ps3-sdk); IMAGE= for another tag
IMAGE ?= nyirsh/vitals-ps3-sdk:latest

ifneq ($(filter rpcs3,$(MAKECMDGOALS)),)
ifeq ($(APP),)
$(error make rpcs3 APP=<app.elf>: the app to run)
endif
endif

ifeq ($(filter 0 1 2,$(DEBUG)),)
$(error DEBUG must be 0, 1 or 2)
endif

# The console: on make's command line (make reboot PS3_HOST=...), else tools/ps3_comms.py reads .env
$(foreach v,PS3_HOST PS3_PORT PS3_HTTP_PORT,$(if $($(v)),$(eval export $(v))))

SSL_DIR = build/vitals-ssl$(if $(filter-out 0,$(DEBUG)),-debug$(DEBUG))
SSL_MODULE = $(SSL_DIR)/libssl.fake.sprx
HTTP_DIR = build/vitals-http$(if $(filter-out 0,$(DEBUG)),-debug$(DEBUG))
BOOT_DIR = build/vitals-boot$(if $(filter-out 0,$(DEBUG)),-debug$(DEBUG))$(if $(filter 1,$(XMB_DRY_RUN)),-xmb-dry-run)$(if $(filter keep,$(XMB_DRY_RUN)),-xmb-keep)$(if $(filter watch,$(XMB_DRY_RUN)),-xmb-watch)$(if $(filter 1,$(XMB)),-xmb)
DNS_DIR = build/vitals-dns$(if $(filter-out 0,$(DEBUG)),-debug$(DEBUG))
TOOLCHAIN = /opt/ps3dk-src/cmake/ps3-ppu-toolchain.cmake
# A command in the image, in this folder: the whole repository is /src, so the build sees ../VERSION
# and ../version.cmake
DOCKER = docker run --rm -v "$(abspath $(CURDIR)/..)":/src -w /src/ps3 $(IMAGE) bash -c
ENV = source /opt/ps3dk-src/scripts/env.sh >/dev/null
# Mozilla's CA bundle: VITALS_BUNDLE, else the app's own copy
BUNDLE = $(or $(VITALS_BUNDLE),vitals-app/assets/mozilla-certs.pem)
SPRX = $(if $(filter 1,$(SIGNED)),.sprx,.fake.sprx)
APP_STAGING = build/vitals-app/pkg_files
VERSION = $(shell cat ../VERSION)
INSTALL_FLAGS =$(if $(filter 1,$(SIGNED)),--signed) $(if $(filter-out 0,$(DEBUG)),--debug $(DEBUG))

all: ssl plugin

ssl:
	$(DOCKER) '$(ENV) && cmake -Wno-deprecated -G Ninja -S vitals-ssl -B $(SSL_DIR) -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DVITALS_DEBUG=$(DEBUG) && cmake --build $(SSL_DIR)'

# libhttp rewritten (README, plan step 5), with DEBUG's log as libssl's (build/vitals-http-debugN);
# what isn't written yet says it was called
http:
	$(DOCKER) '$(ENV) && cmake -Wno-deprecated -G Ninja -S vitals-http -B $(HTTP_DIR) -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DVITALS_DEBUG=$(DEBUG) "-DVITALS_HTTP_USER_AGENT=$(USER_AGENT)" && cmake --build $(HTTP_DIR)'

# vitals' DNS kernel plugin (vitals-dns/kernel): the raw image Cobra loads (tools/build_dns_plugin.sh)
dns-plugin:
	$(DOCKER) 'tools/build_dns_plugin.sh $(DEBUG)'

# The libhttp probe (tests/http-probe): Sony's libhttp's behaviour line by line, in RPCS3 with
# tools/http_probe.sh, to diff vitals' against
http-probe:
	$(DOCKER) '$(ENV) && cmake -Wno-deprecated -G Ninja -S tests/http-probe -B build/http-probe \
		-DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) && cmake --build build/http-probe'

# The boot plugin, with DEBUG's log (build/vitals-boot-debugN)
plugin:
	$(DOCKER) '$(ENV) && cmake -Wno-deprecated -G Ninja -S vitals-boot -B $(BOOT_DIR) -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DVITALS_DEBUG=$(DEBUG) -DVITALS_XMB_DRY_RUN=$(if $(filter 1 keep watch,$(XMB_DRY_RUN)),ON,OFF) \
		-DVITALS_XMB_KEEP_LOADED=$(if $(filter keep,$(XMB_DRY_RUN)),ON,OFF) \
		-DVITALS_XMB_WATCH_ONLY=$(if $(filter watch,$(XMB_DRY_RUN)),ON,OFF) \
		-DVITALS_XMB=$(if $(filter 1,$(XMB)),ON,OFF) && cmake --build $(BOOT_DIR)'

# The app carries every debug level's libssl, libhttp, boot plugin and DNS plugin, so all twelve are
# built first
app:
	$(MAKE) ssl DEBUG=0
	$(MAKE) ssl DEBUG=1
	$(MAKE) ssl DEBUG=2
	$(MAKE) http DEBUG=0
	$(MAKE) http DEBUG=1
	$(MAKE) http DEBUG=2
	$(MAKE) plugin DEBUG=0
	$(MAKE) plugin DEBUG=1
	$(MAKE) plugin DEBUG=2
	$(MAKE) dns-plugin DEBUG=0
	$(MAKE) dns-plugin DEBUG=1
	$(MAKE) dns-plugin DEBUG=2
	@[ -f "$(BUNDLE)" ] || { echo "$(BUNDLE) is missing: set VITALS_BUNDLE to Mozilla's CA bundle" >&2; exit 1; }
	rm -rf build/vitals-app/pkg_files
	@# The package's rule doesn't see the staged files change: without the old package, it's built again
	rm -f build/vitals-app/vitals-app*.pkg
	mkdir -p $(APP_STAGING)/USRDIR
	cp build/vitals-ssl/libssl$(SPRX) $(APP_STAGING)/USRDIR/libssl.sprx
	cp build/vitals-ssl-debug1/libssl$(SPRX) $(APP_STAGING)/USRDIR/libssl-debug1.sprx
	cp build/vitals-ssl-debug2/libssl$(SPRX) $(APP_STAGING)/USRDIR/libssl-debug2.sprx
	cp build/vitals-http/libhttp$(SPRX) $(APP_STAGING)/USRDIR/libhttp.sprx
	cp build/vitals-http-debug1/libhttp$(SPRX) $(APP_STAGING)/USRDIR/libhttp-debug1.sprx
	cp build/vitals-http-debug2/libhttp$(SPRX) $(APP_STAGING)/USRDIR/libhttp-debug2.sprx
	cp build/vitals-boot/vitals_boot$(SPRX) $(APP_STAGING)/USRDIR/vitals_boot.sprx
	cp build/vitals-boot-debug1/vitals_boot$(SPRX) $(APP_STAGING)/USRDIR/vitals_boot-debug1.sprx
	cp build/vitals-boot-debug2/vitals_boot$(SPRX) $(APP_STAGING)/USRDIR/vitals_boot-debug2.sprx
	cp build/vitals-dns/vitals_dns.bin $(APP_STAGING)/USRDIR/vitals_dns.bin
	cp build/vitals-dns-debug1/vitals_dns.bin $(APP_STAGING)/USRDIR/vitals_dns-debug1.bin
	cp build/vitals-dns-debug2/vitals_dns.bin $(APP_STAGING)/USRDIR/vitals_dns-debug2.bin
	cp "$(BUNDLE)" $(APP_STAGING)/USRDIR/cacert.pem
	cp vitals-app/assets/redirects.txt vitals-app/assets/dns.txt $(APP_STAGING)/USRDIR/
	cp ../CHANGELOG.md $(APP_STAGING)/USRDIR/CHANGELOG.md
	cp CREDITS.md $(APP_STAGING)/USRDIR/CREDITS.md
	@# The third-party notices and the licenses they refer to, as the Vita's app carries them
	mkdir -p $(APP_STAGING)/USRDIR/licenses
	cp ../THIRD_PARTY_NOTICES.md $(APP_STAGING)/USRDIR/THIRD_PARTY_NOTICES.md
	cp ../licenses/*.txt $(APP_STAGING)/USRDIR/licenses/
	cp vitals-app/pkg/PIC1.PNG $(APP_STAGING)/PIC1.PNG
	$(DOCKER) '$(ENV) && cmake -Wno-deprecated -G Ninja -S vitals-app -B build/vitals-app -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DSTAGING=/src/ps3/$(APP_STAGING) && cmake --build build/vitals-app'

# The screens as BMPs and PNGs (sips), with CoreText's Helvetica Neue for the PS3's font
preview:
	mkdir -p build/preview
	clang -std=c11 -Wall -Wextra -DVITALS_VERSION='"$(VERSION)"' -Ivitals-app/src -Icommon -I../shared/app -I../shared/include \
		vitals-app/host/preview.c vitals-app/host/font_host.c ../shared/app/ui.c ../shared/app/font.c ../shared/app/changelog.c \
		vitals-app/src/check_model.c -framework CoreText -framework CoreGraphics -framework CoreFoundation \
		-o build/preview/preview
	build/preview/preview build/preview
	build/preview/preview build/preview 1080
	for f in build/preview/*.bmp; do sips -s format png "$$f" --out "$${f%.bmp}.png" >/dev/null; done

test: build/ps3dk-include/cell/http.h
	cmake -Wno-deprecated -S tests/host -B build/tests-host
	cmake --build build/tests-host -j8
	ctest --test-dir build/tests-host --output-on-failure
	cmake -Wno-deprecated -S vitals-app/tests -B build/vitals-app-tests
	cmake --build build/vitals-app-tests -j8
	ctest --test-dir build/vitals-app-tests --output-on-failure
	python3 -m unittest discover -s vitals-app/tests -p 'test_*.py'


rpcs3: ssl
	tools/rpcs3_run.sh $(SSL_MODULE) "$(APP)" $(SECONDS)

install: ssl http plugin dns-plugin
	python3 tools/ps3_comms.py install $(INSTALL_FLAGS)

# The app's Mozilla bundle, from curl (tools/update_certs.py)
update-certs:
	python3 tools/update_certs.py

upload-app: app
	python3 tools/ps3_comms.py app

uninstall reboot log status:
	python3 tools/ps3_comms.py $@

pull:
	docker pull $(IMAGE)

# Every build folder (each debug level's and the XMB builds' too); not build/'s other files
clean:
	rm -rf build/vitals-ssl build/vitals-ssl-debug* build/vitals-boot build/vitals-boot-* build/vitals-dns \
		build/vitals-dns-debug* build/vitals-http build/vitals-http-debug* build/vitals-app build/http-probe build/preview \
		build/tests-host build/vitals-app-tests

# PS3DK's headers the probe's host run needs (tests/host/CMakeLists.txt)
build/ps3dk-include/cell/http.h:
	mkdir -p build/ps3dk-include
	docker run --rm $(IMAGE) bash -c 'cd /opt/ps3dk-src/stage/ps3dev/ps3dk/ppu/include && \
		tar cf - cell/http.h cell/http cell/ssl.h cell/ssl cell/rtc.h cell/error.h' | tar xf - -C build/ps3dk-include
	docker run --rm $(IMAGE) cat /opt/ps3dk-src/LICENSE > build/ps3dk-include/LICENSE

.PHONY: dns-plugin update-certs all ssl http http-probe plugin app upload-app preview test rpcs3 install uninstall reboot log status pull clean
