# Builds vitals-app.vpk: the vitals app (installer and connection test), packaged with the kernel
# plugin, vitals-http, vitals-ssl and the browser provider it installs
# Those come from ../vitals-plugin, ../vitals-http, ../vitals-ssl and ../tls13-vita, which are built
# first
# Everything is built in build/ at the repository root
BUILD_DIR := $(abspath ../build)
# 1 builds the vitals-ssl test app instead (build/vitals-app-ssltest/vitals-app.vpk, title
# VITALSSL1): installed from it, the plugin gives that app Sony's libhttp on vitals-ssl, whose
# debug build it carries; for testing vitals-ssl on a console, never released
SSL_TEST ?= 0
OUT_DIR = $(BUILD_DIR)/vitals-app$(if $(filter 1,$(SSL_TEST)),-ssltest)
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

all: modules
	cmake -S . -B $(OUT_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN) -DCMAKE_BUILD_TYPE=Release \
		-DVITALS_SSL_TEST=$(if $(filter 1,$(SSL_TEST)),ON,OFF)
	cmake --build $(OUT_DIR)

# The plugin, vitals-http, vitals-ssl and the providers have their own Makefiles; CMake decides what
# to rebuild. All of them are built at every debug level, which the app lets users switch between
modules:
	$(foreach level,0 1 2,$(MAKE) -C ../vitals-plugin DEBUG=$(level) SSL_TEST=$(SSL_TEST) &&) true
	$(foreach level,0 1 2,$(MAKE) -C ../vitals-ssl DEBUG=$(level) &&) true
	$(foreach level,0 1 2,$(MAKE) -C ../vitals-http DEBUG=$(level) &&) true
	$(foreach level,0 1 2,$(MAKE) -C ../tls13-vita DEBUG=$(level) &&) true

# Refreshes the bundled Mozilla certificates (assets/) from curl; review and commit the result
update-certs:
	python3 tools/update_certs.py

# Host tests, built for this machine (no VitaSDK needed): the C tests of the install options,
# config.txt editing and OpenSSL locking, then the Python tests of the certificate download and
# updater, which need a real HTTPS server
TEST_DIR = $(BUILD_DIR)/vitals-app-tests

test:
	cmake -S tests -B $(TEST_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(TEST_DIR) -j4
	ctest --test-dir $(TEST_DIR) --output-on-failure
	python3 -m unittest discover -s tests -p 'test_*.py'

clean:
	rm -rf $(BUILD_DIR)/vitals-app $(BUILD_DIR)/vitals-app-ssltest $(TEST_DIR)

.PHONY: all clean modules update-certs test
