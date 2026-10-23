# Builds vitals-app.vpk: the vitals app (installer and connection test), packaged with the kernel
# plugin, TLS providers and PSN redirect it installs
# Those come from ../vitals-plugin, ../tls13-vita and ../vitals-reauth, which are built first
# Everything is built in build/ at the repository root
BUILD_DIR := $(abspath ../build)
OUT_DIR = $(BUILD_DIR)/vitals-app
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

all: modules
	cmake -S . -B $(OUT_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(OUT_DIR)

# The plugin, providers and redirect have their own Makefiles; CMake decides what to rebuild
# The providers and redirect are built at every debug level, which the app lets users switch
# between
modules:
	$(MAKE) -C ../vitals-plugin
	$(foreach level,0 1 2,$(MAKE) -C ../tls13-vita DEBUG=$(level) &&) true
	$(foreach level,0 1 2,$(MAKE) -C ../vitals-reauth DEBUG=$(level) &&) true

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
	rm -rf $(OUT_DIR) $(TEST_DIR)

.PHONY: all clean modules update-certs test
