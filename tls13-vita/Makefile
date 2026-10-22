# Builds the TLS providers: vitals_http.suprx (system HTTP) and vitals.suprx (browser)
# Everything is built in build/ at the repository root
BUILD_DIR := $(abspath ../build)
OUT_DIR = $(BUILD_DIR)/tls13-vita
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

# Provider heap (KiB) per injected process
HTTP_HEAP_KIB ?= 128
# Debug output on the Vita's debug console: 0 none, 1 summaries and failures, 2 everything
DEBUG ?= 0

# CMake tracks what is out of date; the settings are passed every time so a stale cache
# cannot change the build
all:
	# -Wno-deprecated: upstream Mbed TLS still declares cmake_minimum_required(VERSION 3.5)
	cmake -Wno-deprecated -S . -B $(OUT_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DVITALS_BUILD_VITA_PROVIDER=ON \
		-DVITALS_DEBUG=$(DEBUG) \
		-DVITALS_HTTP_HEAP_KIB=$(HTTP_HEAP_KIB) \
		-DVITALS_HTTP_CA_PATH=vs0:/data/external/cert/CA_LIST.cer \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN)
	cmake --build $(OUT_DIR)
	cmake --build $(OUT_DIR) --target vitals.suprx-self

# Host tests of the providers and the shared core, built for this machine, then those of the
# Makefile (no VitaSDK needed)
# The loopback TLS and most browser tests place memory at fixed low addresses, as the Vita's 32-bit
# pointers need, which only Linux allows; elsewhere CMake leaves them out
TEST_DIR = $(BUILD_DIR)/tls13-vita-tests

test:
	cmake -Wno-deprecated -S . -B $(TEST_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DVITALS_BUILD_HOST_TESTS=ON \
		-DVITALS_BUILD_TRANSPORT_TESTS=ON \
		-DVITALS_ENABLE_SANITIZERS=ON \
		-DCMAKE_BUILD_TYPE=Debug
	cmake --build $(TEST_DIR) -j4
	ctest --test-dir $(TEST_DIR) --output-on-failure
	python3 -m unittest discover -s tests -p 'test_*.py'
ifneq ($(shell uname -s),Linux)
	@echo "tls13-vita: the loopback TLS and most browser tests need Linux and were left out"
endif

clean:
	rm -rf $(OUT_DIR) $(TEST_DIR)

.PHONY: all clean test
