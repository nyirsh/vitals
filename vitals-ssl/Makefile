# Builds libssl.suprx, the libssl written from scratch (its connection functions so far)
# Everything is built in build/ at the repository root; nothing installs it yet
BUILD_DIR := $(abspath ../build)
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

# Debug output on the Vita's debug console: 0 none, 1 connections, failures and calls to unwritten
# exports, 2 also Mbed TLS's own messages
DEBUG ?= 0
OUT_DIR = $(BUILD_DIR)/vitals-ssl$(if $(filter 0,$(DEBUG)),,-debug$(DEBUG))

all:
	# -Wno-deprecated: upstream Mbed TLS still declares cmake_minimum_required(VERSION 3.5)
	cmake -Wno-deprecated -S . -B $(OUT_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN) -DCMAKE_BUILD_TYPE=Release \
		-DVITALS_DEBUG=$(DEBUG)
	cmake --build $(OUT_DIR)

# Host tests: the library built for this machine (tests/platform_posix.c in place of the Vita's)
# with the real Mbed TLS, against a local TLS server; they need VitaSDK's <psp2/libssl.h> and are
# skipped without it
TEST_DIR = $(BUILD_DIR)/vitals-ssl-tests

test:
ifeq ($(VITASDK),)
	@echo "vitals-ssl: VITASDK is not set; its host tests were skipped"
else
	cmake -Wno-deprecated -S tests -B $(TEST_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(TEST_DIR) -j4
	ctest --test-dir $(TEST_DIR) --output-on-failure
endif

clean:
	rm -rf $(BUILD_DIR)/vitals-ssl $(BUILD_DIR)/vitals-ssl-debug1 $(BUILD_DIR)/vitals-ssl-debug2 $(TEST_DIR)

.PHONY: all clean test
