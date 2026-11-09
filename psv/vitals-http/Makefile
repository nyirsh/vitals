# Builds libhttp.suprx, the libhttp written from scratch, on vitals-ssl (the libssl module), whose
# stub ../vitals-ssl's build makes
# Everything is built in build/ at the repository root
BUILD_DIR := $(abspath ../build)
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

# The heap (KiB) per process for what TLS keeps here, apart from the pools the app gives sceHttpInit
# and sceSslInit
TLS_HEAP_KIB ?= 64
# What follows an app's own User-Agent, unless ux0:data/vitals/useragent.txt gives another
USER_AGENT ?= libhttp/3.74 (PS Vita)
# Debug output on the Vita's debug console: 0 none, 1 connections and failures, 2 every TLS step
DEBUG ?= 0
OUT_DIR = $(BUILD_DIR)/vitals-http$(if $(filter 0,$(DEBUG)),,-debug$(DEBUG))

all:
	cmake -S . -B $(OUT_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN) -DCMAKE_BUILD_TYPE=Release \
		-DVITALS_DEBUG=$(DEBUG) -DVITALS_HTTP_TLS_HEAP_KIB=$(TLS_HEAP_KIB) \
		"-DVITALS_HTTP_USER_AGENT=$(USER_AGENT)"
	cmake --build $(OUT_DIR)

# Host tests: the library built for this machine (tests/platform_posix.c in place of the Vita's)
# with vitals-ssl and the real Mbed TLS built in, against a local HTTP and HTTPS server; they need VitaSDK's
# <psp2/net/http.h> and are skipped without it
TEST_DIR = $(BUILD_DIR)/vitals-http-tests

test:
ifeq ($(VITASDK),)
	@echo "vitals-http: VITASDK is not set; its host tests were skipped"
else
	cmake -Wno-deprecated -S tests -B $(TEST_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(TEST_DIR) -j4
	ctest --test-dir $(TEST_DIR) --output-on-failure
endif

clean:
	rm -rf $(BUILD_DIR)/vitals-http $(BUILD_DIR)/vitals-http-debug1 $(BUILD_DIR)/vitals-http-debug2 $(TEST_DIR)

.PHONY: all clean test
