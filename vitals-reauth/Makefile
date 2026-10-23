# Builds vitals-reauth.suprx, the user module that sends PSN sign-in to its new host
# Everything is built in build/ at the repository root
BUILD_DIR := $(abspath ../build)
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

# Debug output on the Vita's debug console: 0 none, 1 or 2 log each hook and redirect
# Each level builds in its own folder (vitals-reauth, vitals-reauth-debug1, vitals-reauth-debug2),
# as the app carries all three
DEBUG ?= 0
OUT_DIR = $(BUILD_DIR)/vitals-reauth$(if $(filter 0,$(DEBUG)),,-debug$(DEBUG))

all:
	cmake -S . -B $(OUT_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN) -DCMAKE_BUILD_TYPE=Release \
		-DVITALS_DEBUG=$(DEBUG)
	cmake --build $(OUT_DIR)

# Host test of the module against stand-ins for taiHEN (no VitaSDK needed); its injection is
# tested with the kernel plugin
TEST_DIR = $(BUILD_DIR)/vitals-reauth-tests

test:
	cmake -S tests -B $(TEST_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(TEST_DIR) -j4
	ctest --test-dir $(TEST_DIR) --output-on-failure

clean:
	rm -rf $(BUILD_DIR)/vitals-reauth $(BUILD_DIR)/vitals-reauth-debug1 $(BUILD_DIR)/vitals-reauth-debug2 $(TEST_DIR)

.PHONY: all clean test
