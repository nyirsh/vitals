# Builds vitals-reauth.suprx, the user module that sends PSN sign-in to its new host
# Everything is built in build/ at the repository root
BUILD_DIR := $(abspath ../build)
OUT_DIR = $(BUILD_DIR)/vitals-reauth
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

# Debug output on the Vita's debug console: 0 none, 1 or 2 log each hook and redirect
DEBUG ?= 0

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
	rm -rf $(OUT_DIR) $(TEST_DIR)

.PHONY: all clean test
