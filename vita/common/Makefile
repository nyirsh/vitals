# The code every Vita module shares (as the PS3's common/): vitals' headers (include/vitals), the
# core library (src/, core.cmake) and the user-mode runtime the modules link without a C library
# (runtime/). Nothing to build on its own: each module builds what it uses
# Everything is built in build/ at the repository root
BUILD_DIR := $(abspath ../build)

all:

# Host tests of the core library and the runtime, built for this machine (no VitaSDK needed)
TEST_DIR = $(BUILD_DIR)/common-tests

test:
	cmake -S . -B $(TEST_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(TEST_DIR) -j4
	ctest --test-dir $(TEST_DIR) --output-on-failure

clean:
	rm -rf $(TEST_DIR)

.PHONY: all clean test
