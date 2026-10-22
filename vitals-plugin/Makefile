# Builds the vitals kernel plugin (vitals.skprx)
# Everything is built in build/ at the repository root
BUILD_DIR := $(abspath ../build)
OUT_DIR = $(BUILD_DIR)/vitals-plugin
HTTP_PROVIDER_PATH = vs0:/data/external/vitals/native/vitals_http.suprx

# CMake tracks what is out of date; the settings are passed every time so a stale cache
# cannot change the build
all:
	cmake -S . -B $(OUT_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DVITALS_HTTP_PROVIDER_PATH=$(HTTP_PROVIDER_PATH)
	cmake --build $(OUT_DIR)

# Host tests of the plugin against mocks of the Vita kernel, then those of its build check and
# Makefile (no VitaSDK needed)
TEST_DIR = $(BUILD_DIR)/vitals-plugin-tests

test:
	cmake -S tests -B $(TEST_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(TEST_DIR) -j4
	ctest --test-dir $(TEST_DIR) --output-on-failure
	python3 -m unittest discover -s tests -p 'test_*.py'

clean:
	rm -rf $(OUT_DIR) $(TEST_DIR)

.PHONY: all clean test
