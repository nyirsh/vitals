# Builds libssl.suprx, the libssl written from scratch (a skeleton for now: every export fails)
# Everything is built in build/ at the repository root; nothing installs it yet
BUILD_DIR := $(abspath ../build)
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

# Debug output on the Vita's debug console: 0 none, 1 start-up and calls to unwritten exports
DEBUG ?= 0
OUT_DIR = $(BUILD_DIR)/vitals-ssl$(if $(filter 0,$(DEBUG)),,-debug$(DEBUG))

all:
	cmake -Wno-deprecated -S . -B $(OUT_DIR) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN) -DCMAKE_BUILD_TYPE=Release \
		-DVITALS_DEBUG=$(DEBUG)
	cmake --build $(OUT_DIR)

# No host tests yet
test:
	@echo "vitals-ssl: no host tests yet"

clean:
	rm -rf $(BUILD_DIR)/vitals-ssl $(BUILD_DIR)/vitals-ssl-debug1 $(BUILD_DIR)/vitals-ssl-debug2

.PHONY: all clean test
