# A temporary diagnostic, not part of the release build: make -C vitals-diag
BUILD_DIR := $(abspath ../build)
OUT_DIR = $(BUILD_DIR)/vitals-diag
VITA_TOOLCHAIN = $(VITASDK)/share/vita.toolchain.cmake

all:
	cmake -S . -B $(OUT_DIR) -DCMAKE_TOOLCHAIN_FILE=$(VITA_TOOLCHAIN) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(OUT_DIR)

.PHONY: all
