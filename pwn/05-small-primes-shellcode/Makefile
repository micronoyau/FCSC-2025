ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(ROOT_DIR)/build
CRACKER ?= $(ROOT_DIR)/shellcode-cracker
SHELLCODES_DIR ?= $(ROOT_DIR)/shellcodes
SHELLCODES ?= stage0 stage1

BUILD_TOOLS ?= /usr/aarch64-linux-gnu/bin
AS := $(BUILD_TOOLS)/as
LD := $(BUILD_TOOLS)/ld
OBJCOPY := $(BUILD_TOOLS)/objcopy

.PHONY: all vm shellcodes

all: shellcodes

shellcodes: $(patsubst %,$(BUILD_DIR)/%.bin,$(SHELLCODES))

$(BUILD_DIR)/%.o: $(SHELLCODES_DIR)/%.S
	mkdir -p $(BUILD_DIR)
	$(AS) -o $@ $<

$(BUILD_DIR)/%.elf: $(BUILD_DIR)/%.o
	$(LD) --oformat=elf64-littleaarch64 -o $@ $<

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	$(OBJCOPY) -O binary -j .text $< $@
	cd $(CRACKER) && cargo r check $@

clean:
	rm -rf $(BUILD_DIR)
	cd $(CRACKER) && cargo clean
