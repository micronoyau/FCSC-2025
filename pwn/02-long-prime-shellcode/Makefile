ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(ROOT_DIR)/build
CRACKER ?= $(ROOT_DIR)/shellcode-cracker
SHELLCODES_DIR ?= $(ROOT_DIR)/shellcodes
SHELLCODES ?= bin_sh

.PHONY: all crack shellcodes

all: crack

crack: $(BUILD_DIR)/bin_sh.bin
	cd $(CRACKER) && cargo r $<

shellcodes: $(patsubst %,$(BUILD_DIR)/%.bin,$(SHELLCODES))

$(BUILD_DIR)/%.o: $(SHELLCODES_DIR)/%.S
	mkdir -p $(BUILD_DIR)
	as -msyntax=intel -o $@ $<

$(BUILD_DIR)/%.elf: $(BUILD_DIR)/%.o
	ld --oformat=elf64-x86-64 -o $@ $<

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	objcopy -O binary -j .text $< $@

clean:
	rm -rf $(BUILD_DIR)
	cd $(CRACKER) && cargo clean
