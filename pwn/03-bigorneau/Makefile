ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(ROOT_DIR)/build
SHELLCODES_DIR ?= $(ROOT_DIR)/shellcodes
SHELLCODES ?= stage0 stage1

.PHONY: all shellcodes

all: shellcodes

shellcodes: $(patsubst %,$(BUILD_DIR)/%.bin,$(SHELLCODES))

$(BUILD_DIR)/%.o: $(SHELLCODES_DIR)/%.S
	mkdir -p $(BUILD_DIR)
	as -msyntax=intel -o $@ $<

$(BUILD_DIR)/%.elf: $(BUILD_DIR)/%.o
	ld --oformat=elf64-x86-64 -o $@ $<

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	objcopy -O binary -j .text $< $@
	r2 -q -c 'pd 20' $@
	python check.py $@

clean:
	rm -rf $(BUILD_DIR)
