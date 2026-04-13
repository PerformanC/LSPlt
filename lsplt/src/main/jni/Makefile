NDK_PATH ?= $(HOME)/Android/Sdk/ndk/29.0.13113456
API_LEVEL ?= 26
ARCH ?= arm64-v8a
BUILD_TYPE ?= debug
out ?= build/$(BUILD_TYPE)/$(ARCH)

TOOLCHAIN = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64
SYSROOT = $(TOOLCHAIN)/sysroot
CC = $(TOOLCHAIN)/bin/clang
AR = $(TOOLCHAIN)/bin/llvm-ar

TARGET_arm64-v8a = aarch64-linux-android$(API_LEVEL)
TARGET_armeabi-v7a = armv7a-linux-androideabi$(API_LEVEL)
TARGET_x86 = i686-linux-android$(API_LEVEL)
TARGET_x86_64 = x86_64-linux-android$(API_LEVEL)

CC_ARCH = $(CC) --target=$(TARGET_$(ARCH)) --sysroot=$(SYSROOT)

CFLAGS = -std=c99 -DANDROID -Wall -fPIC

ifeq ($(BUILD_TYPE),release)
	CFLAGS += -O3 -flto
else
	CFLAGS += -g -O0
endif

LIB = $(out)/liblsplt.a

.PHONY: all clean

all: $(LIB)

$(out)/lsplt.o: lsplt.c
	@mkdir -p $(out)
	$(CC_ARCH) $(CFLAGS) -Iinclude -I. -c $< -o $@

$(out)/elf_util.o: elf_util.c
	@mkdir -p $(out)
	$(CC_ARCH) $(CFLAGS) -Iinclude -I. -c $< -o $@

$(LIB): $(out)/lsplt.o $(out)/elf_util.o
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

clean:
	rm -rf build
