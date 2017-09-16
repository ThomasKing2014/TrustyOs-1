# Copyright (C) 2013-2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)
#sp9833 for sharkl2
TARGET := sharkl2-1h10

#
# GLOBAL definitions
#

# requires linker GC
WITH_LINKER_GC := 1

# force enums to be 4bytes
ARCH_arm_COMPILEFLAGS := -mabi=aapcs-linux

# Disable VFP and NEON for now
#ARM_WITHOUT_VFP_NEON := true

# Need support for Non-secure memory mapping
WITH_NS_MAPPING := true

# This project requires trusty IPC
WITH_TRUSTY_IPC := true

# do not relocate kernel in physical memory
GLOBAL_DEFINES += WITH_NO_PHYS_RELOCATION=1

# limit heap grows
GLOBAL_DEFINES += HEAP_GROW_SIZE=65536

# external ta support
GLOBAL_DEFINES += WITH_MEMLOG_EARLY=1 \
		  WITH_USER_TASK_ATTACH=1

#rpmb 512k Reserve block 1022-1024,main 1024*1024*4040
GLOBAL_DEFINES += \
    APP_STORAGE_RPMB_BLOCK_SIZE=512 \
    APP_STORAGE_RPMB_BLOCK_COUNT=1021 \
    APP_STORAGE_MAIN_BLOCK_SIZE=4040 \
    APP_STORAGE_MAIN_BLOCK_COUNT=1048576 \

#sprd image version save in block 1022 * 2, 1023 * 2
GLOBAL_DEFINES += \
    SPRDMODEMIMGVERSION_BLOCK_INDEX=2044 \
    SPRDIMGVERSION_BLOCK_INDEX=2046 \

#GLOBAL_DEFINES += \
#    ENABLE_CONSOLE=1 \
#    DISABLE_DEBUG_OUTPUT=1 \


CONFIG_SPRD_SECBOOT := 1
GLOBAL_DEFINES += CONFIG_SPRD_SECBOOT=1

ifeq ($(strip $(PRODUCT_VBOOT_VER)),V2)
CONFIG_VBOOT_V2 := 1
GLOBAL_DEFINES += CONFIG_VBOOT_V2=1
GLOBAL_DEFINES += AVB_ENABLE_DEBUG=1
GLOBAL_DEFINES += AVB_COMPILATION=1
endif

GLOBAL_DEFINES += CONFIG_SPRD_FIREWALL=1

# true : Use hardware algorithms ( ECC && RSA ) replace software ones in openssl.
# false : Use software algorithms. default : true
SPRD_CONFIG_HW_RSA_ECC:=true
ifeq ($(strip $(SPRD_CONFIG_HW_RSA_ECC)), true)
GLOBAL_DEFINES += SPRD_HARDWARE_RSA_ECC=1
else
GLOBAL_DEFINES += SPRD_HARDWARE_RSA_ECC=0
endif

MEMBASE := 0x94100000
MEMSIZE := $(TOS_MEM_SIZE)

ifneq ($(strip $(FINGERPRINT_VENDOR)),)
BOOT_MEM_OFFSET := 0x3e0000
else
BOOT_MEM_OFFSET := 0x180000
endif

WITH_SMP := 1

GLOBAL_DEFINES += TRUSTY_KEYMASTER_VERSION=$(TRUSTY_KEYMASTER_VERSION)

#
# defien the path of soc header files
#
GLOBAL_INCLUDES += external/lk/platform/sprd/sharkl2/include

#
# Modules to be compiled into lk.bin
#
MODULES += \
    lib/sm \
    lib/trusty \
    lib/memlog \
    lib/sprdsec/arm \
    platform/sprd/timer \
    platform/sprd/efuse \
    platform/sprd/crypto/sprd \
    platform/sprd/firewall/sharkl2 \
    platform/sprd/secureboot/sprd

MODULES += \
    platform/sprd/clk \
    platform/sprd/hwspinlock \
    platform/sprd/spi \
    platform/sprd/i2c \
    platform/sprd/gpio

MODULES += \
    platform/sprd/fingerprint/default




TRUSTY_USER_ARCH := arm

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS :=

# External ta
ifeq ($(strip $(FINGERPRINT_VENDOR)),chipone)
ifeq ($(MAKECMDGOALS),sdk)
TRUSTY_EXTERNAL_USER_TASKS :=
else
TRUSTY_EXTERNAL_USER_TASKS := \
  $(shell pwd)/../../partner/chipone/fp_ta.elf
endif
endif

# compiled from source
TRUSTY_ALL_USER_TASKS := \
    keymaster \
    gatekeeper \
    storage \
    production \
    crypto \
    rpmbproxy \

TRUSTY_ALL_USER_TASKS += \
    kernelbootcp \

EXTRA_BUILDRULES += app/trusty/user-tasks.mk
