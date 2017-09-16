# Copyright (C) 2017 spreadtrum


LOCAL_DIR := $(GET_LOCAL_DIR)

TARGET := pike2

#
# GLOBAL definitions
#

# requires linker GC
WITH_LINKER_GC := 1

# force enums to be 4bytes
ARCH_arm_COMPILEFLAGS := -mabi=aapcs-linux

# Disable VFP and NEON for now
ARM_WITHOUT_VFP_NEON := true

# Need support for Non-secure memory mapping
WITH_NS_MAPPING := true

# This project requires trusty IPC
WITH_TRUSTY_IPC := true

# do not relocate kernel in physical memory
GLOBAL_DEFINES += WITH_NO_PHYS_RELOCATION=1

# limit heap grows
GLOBAL_DEFINES += HEAP_GROW_SIZE=65536


#rpmb 512k
GLOBAL_DEFINES += \
    APP_STORAGE_RPMB_BLOCK_SIZE=512 \
    APP_STORAGE_RPMB_BLOCK_COUNT=1024 \

GLOBAL_DEFINES += \
    ENABLE_CONSOLE=1 \
#    DISABLE_DEBUG_OUTPUT=1 \



CONFIG_SPRD_SECBOOT := 1
GLOBAL_DEFINES += CONFIG_SPRD_SECBOOT=1

MEMBASE := 0x94100000
MEMSIZE := $(TOS_MEM_SIZE)

WITH_SMP := 1
GLOBAL_DEFINES += TRUSTY_KEYMASTER_VERSION=$(TRUSTY_KEYMASTER_VERSION)
#
# defien the path of soc header files
#
GLOBAL_INCLUDES += external/lk/platform/sprd/pike2/include
GLOBAL_INCLUDES += external/lk/platform/sprd/soc

#
# Modules to be compiled into lk.bin
#
MODULES += \
    lib/sm \
    lib/trusty \
    lib/memlog \

MODULES += \
    platform/sprd/clk \
    platform/sprd/hwspinlock \
    platform/sprd/spi \
    platform/sprd/gpio \
    platform/sprd/i2c


TRUSTY_USER_ARCH := arm

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS :=

# External ta
TRUSTY_EXTERNAL_USER_TASKS :=

# compiled from source
TRUSTY_ALL_USER_TASKS := \
    sample/ipc-unittest/srv \
    keymaster \
    gatekeeper \
    storage \


EXTRA_BUILDRULES += app/trusty/user-tasks.mk
