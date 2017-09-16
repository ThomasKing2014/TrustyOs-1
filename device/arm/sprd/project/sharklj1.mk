#
# Copyright (c) 2017, Spreadtrum Communications.
#
# The above copyright notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

KERNEL_32BIT := false

DEBUG ?= 2
SMP_MAX_CPUS ?= 8
SMP_CPU_CLUSTER_SHIFT ?= 2

TARGET := sharklj1
# force enums to be 4bytes. This options must be set, or keymaster app will crash.
ARCH_arm_COMPILEFLAGS := -mabi=aapcs-linux

ifeq (false,$(call TOBOOL,$(KERNEL_32BIT)))

# Arm64 address space configuration
KERNEL_ASPACE_BASE := 0xffffffffe0000000
KERNEL_ASPACE_SIZE := 0x0000000020000000
KERNEL_BASE        := 0xffffffffe0000000
MEMBASE         := 0x94100000
GLOBAL_DEFINES += MMU_USER_SIZE_SHIFT=25 # 32 MB user-space address space

else

KERNEL_BASE        := 0x94100000

endif

MEMSIZE := $(TOS_MEM_SIZE)

ifneq ($(strip $(FINGERPRINT_VENDOR)),)
BOOT_MEM_OFFSET := 0x3e0000
else
BOOT_MEM_OFFSET := 0x180000
endif

# select timer
ifeq (true,$(call TOBOOL,$(KERNEL_32BIT)))
# 32 bit Secure EL1 with a 64 bit EL3 gets the non-secure physical timer
GLOBAL_DEFINES += TIMER_ARM_GENERIC_SELECTED=CNTV
else
GLOBAL_DEFINES += TIMER_ARM_GENERIC_SELECTED=CNTPS
endif

# true : Use hardware algorithms ( ECC && RSA ) replace software ones in openssl.
# false : Use software algorithms. default : true
SPRD_CONFIG_HW_RSA_ECC:=true
ifeq ($(strip $(SPRD_CONFIG_HW_RSA_ECC)), true)
GLOBAL_DEFINES += SPRD_HARDWARE_RSA_ECC=1
else
GLOBAL_DEFINES += SPRD_HARDWARE_RSA_ECC=0
endif

#
# GLOBAL definitions
#

# requires linker GC
WITH_LINKER_GC := 1

# Need support for Non-secure memory mapping
WITH_NS_MAPPING := true

# do not relocate kernel in physical memory
GLOBAL_DEFINES += WITH_NO_PHYS_RELOCATION=1

# limit heap grows
GLOBAL_DEFINES += HEAP_GROW_SIZE=8192

# external ta support
GLOBAL_DEFINES += WITH_MEMLOG_EARLY=1 \
		  WITH_USER_TASK_ATTACH=1
GLOBAL_DEFINES += TRUSTY_KEYMASTER_VERSION=$(TRUSTY_KEYMASTER_VERSION)
# limit physical memory to 38 bit to prevert tt_trampiline from getting larger than arm64_kernel_translation_table
GLOBAL_DEFINES += MMU_IDENT_SIZE_SHIFT=38

GLOBAL_INCLUDES += external/lk/platform/sprd/firewall/sharklj1/inc
GLOBAL_INCLUDES += external/lk/platform/sprd/pal/inc
GLOBAL_INCLUDES += external/lk/platform/sprd/soc/sharklj1/include \
		external/lk/platform/sprd/soc

#rpmb 512k,main 1024*1024*4040
GLOBAL_DEFINES += \
    APP_STORAGE_RPMB_BLOCK_SIZE=512 \
    APP_STORAGE_RPMB_BLOCK_COUNT=1024 \
    APP_STORAGE_MAIN_BLOCK_SIZE=4040 \
    APP_STORAGE_MAIN_BLOCK_COUNT=1048576 \

#GLOBAL_DEFINES += \
#	ENABLE_CONSOLE=1 \
#   DISABLE_DEBUG_OUTPUT=1 \

ifeq ($(strip $(CONFIG_SPRD_FIREWALL)),true)
GLOBAL_DEFINES += CONFIG_SPRD_FIREWALL=1
endif

ifeq ($(strip $(CONFIG_SPRD_FIREWALL_ILLEGAL_ACCESS_DETECT)),true)
GLOBAL_DEFINES += CONFIG_SPRD_FIREWALL_ILLEGAL_ACCESS_DETECT=1
endif

CONFIG_SPRD_SECBOOT := 1
GLOBAL_DEFINES += CONFIG_SPRD_SECBOOT=1

#
# Modules to be compiled into lk.bin
#
MODULES += \
	lib/sm \
	lib/trusty \
	lib/memlog \
	lib/sprdsec/arm \
	platform/sprd/efuse \
	platform/sprd/crypto/sprd \
	platform/sprd/firewall/sharklj1 \
	platform/sprd/secureboot/sprd \

MODULES += \
    platform/sprd/clk \
    platform/sprd/hwspinlock \
    platform/sprd/spi \
    platform/sprd/gpio \
    platform/sprd/i2c

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
  $(shell pwd)/../../partner/chipone/sharklj1/fp_ta.elf
endif
endif

# compiled from source
TRUSTY_ALL_USER_TASKS := \
    keymaster \
    gatekeeper \
    storage \
    app/sample/ipc-unittest/srv \
    kernelbootcp \
    production \
    crypto \

# This project requires trusty IPC
WITH_TRUSTY_IPC := true

EXTRA_BUILDRULES += app/trusty/user-tasks.mk
