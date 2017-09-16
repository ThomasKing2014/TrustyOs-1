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
KERNEL_32BIT := true

DEBUG ?= 2
SMP_MAX_CPUS ?= 2
SMP_CPU_CLUSTER_SHIFT ?= 2

TARGET := sharkle

ifeq (false,$(call TOBOOL,$(KERNEL_32BIT)))

# Arm64 address space configuration
KERNEL_ASPACE_BASE := 0xffffffffe0000000
KERNEL_ASPACE_SIZE := 0x0000000020000000
KERNEL_BASE        := 0xffffffffe0000000
MEMBASE            := $(TOS_MEM_ADDR)
GLOBAL_DEFINES += MMU_USER_SIZE_SHIFT=25 # 32 MB user-space address space

else

KERNEL_BASE        := $(TOS_MEM_ADDR)

endif

MEMSIZE := $(TOS_MEM_SIZE)

BOOT_MEM_OFFSET := 0x7D000 #500k

GLOBAL_DEFINES += SML_TOS_SIZE=$(SML_TOS_SIZE)

# select timer
ifeq (true,$(call TOBOOL,$(KERNEL_32BIT)))
# 32 bit Secure EL1 with a 64 bit EL3 gets the non-secure physical timer
GLOBAL_DEFINES += TIMER_ARM_GENERIC_SELECTED=CNTV
else
GLOBAL_DEFINES += TIMER_ARM_GENERIC_SELECTED=CNTPS
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

# limit physical memory to 38 bit to prevert tt_trampiline from getting larger than arm64_kernel_translation_table
GLOBAL_DEFINES += MMU_IDENT_SIZE_SHIFT=38

GLOBAL_DEFINES += \
    ENABLE_CONSOLE=1

#GLOBAL_DEFINES += CONFIG_SPRD_FIREWALL=1
GLOBAL_DEFINES += TRUSTY_KEYMASTER_VERSION=$(TRUSTY_KEYMASTER_VERSION)
#
# defien the path of soc header files
#
GLOBAL_INCLUDES += external/lk/platform/sprd/soc/sharkle/include
GLOBAL_INCLUDES += external/lk/platform/sprd/soc
GLOBAL_INCLUDES += lk/trusty/lib/sprdsec/arm/include

#
# Modules to be compiled into lk.bin
#
MODULES += \
	lib/sm \
	lib/trusty \
	lib/sprdsec/arm

MODULES += \
	platform/sprd/clk \
	platform/sprd/hwspinlock

TRUSTY_USER_ARCH := arm

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS :=
# compiled from source
TRUSTY_ALL_USER_TASKS := \
	app/sample/ipc-unittest/srv

# This project requires trusty IPC
WITH_TRUSTY_IPC := true

EXTRA_BUILDRULES += app/trusty/user-tasks.mk
