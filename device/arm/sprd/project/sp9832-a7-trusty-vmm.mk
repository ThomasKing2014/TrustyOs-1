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

TARGET := sp9832-a7

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

GLOBAL_DEFINES += \
	WITH_HYPERVISOR=1 \
	WITH_LIB_SM_MONITOR=1 \
	WITH_MEMLOG_EARLY=1 \
	WITH_USER_TASK_ATTACH=1

# define VMM entrypiont address
GLOBAL_DEFINES += VMM_ENTRY_BASE=0xBFA00000

MEMBASE := 0xBDA00000
MEMSIZE := 0x02000000   # 32MB

BOOT_MEM_OFFSET := 0x400000

WITH_SMP := 1
WITH_HOTPLUG := 1

#
# Modules to be compiled into lk.bin
#
MODULES += \
	lib/sm \
	lib/trusty \
	lib/memlog \
	vendor/sprd/modules/sprdsec

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
	sample/skel \
	sample/skel2\
	keymaster \
	gatekeeper \

EXTRA_BUILDRULES += app/trusty/user-tasks.mk
