ifeq ($(strip $(BOARD_TEE_CONFIG)), trusty)

TRUSTY_TOPDIR := $(call my-dir)
include $(CLEAR_VARS)

ifneq ($(strip $(BOARD_TEE_64BIT)), true)
TRUSTY_CROSS_COMPILE := $(shell pwd)/prebuilts/gcc/linux-x86/arm/arm-eabi-4.8/bin/arm-eabi-
TRUSTY_APP_CROSS_COMPILE := $(shell pwd)/prebuilts/gcc/linux-x86/arm/arm-eabi-4.8/bin/arm-eabi-
else
TRUSTY_CROSS_COMPILE := $(shell pwd)/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin/aarch64-linux-android-
TRUSTY_APP_CROSS_COMPILE := $(shell pwd)/prebuilts/gcc/linux-x86/arm/arm-eabi-4.8/bin/arm-eabi-
endif

ifeq (7.0,$(filter 7.0,$(PLATFORM_VERSION)))
CONFIG_KEYMASTER_VERSION := 1
else
CONFIG_KEYMASTER_VERSION := 2
endif

# The target name and *ABSOLUTE* path
TRUSTY_DEFAULT_PROJECT := $(CFG_TRUSTY_DEFAULT_PROJECT)
TRUSTY_BUILD_OUT := $(shell pwd)/$(TARGET_OUT_INTERMEDIATES)/trusty
TRUSTY_BIN    := $(TRUSTY_BUILD_OUT)/lk.bin
INSTALLED_TRUSTOS_TARGET := $(PRODUCT_OUT)/tos.bin

ifneq ($(strip $(BOARD_TOS_MEM_SIZE)),)
TOS_MEM_SIZE := $(BOARD_TOS_MEM_SIZE)
else
TOS_MEM_SIZE := 0x2000000
endif

ifneq ($(strip $(BOARD_TOS_MEM_ADDR)),)
TOS_MEM_ADDR := $(BOARD_TOS_MEM_ADDR)
else
TOS_MEM_ADDR := 0x94100000
endif

ifneq ($(strip $(BOARD_SEC_MEM_SIZE)),)
SML_TOS_SIZE := $(BOARD_SEC_MEM_SIZE)
else
SML_TOS_SIZE := 0x1000000
endif

TRUSTY_BUILD_OPTION := \
      -C $(TRUSTY_TOPDIR)/ \
      TOOLCHAIN_PREFIX=$(TRUSTY_CROSS_COMPILE) \
      BUILDROOT=$(TRUSTY_BUILD_OUT) \
      DEFAULT_PROJECT=$(TRUSTY_DEFAULT_PROJECT) \
      FINGERPRINT_VENDOR=$(BOARD_FINGERPRINT_CONFIG) \
      PRODUCT_VBOOT_VER=$(PRODUCT_VBOOT) \
      CONFIG_SPRD_FIREWALL=$(CONFIG_TEE_FIREWALL) \
      TOS_MEM_SIZE=$(TOS_MEM_SIZE) \
      TOS_MEM_ADDR=$(TOS_MEM_ADDR) \
      SML_TOS_SIZE=$(SML_TOS_SIZE) \
      TRUSTY_KEYMASTER_VERSION=$(CONFIG_KEYMASTER_VERSION)

TRUSTY_BUILD_OPTION += \
      ARCH_arm_TOOLCHAIN_PREFIX=$(TRUSTY_APP_CROSS_COMPILE)

ifneq ($(strip $(SDK)),)
TRUSTY_BUILD_OPTION += SDK_MAKEROOT=vendor/sprd/build/sdk sdk
endif

trusty_dep:
	@echo "Build Trusted OS $(TRUSTY_TOPDIR) dir (sprd trusty).. project $(TRUSTY_DEFAULT_PROJECT)"
	$(MAKE) $(TRUSTY_BUILD_OPTION)

$(TRUSTY_BIN):trusty_dep

$(INSTALLED_TRUSTOS_TARGET): $(TRUSTY_BIN)
	@cp $< $@
	@echo "install tos image done."

trusty: $(INSTALLED_TRUSTOS_TARGET)

ALL_DEFAULT_INSTALLED_MODULES += $(INSTALLED_TRUSTOS_TARGET)
ALL_MODULES.$(LOCAL_MODULE).INSTALLED += $(INSTALLED_TRUSTOS_TARGET)

.PHONY: trusty

# Build all modules
include $(call all-makefiles-under,$(TRUSTY_TOPDIR)/vendor/sprd/modules/)

else
trusty:
endif
