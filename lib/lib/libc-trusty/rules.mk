LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

WITH_CUSTOM_MALLOC := true

GLOBAL_INCLUDES := $(LOCAL_DIR)/include $(LKROOT)/include $(GLOBAL_INCLUDES)

MODULE_SRCS := \
	$(LOCAL_DIR)/abort.c \
	$(LOCAL_DIR)/assert.c \
	$(LOCAL_DIR)/atexit.c \
	$(LOCAL_DIR)/exit.c \
	$(LOCAL_DIR)/malloc.c \
	$(LOCAL_DIR)/stdio.c \
	$(LOCAL_DIR)/libc_init.c \
	$(LOCAL_DIR)/libc_fatal.c \

include $(LOCAL_DIR)/arch/$(ARCH)/rules.mk

MODULE_DEPS := \
	lib/libc \
	lib/version

include make/module.mk
