LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)
MODULE_USER := true

MODULE_SRCS := \
	$(LOCAL_DIR)/openssl-engine.c

GLOBAL_INCLUDES += $(LOCAL_DIR)/include

include make/module.mk
