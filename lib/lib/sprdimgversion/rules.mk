# Copyright (C) 2017 spreadtrum.com
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS := $(LOCAL_DIR)/sprdimgversion.c

GLOBAL_INCLUDES += $(LOCAL_DIR)/include/

MODULE_DEPS := \
	interface/sprdimgversion \

include make/module.mk

