LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)
MODULE_USER := true

MODULE_SRCS := \
    $(LOCAL_DIR)/keybox_tools.cpp

MODULE_DEPS := \
    lib/storage

MODULE_CPPFLAGS := -std=c++11
GLOBAL_INCLUDES += $(LOCAL_DIR)/include

include make/module.mk
