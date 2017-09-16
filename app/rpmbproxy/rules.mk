# Copyright (C) 2015 spreadtrum.com
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
    $(LOCAL_DIR)/manifest.c \
    $(LOCAL_DIR)/main.c \
    $(LOCAL_DIR)/rpmbproxy_ipc.c \
    $(LOCAL_DIR)/rpmbproxy.c \
    $(LOCAL_DIR)/client_handle.c

MODULE_DEPS += \
    app/trusty \
    lib/libc-trusty \
    lib/hwkey \
    openssl

include make/module.mk
