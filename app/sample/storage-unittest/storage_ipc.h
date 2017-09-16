/*
 * Copyright (C) 2017 spreadtrum
 */
#pragma once

#include <stdio.h>
#include <string.h>
#include <trusty_ipc.h>
#include <trusty_uuid.h>



#define STORAGE_UNITTEST_PROXY_PORT "com.android.trusty.storage-unittest"
#define STORAGE_UNITTEST_MAX_BUFFER_SIZE 4096


struct evt_context;

typedef void (*evt_handler_t) (const struct uevent *ev);
typedef int (*msg_handler_t)(struct evt_context *context, void *msg, size_t msg_size);

struct evt_context {
	evt_handler_t evt_handler;
    msg_handler_t msg_handler;
	handle_t handle;
};

void dispatch_evt(const uevent_t *ev);
void port_evt_handle(const uevent_t *ev);
