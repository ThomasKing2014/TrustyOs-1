/*
 * Copyright (C) 2017 spreadtrum.com
 */
#pragma once

#include <stdio.h>
#include <string.h>
#include <trusty_ipc.h>
#include <trusty_uuid.h>



#define RPMBPROXY_PORT "com.spreadtrum.rpmbproxy"
#define RPMBPROXY_MAX_BUFFER_SIZE 4096


struct event_context;


typedef void (*event_handler_t) (const struct uevent *ev);
typedef int (*message_handler_t)(struct event_context *context, void *msg, size_t msg_size);

struct event_context {
    event_handler_t evt_handler;
    message_handler_t msg_handler;
    handle_t handle;
};

void event_dispatch(const uevent_t *ev);
void port_event_handle(const uevent_t *ev);
