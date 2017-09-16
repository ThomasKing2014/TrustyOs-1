/*
 * Copyright (C) 2017 spreadtrum
 */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <trusty_std.h>


#include "log.h"
#include "client_handle.h"
#include "rpmbproxy_ipc.h"



static unsigned char chan_message_buf[RPMBPROXY_MAX_BUFFER_SIZE];


extern int handle_clt_msg (struct event_context *ctx, void *msg_buf, size_t msg_size);

static int handle_chan_message(struct event_context *chan_ctx, const uevent_t *ev)
{
    handle_t chan = ev->handle;

    /* get message info */
    ipc_msg_info_t msg_inf;
    int rc = get_msg(chan, &msg_inf);
    if (rc == ERR_NO_MSG)
        return NO_ERROR; /* no new messages */

    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to get_msg for chan (%d), closing connection\n", rc, chan);
        return rc;
    }

    if (msg_inf.len > RPMBPROXY_MAX_BUFFER_SIZE) {
        TLOGE("%s: message too large %d\n", __func__, msg_inf.len);
        put_msg(chan, msg_inf.id);
        return ERR_NOT_ENOUGH_BUFFER;
    }

    /* read msg content */
    iovec_t iov = {
        .base = chan_message_buf,
        .len = msg_inf.len,
    };
    ipc_msg_t msg = {
        .iov = &iov,
        .num_iov = 1,
    };

    rc = read_msg(chan, msg_inf.id, 0, &msg);
    put_msg(chan, msg_inf.id);
    if (rc < 0) {
        TLOGE("failed to read msg (%d, %d)\n", rc, chan);
        return rc;
    }

    if (((size_t) rc) < msg_inf.len) {
        TLOGE("invalid message of size (%d, %d)\n", rc, chan);
        return ERR_NOT_VALID;
    }

    rc = chan_ctx->msg_handler(chan_ctx, chan_message_buf, msg_inf.len);

err_handle_msg:
err_read_msg:
    return rc;
}



static void chan_event_handle(const uevent_t *ev)
{
    struct event_context *chan_ctx;
    int rc;

    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_READY)) {

        /* close it as it is in an error state */
        TLOGE("error event (0x%x) for chan (%d)\n", ev->event, ev->handle);
        goto close_chan;
    }


    if (ev->event & (IPC_HANDLE_POLL_MSG |
                 IPC_HANDLE_POLL_SEND_UNBLOCKED)) {

        chan_ctx = ev->cookie;
        if (NULL != chan_ctx->msg_handler) {
            rc = handle_chan_message(chan_ctx, ev);
            if (rc < 0) {
                TLOGE("error (%d) in channel, disconnecting peer\n", rc);
                goto close_chan;
            }
        } else {
            TLOGE("error: don't set msg_handler to channel (%d). closing...\n", ev->handle);
            goto close_chan;

        }

    }

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        TLOGE("error event (0x%x) for chan (%d)\n", ev->event, ev->handle);
        goto close_chan;
    }

    return;

close_chan:
    free(ev->cookie);
    close(ev->handle);
}


void port_event_handle(const uevent_t *ev)
{
    uuid_t peer_uuid;
    struct event_context *chan_ctx;

    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_HUP) ||
        (ev->event & IPC_HANDLE_POLL_MSG) ||
        (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        /* should never happen with port handles */
        TLOGE("error event (0x%x) for port (%d)\n", ev->event,
              ev->handle);
        return;
    }


    if (ev->event & IPC_HANDLE_POLL_READY) {
        handle_t chan;

        /* incomming connection: accept it */
        int rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            TLOGE("failed (%d) to accept on port %d\n",
                   rc, ev->handle);
            return;
        }
        chan = (handle_t) rc;

        chan_ctx = calloc(1, sizeof(struct event_context));
        if (!chan_ctx) {
            TLOGE("failed (%d) to callocate state for chan %d\n",
                   rc, chan);
            close(chan);
            return;
        }

        /* init state */
        chan_ctx->evt_handler = chan_event_handle;
        chan_ctx->msg_handler = handle_clt_msg;
        chan_ctx->handle = chan;

        /* attach it to handle */
        rc = set_cookie(chan, chan_ctx);
        if (rc) {
            TLOGI("failed (%d) to set_cookie on chan %d\n", rc, chan);
            free(chan_ctx);
            close(chan);
            return;
        }
    }
}

void event_dispatch(const uevent_t *ev)
{
    assert(ev);

    if (ev->event == IPC_HANDLE_POLL_NONE) {
        /* not really an event, do nothing */
        TLOGE("got an empty event\n");
        return;
    }

    if (ev->handle == INVALID_IPC_HANDLE) {
        /* not a valid handle  */
        TLOGE("got an event (0x%x) with invalid handle (%d)",
              ev->event, ev->handle);
        return;
    }

    /* check if we have handler */
    struct event_context *ctx = ev->cookie;
    if (ctx && ctx->evt_handler) {
        /* invoke it */
        ctx->evt_handler(ev);
        return;
    }

    /* no handler? close it */
    TLOGE("no handler for event (0x%x) with handle %d, to close handle\n",
           ev->event, ev->handle);
    close(ev->handle);

    return;
}
