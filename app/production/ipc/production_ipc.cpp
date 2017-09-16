/*
 * Copyright (c) 2015, Spreadtrum.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// TODO: add guard in header
extern "C" {
#include <stdlib.h>
}

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <err.h>

#include <trusty_std.h>
#include <trusty_ipc.h>

#include <UniquePtr.h>
#include "production_ipc.h"

#include "trusty_production.h"


using namespace production;

typedef void (*event_handler_proc_t)(const uevent_t* ev, void* ctx);
struct tipc_event_handler {
    event_handler_proc_t proc;
    void* priv;
};

struct production_chan_ctx {
    struct tipc_event_handler handler;
    uuid_t uuid;
    handle_t chan;
    long (*dispatch)(production_chan_ctx*, production_message*, uint32_t, uint8_t*,
                     uint32_t*);
};

struct production_srv_ctx {
    handle_t port_secure;
    handle_t port_non_secure;
};

static void production_port_handler_secure(const uevent_t* ev, void* priv);
static void production_port_handler_non_secure(const uevent_t* ev, void* priv);

/*static tipc_event_handler production_port_evt_handler_secure = {
    .proc = production_port_handler_secure, .priv = NULL,
};*/

static tipc_event_handler production_port_evt_handler_non_secure = {
    .proc = production_port_handler_non_secure, .priv = NULL,
};

static void production_chan_handler(const uevent_t* ev, void* priv);

TrustyProduction* device;

class MessageDeleter {
  public:
    explicit MessageDeleter(handle_t chan, int id) {
        chan_ = chan;
        id_ = id;
    }

    ~MessageDeleter() { put_msg(chan_, id_); }

  private:
    handle_t chan_;
    int id_;
};

static long handle_port_errors(const uevent_t* ev) {
    if ((ev->event & IPC_HANDLE_POLL_ERROR) || (ev->event & IPC_HANDLE_POLL_HUP) ||
        (ev->event & IPC_HANDLE_POLL_MSG) || (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        /* should never happen with port handles */
        LOG_I("error event (0x%x) for port (%d)\n", ev->event, ev->handle);
        return ERR_BAD_STATE;
    }
    return NO_ERROR;
}

static long send_response(handle_t chan, uint32_t cmd, production_rsp_code code, uint8_t* out_buf, uint32_t out_buf_size) {
    production_message pd_msg;
    pd_msg.cmd = cmd | PRODUCTION_RESP_BIT;
    pd_msg.msg_code = code;
    iovec_t iov[2];
    ipc_msg_t msg;
    if(out_buf_size==0){
        iov[0].base= &pd_msg;
        iov[0].len = sizeof(pd_msg);
        msg.num_iov = 1;
        msg.iov = iov;
        msg.num_handles = 0;
        msg.handles = NULL;
    }else{
        iov[0].base= &pd_msg;
        iov[0].len = sizeof(pd_msg);
        iov[1].base= out_buf;
        iov[1].len = out_buf_size;
        msg.num_iov = 2;
        msg.iov = iov;
        msg.num_handles = 0;
        msg.handles = NULL;
    }

    long rc = send_msg(chan, &msg);
    // fatal error
    if (rc < 0) {
        LOG_I("failed (%ld) to send_msg for chan (%d)\n", rc, chan);
        return rc;
    }

    return NO_ERROR;
}

static long send_error_response(handle_t chan, uint32_t cmd, production_rsp_code err) {
    return send_response(chan, cmd, err, NULL, 0);
}

static long production_dispatch_secure(production_chan_ctx* ctx, production_message* msg,
                                      uint32_t payload_size, uint8_t* out,
                                      uint32_t* out_size) {
    return ERR_NOT_IMPLEMENTED;
}

static long production_dispatch_non_secure(production_chan_ctx* ctx, production_message* msg,
                                          uint32_t payload_size, uint8_t* out,
                                          uint32_t* out_size){
    LOG_I("Enter production_dispatch_non_secure\n");
    LOG_I("Dispatching command %02x\n", msg->cmd);
    switch(msg->cmd){
        case PRODUCTION_SYSTEM_INIT:
            LOG_I("msg->cmd PRODUCTION_SYSTEM_INIT\n");
            return device->SystemInit(msg, payload_size, out, out_size);
        case PRODUCTION_SYSTEM_CLOSE:
            LOG_I("msg->cmd PRODUCTION_SYSTEM_CLOSE\n");
            return device->SystemClose(msg, payload_size, out, out_size);
        case PRODUCTION_SET_ROTPK:
            LOG_I("msg->cmd PRODUCTION_SET_ROTPK\n");
            return device->SetROTPK(msg, payload_size, out, out_size);
        case PRODUCTION_GET_ROTPK:
            LOG_I("msg->cmd PRODUCTION_GET_ROTPK\n");
            return device->GetROTPK(msg, payload_size, out, out_size);
        case PRODUCTION_CHECK_SECURE:
            LOG_I("msg->cmd PRODUCTION_CHECK_SECURE\n");
            return device->CheckSecureEnable(msg, payload_size, out, out_size);
		case PRODUCTION_SEND_KEYBOX:
            LOG_I("msg->cmd PRODUCTION_SEND_KEYBOX\n");
            return device->SendKeybox(msg, payload_size, out, out_size);
        default:
            return ERR_NOT_IMPLEMENTED;
    }
}

/*static bool production_port_accessible(uuid_t* uuid, bool secure) {
    return !secure || memcmp(uuid, &gatekeeper_uuid, sizeof(gatekeeper_uuid)) == 0;
}*/

static production_chan_ctx* production_ctx_open(handle_t chan, uuid_t* uuid, bool secure) {
    /*if (!production_port_accessible(uuid, secure)) {
        LOG_E("access denied for client uuid", 0);
        return NULL;
    }*/
    production_chan_ctx* ctx = new production_chan_ctx;
    if (ctx == NULL) {
        return ctx;
    }

    ctx->handler.proc = &production_chan_handler;
    ctx->handler.priv = ctx;
    ctx->uuid = *uuid;
    ctx->chan = chan;
    ctx->dispatch = secure ? &production_dispatch_secure : &production_dispatch_non_secure;
    return ctx;
}

static void production_ctx_close(production_chan_ctx* ctx) {
    close(ctx->chan);
    delete ctx;
}

static long handle_msg(production_chan_ctx* ctx) {
    handle_t chan = ctx->chan;

    /* get message info */
    ipc_msg_info_t msg_inf;
    int rc = get_msg(chan, &msg_inf);
    if (rc == ERR_NO_MSG)
        return NO_ERROR; /* no new messages */

    // fatal error
    if (rc != NO_ERROR) {
        LOG_I("failed (%d) to get_msg for chan (%d), closing connection\n", rc, chan);
        return rc;
    }

    MessageDeleter md(chan, msg_inf.id);

    // allocate msg_buf, with one extra byte for null-terminator
    UniquePtr<uint8_t[]> msg_buf(new uint8_t[msg_inf.len + 1]);
    msg_buf[msg_inf.len] = 0;

    /* read msg content */
    iovec_t iov = {msg_buf.get(), msg_inf.len};
    ipc_msg_t msg = {1, &iov, 0, NULL};

    rc = read_msg(chan, msg_inf.id, 0, &msg);

    // fatal error
    if (rc < 0) {
        LOG_I("failed to read msg (%d)\n", rc);
        return rc;
    }
    LOG_I("Read %d-byte message\n", rc);

    if (((unsigned long)rc) < sizeof(production_message)) {
        LOG_I("invalid message of size (%d)\n", rc);
        return ERR_NOT_VALID;
    }

    uint8_t out_buf[32];
    uint32_t out_buf_size = 0;
    production_message* in_msg = reinterpret_cast<production_message*>(msg_buf.get());

    rc = ctx->dispatch(ctx, in_msg, msg_inf.len - sizeof(*in_msg), (uint8_t *)out_buf, &out_buf_size);
    if (rc != PROD_OK) {
        LOG_I("error handling message (%d), send rsp cmd is %02x\n", rc, in_msg->cmd);
        return send_error_response(chan, in_msg->cmd, (production_rsp_code)rc);
    }

    LOG_I("Sending %d-byte response\n", out_buf_size);
    return send_response(chan, in_msg->cmd, (production_rsp_code)rc, (uint8_t *)out_buf, out_buf_size);
}

static void production_chan_handler(const uevent_t* ev, void* priv) {
    production_chan_ctx* ctx = reinterpret_cast<production_chan_ctx*>(priv);
    if (ctx == NULL) {
        LOG_I("error: no context on channel %d\n", ev->handle);
        close(ev->handle);
        return;
    }
    if ((ev->event & IPC_HANDLE_POLL_ERROR) || (ev->event & IPC_HANDLE_POLL_READY)) {
        /* close it as it is in an error state */
        LOG_I("error event (0x%x) for chan (%d)\n", ev->event, ev->handle);
        close(ev->handle);
        return;
    }

    if (ev->event & IPC_HANDLE_POLL_MSG) {
        long rc = handle_msg(ctx);
        if (rc != NO_ERROR) {
            /* report an error and close channel */
            LOG_I("failed (%ld) to handle event on channel %d\n", rc, ev->handle);
            production_ctx_close(ctx);
            return;
        }
    }

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        /* closed by peer. */
        production_ctx_close(ctx);
        return;
    }
}

static void production_port_handler(const uevent_t* ev, void* priv, bool secure) {
    long rc = handle_port_errors(ev);
    if (rc != NO_ERROR) {
        LOG_I("handle_port_errors failed rc is %ld \n",rc);
        abort();
    }

    uuid_t peer_uuid;
    if (ev->event & IPC_HANDLE_POLL_READY) {
        /* incoming connection: accept it */
        int rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            LOG_I("failed (%d) to accept on port %d\n", rc, ev->handle);
            return;
        }

        handle_t chan = (handle_t)rc;
        production_chan_ctx* ctx = production_ctx_open(chan, &peer_uuid, secure);
        if (ctx == NULL) {
            LOG_I("failed to allocate context on chan %d\n", chan);
            close(chan);
            return;
        }

        rc = set_cookie(chan, ctx);
        if (rc < 0) {
            LOG_I("failed (%d) to set_cookie on chan %d\n", rc, chan);
            production_ctx_close(ctx);
            return;
        }
    }
}

static void production_port_handler_secure(const uevent_t* ev, void* priv) {
    production_port_handler(ev, priv, true);
}

static void production_port_handler_non_secure(const uevent_t* ev, void* priv) {
    production_port_handler(ev, priv, false);
}

static void dispatch_event(const uevent_t* ev) {
    if (ev == NULL){
        LOG_I("got an NULL event\n");
        return;
    }

    if (ev->event == IPC_HANDLE_POLL_NONE) {
        /* not really an event, do nothing */
        LOG_I("got an empty event\n");
        return;
    }

    /* check if we have handler */
    tipc_event_handler* handler = reinterpret_cast<tipc_event_handler*>(ev->cookie);
    if (handler && handler->proc) {
        /* invoke it */
        LOG_I("Invoke handler->proc\n");
        handler->proc(ev, handler->priv);
        return;
    }

    /* no handler? close it */
    LOG_I("no handler for event (0x%x) with handle %d\n", ev->event, ev->handle);

    close(ev->handle);

    return;
}

static long production_ipc_init(production_srv_ctx* ctx) {
    int rc;

    /* Initialize secure-side service
    rc = port_create(PRODUCTION_SECURE_PORT, 1, PRODUCTION_MAX_BUFFER_LENGTH,
                     IPC_PORT_ALLOW_TA_CONNECT);
    if (rc < 0) {
        LOG_E("Failed (%d) to create port %s", rc, PRODUCTION_SECURE_PORT);
        return rc;
    }

    ctx->port_secure = (handle_t)rc;

    rc = set_cookie(ctx->port_secure, &production_port_evt_handler_secure);
    if (rc) {
        LOG_E("failed (%d) to set_cookie on port %d", rc, ctx->port_secure);
        close(ctx->port_secure);
        return rc;
    }*/

    /* initialize service*/
    rc = port_create(PRODUCTION_PORT, 1, PRODUCTION_MAX_BUFFER_LENGTH, IPC_PORT_ALLOW_NS_CONNECT);
    if (rc < 0) {
        LOG_I("Failed (%d) to create port %s\n", rc, PRODUCTION_PORT);
        return rc;
    }

    ctx->port_non_secure = (handle_t)rc;

    rc = set_cookie(ctx->port_non_secure, &production_port_evt_handler_non_secure);
    if (rc) {
        LOG_I("failed (%d) to set_cookie on port %d\n", rc, ctx->port_non_secure);
        close(ctx->port_non_secure);
        return rc;
    }

    return NO_ERROR;
}

int main(void){
    long rc;
    uevent_t event;

    device = new TrustyProduction();

    LOG_I("Initializing Production TA ......\n");

    production_srv_ctx ctx;
    rc = production_ipc_init(&ctx);
    if (rc < 0) {
        LOG_I("Production TA failed (%ld) to initialize production.\n", rc);
        return rc;
    }
    LOG_I("Initialize Production TA success!\n");

    /* enter main event loop */
    while (true) {
        event.handle = INVALID_IPC_HANDLE;
        event.event = 0;
        event.cookie = NULL;

        rc = wait_any(&event, -1);
        if (rc < 0) {
            LOG_I("Production TA wait_any failed (%ld)\n", rc);
            break;
        }

        if (rc == NO_ERROR) { /* got an event */
            LOG_I("Production TA got an event\n");
            dispatch_event(&event);
        }
    }
    return 0;
}
