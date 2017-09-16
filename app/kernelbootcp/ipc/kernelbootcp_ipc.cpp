/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// TODO: add guard in header
extern "C" {
#include <stdlib.h>
}

#include <string.h>
#include <stdio.h>
#include <trusty_std.h>
#include <trusty_ipc.h>
#include <err.h>
#include <UniquePtr.h>
#include "kernelbootcp_ipc.h"
#include "trusty_kernelbootcp.h"

using namespace kernelbootcp;
TrustyKernelBootCp *device;

class SessionManager {
  public:
    SessionManager(long* err) {
        *err = device->OpenSession();
    }
    ~SessionManager() {
        device->CloseSession();
    }
};

class MessageDeleter {
public:
    explicit MessageDeleter(handle_t chan, int id) {
        chan_ = chan;
        id_ = id;
    }

    ~MessageDeleter() {
        put_msg(chan_, id_);
    }

private:
    handle_t chan_;
    int id_;
};

static long kbc_handle_request(uint32_t cmd, uint8_t *in_buf, uint32_t in_buf_size,
                               UniquePtr<uint8_t[]> *out_buf, uint32_t *out_buf_size)
{
    long    ret = NO_ERROR;

    switch (cmd) {
        case KERNEL_BOOTCP_VERIFY_ALL:
            TLOGI("cmd KERNEL_BOOTCP_VERIFY_ALL\n");
            ret = device->kbc_verify_all(in_buf, in_buf_size);
            break;
        case KERNEL_BOOTCP_UNLOCK_DDR:
            TLOGI("cmd KERNEL_BOOTCP_UNLOCK_DDR\n");
            ret = device->kbc_unlock_ddr();
            break;
        default:
            return ERR_NOT_VALID;
    }
    return ret;
}


static long kbc_send_response(handle_t  chan,    uint32_t cmd,
                              uint8_t  *out_buf, uint32_t out_buf_size)
{
    struct kernelbootcp_message kbc_msg = { cmd | KERNELBOOTCP_BIT, {}};
    iovec_t iov[2] = {{ &kbc_msg, sizeof(kbc_msg) },
                      { out_buf, out_buf_size }};
    ipc_msg_t msg = { 2, iov, 0, NULL };

    /* send message back to the caller */
    long rc = send_msg(chan, &msg);
    TLOGI("kbc_send_response rc = %d \n", (int)rc);

    // fatal error
    if (rc < 0) {
        TLOGE("failed (%ld) to send_msg for chan (%d)\n", rc, chan);
        return rc;
    }
    return NO_ERROR;
}

static long kbc_send_error_response(handle_t chan, uint32_t cmd, long err) {
    return kbc_send_response(chan, cmd, reinterpret_cast<uint8_t*>(&err), sizeof(err));
}

static long kbc_handle_msg(handle_t chan)
{
    /* get message info */
    ipc_msg_info_t msg_inf;

    long rc = get_msg(chan, &msg_inf);
    if (rc == ERR_NO_MSG) {
        TLOGI("no message!\n");
        return NO_ERROR; /* no new messages */
    }

    // fatal error
    if (rc != NO_ERROR) {
        TLOGE("failed (%ld) to get_msg for chan (%d), closing connection\n",
                rc, chan);
        return rc;
    }

    MessageDeleter md(chan, msg_inf.id);

    UniquePtr<uint8_t[]> msg_buf(new uint8_t[msg_inf.len]);

    /* read msg content */
    iovec_t iov = { msg_buf.get(), msg_inf.len };
    ipc_msg_t msg = { 1, &iov, 0, NULL} ;

    rc = read_msg(chan, msg_inf.id, 0, &msg);

    if (rc < 0) {
        TLOGE("failed to read msg (%ld) for chan (%d)\n", rc, chan);
        return rc;
    }

    if(((size_t)rc) < sizeof(kernelbootcp_message)) {
        TLOGE("invalid message of size (%zu) for chan (%d)\n",
              (size_t)rc, chan);
        return ERR_NOT_VALID;
    }

    /* get request command */
    kernelbootcp_message *kbc_msg =
        reinterpret_cast<struct kernelbootcp_message *>(msg_buf.get());

    UniquePtr<uint8_t[]> out_buf;
    uint32_t out_buf_size = 0;
    rc = kbc_handle_request(kbc_msg->cmd, kbc_msg->payload,
            msg_inf.len - sizeof(kernelbootcp_message), &out_buf, &out_buf_size);

    if (rc < 0) {
        TLOGE("unable (%ld) to handle request \n", rc);
        return kbc_send_error_response(chan, kbc_msg->cmd, rc);
    }

    rc = kbc_send_response(chan, kbc_msg->cmd, out_buf.get(), out_buf_size);

    if (rc < 0) {
        TLOGE("unable (%ld) to send response \n", rc);
    }

    return rc;
}

static void kbc_handle_port(uevent_t *ev)
{
    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_HUP) ||
        (ev->event & IPC_HANDLE_POLL_MSG) ||
        (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        /* should never happen with port handles */
        TLOGE("error event (0x%x) for port (%d)\n",
               ev->event, ev->handle);
        abort();
    }

    uuid_t peer_uuid;
    if (ev->event & IPC_HANDLE_POLL_READY) {
        /* incoming connection: accept it */
        int rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            TLOGE("failed (%d) to accept on port %d\n",
                    rc, ev->handle);
            return;
        }
    }
}

static void kbc_handle_channel(uevent_t *ev)
{
    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_READY)) {
        /* close it as it is in an error state */
        TLOGE("error event (0x%x) for chan (%d)\n",
               ev->event, ev->handle);
        abort();
    }

    handle_t chan = ev->handle;

    if (ev->event & IPC_HANDLE_POLL_MSG) {
        long rc = kbc_handle_msg(chan);
        if (rc != NO_ERROR) {
            /* report an error and close channel */
            TLOGE("failed (%ld) to handle event on channel %d\n", rc, ev->handle);
            close(chan);
        }
    }

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        /* closed by peer. */
        close(chan);
        return;
    }

}

static long kbc_ipc_init(void)
{
    int rc;

    TLOGI("kbc_ipc_init enter. \n");
    /* Initialize service */
    rc = port_create(KERNELBOOTCP_PORT, 1, KERNELBOOTCP_MAX_BUFFER_LENGTH,
            IPC_PORT_ALLOW_NS_CONNECT);
    if (rc < 0) {
        TLOGE("Failed (%d) to create port %s\n", rc, KERNELBOOTCP_PORT);
    }

    TLOGI("kbc_ipc_init rc = %d \n", rc);
    return rc;
}

int main(void)
{
    long rc;
    uevent_t event;

    TLOGI("Initializing\n");

    device = new TrustyKernelBootCp();

    rc = kbc_ipc_init();
    if (rc < 0) {
        TLOGE("failed (%ld) to initialize kernelbootcp", rc);
        return rc;
    }

    handle_t port = (handle_t) rc;
    TLOGI("port = %d\n", port);

    /* enter main event loop */
    while (true) {
        event.handle = INVALID_IPC_HANDLE;
        event.event  = 0;
        event.cookie = NULL;

//        TLOGI("wait_any... \n");
        rc = wait_any(&event, -1);
//        TLOGI("wait_any rc = %d \n", rc);
        if (rc < 0) {
            TLOGE("wait_any failed (%ld)\n", rc);
            break;
        }

        if (rc == NO_ERROR) { /* got an event */
//            TLOGI("event.handle = %d port = %d \n", event.handle, port);
            if (event.handle == port) {
                kbc_handle_port(&event);
            } else {
                kbc_handle_channel(&event);
            }
        }
    }

    return 0;
}
