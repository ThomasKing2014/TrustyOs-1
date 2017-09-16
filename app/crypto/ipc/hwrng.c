/*
 * The MIT License (MIT)
 * Copyright (c) 2008-2015 Travis Geiselbrecht
 * Copyright (c) 2016, Spreadtrum Communications.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>

 #include <trusty_std.h>
 #include <trusty_ipc.h>
 #include <err.h>

 #include <app/crypto/crypto_ipc.h>
 #include <interface/hwrng/hwrng.h>
 #include <hw_crypto.h>

 static long send_response(handle_t chan, uint8_t *out, uint32_t len)
 {
     iovec_t out_iov = {
         .base = out,
         .len = len,
     };
     ipc_msg_t out_msg = {
         .iov = &out_iov,
         .num_iov = 1,
     };
     /* send message back to the caller */
     long rc = send_msg(chan, &out_msg);
     if (rc < 0) {
         TLOGE("hwrng : failed (%ld) to send_msg for chan (%d)\n", rc, chan);
     }

     return rc;
 }

 static long handle_request(uint8_t *out, uint32_t len)
 {
    long rc;
    sprd_rng_params_t rng_params;
    rng_params.len = len;
    rng_params.out = (user_addr_t)out;
    // success = 0 , fail = !0(value > 0)
    rc = ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_RNG_GEN, &rng_params);
#if 0
    printf("HWRNG : ");
    uint32_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
#endif
    return rc;
 }

 static long handle_msg(handle_t chan)
 {
    /* get message info */
    ipc_msg_info_t msg_inf;

    long rc = get_msg(chan, &msg_inf);
    if (rc == ERR_NO_MSG) {
        rc = NO_ERROR; /* no new messages */
        goto err0;
    }

    // fatal error
    if (rc != NO_ERROR) {
        TLOGE("hwrng : failed (%ld) to get_msg for chan (%d), closing connection\n",
            rc, chan);
        goto err0;
    }

    /* read msg content */
    iovec_t iov;
    iov.base = malloc(sizeof(struct hwrng_req));
    if (iov.base == NULL) {
        TLOGE("hwrng : base memory malloc fail \n");
        rc = ERR_NO_MEMORY;
        goto err1;
    }
    iov.len = sizeof(struct hwrng_req);
    ipc_msg_t msg = { 1, &iov, 0, NULL} ;

    rc = read_msg(chan, msg_inf.id, 0, &msg);
    put_msg(chan, msg_inf.id);
    if (rc < 0) {
        TLOGE("hwrng : failed to read msg (%ld) for chan (%d)\n", rc, chan);
        goto err1;
    }
    if(((size_t)rc) < sizeof(struct hwrng_req)) {
        TLOGE("hwrng : invalid message of size (%zu) for chan (%d)\n",
            (size_t)rc, chan);
        rc = ERR_GENERIC;
        goto err1;
    }

    struct hwrng_req *hr_req = (struct hwrng_req *)(iov.base);
    uint8_t *rng_out = malloc(hr_req->len);
    if (rng_out == NULL) {
        TLOGE("hwrng : rng memory malloc fail \n");
        rc = ERR_NO_MEMORY;
        goto err2;
    }
    rc = handle_request(rng_out, hr_req->len);
    if (rc != 0) {
        TLOGE("hwrng : ioctl %ld unable to handle request \n", rc);
        rc = ERR_GENERIC;
        goto err2;
    }
    rc = send_response(chan, rng_out, hr_req->len);
    if (rc < 0) {
        TLOGE("hwrng : unable (%ld) to send response \n", rc);
    }

err2:
    free(rng_out);
err1:
    free(iov.base);
err0:
    return rc;
 }

void hwrng_msg_handle(const uevent_t *ev)
{
    int rc;
    handle_t chan;

    if (ev->event & IPC_HANDLE_POLL_READY) {
        TLOGI("IPC_HANDLE_POLL_READY\n");
        cipc_event_handler_t *handler = ev->cookie;
        uuid_t peer_uuid;

        rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            TLOGE("Failed (%d) to accept on port %d\n", rc, ev->handle);
        }
        chan = (handle_t)rc;

        rc = set_cookie(chan, handler);
        if (rc < 0) {
            TLOGE("Failed (%d) to set cookie on port %d\n", rc, chan);
            close(chan);
        }
        return;
    }

    if (ev->event & IPC_HANDLE_POLL_MSG) {
        TLOGI("IPC_HANDLE_POLL_MSG\n");
        chan = (handle_t)ev->handle;
        rc = handle_msg(chan);
        if (rc < 0) {
            /* report an error and close channel */
            TLOGE("failed (%d) to handle event on channel %d\n", rc, ev->handle);
            close(chan);
        }
    }
}
