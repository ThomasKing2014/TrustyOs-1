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
 #include <interface/hwkey/hwkey.h>
 #include <hw_crypto.h>

 struct hwkey {
     uint32_t ct_len;
     uint8_t *ct;
 };

 static long send_response(handle_t chan, struct hwkey_msg *req, struct hwkey *hk_out)
 {
    req->cmd |= HWKEY_RESP_BIT;
    iovec_t out_iov[2] = {
        {
            .base = req,
            .len = sizeof(struct hwkey_msg)
        },
        {
            .base = hk_out->ct,
            .len = hk_out->ct_len
        }
    };
    ipc_msg_t out_msg = {
        .iov = out_iov,
        .num_iov = 2,
    };

    /* send message back to the caller */
    long rc = send_msg(chan, &out_msg);
    if (rc < 0) {
        TLOGE("hwkey : failed (%ld) to send_msg for chan (%d)\n", rc, chan);
    }
    return rc;
 }

 static long handle_request(struct hwkey_msg *hk_req, uint32_t id_len, struct hwkey *hk_out)
 {
    long rc;
    sprd_hwkey_params_t hwkey_params;
    uint8_t *pt_temp, *ct_temp;
    uint32_t len;

    if (strncmp((char const *)hk_req->payload, (char const *)RPMB_STORAGE_AUTH_KEY_ID, id_len) == 0) {
        //rpmb key
        TLOGI("hwkey : RPMB_STORAGE_AUTH_KEY_SIZE \n");
        hwkey_params.pt_len = RPMB_STORAGE_AUTH_KEY_SIZE;
        pt_temp = (uint8_t *)malloc(RPMB_STORAGE_AUTH_KEY_SIZE);
        if (!pt_temp) {
            TLOGE("hwkey : alloc memory fail \n");
            rc = ERR_NO_MEMORY;
            goto err0;
        }
        memcpy(pt_temp, RPMB_STORAGE_AUTH_KEY_ID, RPMB_STORAGE_AUTH_KEY_SIZE);
        hwkey_params.ct_len = RPMB_STORAGE_AUTH_KEY_SIZE;
    } else if (strncmp((char const *)hk_req->payload, (char const *)HWCRYPTO_UNITTEST_KEYBOX_ID, id_len) == 0) {
        //test keybox
        TLOGI("hwkey : HWCRYPTO_UNITTEST_KEYBOX_ID \n");
        hwkey_params.pt_len = HWKEY_COMMON_SIZE;
        pt_temp = (uint8_t *)malloc(HWKEY_COMMON_SIZE);
        if (!pt_temp) {
            TLOGE("hwkey : alloc memory fail \n");
            rc = ERR_NO_MEMORY;
            goto err0;
        }
        memcpy(pt_temp, HWCRYPTO_UNITTEST_KEYBOX_ID, HWKEY_COMMON_SIZE);
        hwkey_params.ct_len = HWKEY_COMMON_SIZE;
    } else {
        //common key (pt_len >= ct_len)
        if ( id_len % 32 == 0) {
            len = id_len;
        } else {
            len = (id_len/32 + 1)*32;
        }
        hwkey_params.pt_len = len;
        pt_temp = (uint8_t *)malloc(len);
        if (!pt_temp) {
            TLOGE("hwkey : alloc memory fail \n");
            rc = ERR_NO_MEMORY;
            goto err0;
        }
        memset(pt_temp, 0, len);
        memcpy(pt_temp, hk_req->payload, id_len);
        hwkey_params.ct_len = id_len;
    }
    ct_temp = (uint8_t *)malloc(hwkey_params.ct_len);
    if (!ct_temp) {
        TLOGE("hwkey : alloc memory fail \n");
        rc = ERR_NO_MEMORY;
        goto err0;
    }

    hwkey_params.pt = (user_addr_t)pt_temp;
    hwkey_params.ct = (user_addr_t)ct_temp;
    rc = ioctl(IO_DEVICE_CRYPTO, SPRD_ENGINE_HUK_DERIVE, &hwkey_params);
    if (rc != 0) {
        rc = ERR_GENERIC;
        goto err0;
    }
    hk_out->ct = (uint8_t *)hwkey_params.ct;
    hk_out->ct_len = hwkey_params.ct_len;

#if 0
    printf("HWKEY : ");
    uint32_t i;
    for (i = 0; i < hwkey_params.ct_len; i++) {
        printf("%02x", ct_temp[i]);
    }
    printf("\n");
#endif
err0:
    free(pt_temp);
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
        TLOGE("hwkey : failed (%ld) to get_msg for chan (%d), closing connection\n",
            rc, chan);
        goto err0;
    }

    /* read msg content */
    iovec_t iov;
    iov.base = malloc(msg_inf.len);
    if (!iov.base) {
        TLOGE("hwkey : alloc memory fail \n");
        rc = ERR_NO_MEMORY;
        goto err1;
    }
    iov.len = msg_inf.len;
    ipc_msg_t msg = { 1, &iov, 0, NULL} ;

    rc = read_msg(chan, msg_inf.id, 0, &msg);
    put_msg(chan, msg_inf.id);
    if (rc < 0) {
        TLOGE("hwkey : failed to read msg (%ld) for chan (%d)\n", rc, chan);
        goto err1;
    }
    if(((size_t)rc) < msg_inf.len) {
        TLOGE("hwkey : invalid message of size (%zu) for chan (%d)\n",
        (size_t)rc, chan);
        rc = ERR_GENERIC;
        goto err1;
    }
    /* send hwkey msg */
    size_t id_len = msg_inf.len - sizeof(struct hwkey_msg);
    struct hwkey_msg *hk_req = (struct hwkey_msg *)(iov.base);
    struct hwkey hk_out;
    hk_out.ct = NULL;
    rc = handle_request(hk_req, id_len, &hk_out);
    if (rc != 0) {
        TLOGE("hwkey : unable (%ld) to handle request \n", rc);
        goto err2;
    }

    rc = send_response(chan, hk_req, &hk_out);
    if (rc < 0) {
        TLOGE("hwkey : unable (%ld) to send response \n", rc);
    }
err2:
    free(hk_out.ct);
err1:
    free(iov.base);
err0:
    return rc;
 }

void hwkey_msg_handle(const uevent_t *ev)
{
    int rc;
    handle_t chan;

    if (ev->event & IPC_HANDLE_POLL_READY) {
        TLOGI("IPC_HANDLE_POLL_READY\n");
        cipc_event_handler_t *handler = ev->cookie;
        uuid_t peer_uuid;

        rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            TLOGE("failed (%d) to accept on port %d\n", rc, ev->handle);
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
            TLOGE("Failed (%d) to handle event on channel %d\n", rc, ev->handle);
            close(chan);
        }
    }
}
