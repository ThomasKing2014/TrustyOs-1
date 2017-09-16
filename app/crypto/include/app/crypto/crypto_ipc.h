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

#pragma once

#define LOG_TAG "crypto-ipc"
#define TLOGE(fmt, ...) \
	fprintf(stderr, "%s : %s : " fmt, LOG_TAG, __func__, ##__VA_ARGS__)

#define TLOGI(fmt, ...) \
	printf("%s : %s : " fmt, LOG_TAG, __func__, ##__VA_ARGS__)

typedef void (*event_handler_proc_t) (const uevent_t *ev);

typedef struct crypto_ipc_event_handler {
    event_handler_proc_t proc;
    void *priv;
} cipc_event_handler_t;

typedef struct crypto_ipc_srv {
    const char *name;
    uint msg_num;
    size_t msg_size;
    uint port_flags;
    event_handler_proc_t port_handler;
} cipc_srv_t;

typedef struct crypto_ipc_srv_state {
    const cipc_srv_t *service;
    handle_t port;
    void *priv;
    cipc_event_handler_t handler;
} cipc_srv_state_t;

#define IPC_PORT_ALLOW_ALL  (  IPC_PORT_ALLOW_NS_CONNECT \
                             | IPC_PORT_ALLOW_TA_CONNECT \
                            )

#define RPMB_STORAGE_AUTH_KEY_ID "com.android.trusty.storage_auth.rpmb"
#define HWCRYPTO_UNITTEST_KEYBOX_ID "com.android.trusty.hwcrypto.unittest.key32"

#define RPMB_STORAGE_AUTH_KEY_SIZE 	32
#define HWKEY_COMMON_SIZE 32

extern void hwrng_msg_handle(const uevent_t *ev);
extern void hwkey_msg_handle(const uevent_t *ev);
