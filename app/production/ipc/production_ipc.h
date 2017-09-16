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

#pragma once
#include <stdio.h>

#define PRODUCTION_PORT "com.android.trusty.production"
#define PRODUCTION_MAX_BUFFER_LENGTH 4096

#define LOG_TAG "trusty_production"
//Add for open debug
#define LOCAL_TRACE 1

#if LOCAL_TRACE
#define LOG_I(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)
#define LOG_E(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)
#else
#define LOG_I(fmt, ...)
#define LOG_E(fmt, ...)
#endif

#define EFUSE_ROTPK_KEY_LEN 32
#define RPMB_KEY_LEN 32

// Commands
enum production_command {
    PRODUCTION_RESP_BIT             = 1,
    PRODUCTION_REQ_SHIFT            = 1,

    PRODUCTION_SECURE_PUBLIC_FUSE   = (0 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_FUSE_KCE 	    = (1 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_FUSE_ROTPK_ID = (2 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_RPMB          = (3 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_RTC           = (4 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_IFAA          = (5 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_SOTER         = (6 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_CUP           = (7 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_FIDO          = (8 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_HDCP22        = (9 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_WIDEVINE_L1   = (10 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SECURE_TPM           = (11 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SYSTEM_INIT          = (12 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SYSTEM_CLOSE         = (13 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SET_ROTPK            = (14 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_GET_ROTPK            = (15 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_CHECK_SECURE         = (16 << PRODUCTION_REQ_SHIFT),
    PRODUCTION_SEND_KEYBOX          = (17 << PRODUCTION_REQ_SHIFT)
};

typedef enum{
    PROD_OK                  = 0, // success
    PROD_ERROR_GET_LCS       = 1,// efuse get lcs error
    PROD_ERROR_LCS_SECURE    = 2,// rotpk has been programed
    PROD_ERROR_NOT_WR_HUK    = 3,// huk has not been programed
    PROD_ERROR_WR_HUK        = 4,// efuse write huk error
    PROD_ERROR_WR_KCE        = 5,// efuse write kce error
    PROD_ERROR_GET_RPMB      = 6,// get rpmb key error
    PROD_ERROR_WR_RPMB       = 7,// write rpmb key error
    PROD_ERROR_GET_UID       = 8,// get uid error
    PROD_ERROR_SET_RTC       = 9,// set rtc error
    PROD_ERROR_WR_ROTPK      = 10,// write public key hash(ROTPK0) error
    PROD_ERROR_GET_ROTPK     = 11,// get public key hash(ROTPK0) error
    PROD_ERROR_NOT_FINISH    = 12,// production do not finish error
    PROD_ERROR_UNKNOW        = 13,// unknow error
    PROD_ERROR_SEND_KEYB     = 14,//send keybox error
}production_rsp_code;

//#ifdef __ANDROID__

/**
 * production_message - Serial header for communicating with KM server
 * @cmd: the command, one of production_command.
 * @payload: start of the serialized command specific payload
 */
typedef struct _production_message {
    uint32_t cmd;
    int msg_code;
    uint8_t payload[0];
}production_message;

//#endif
