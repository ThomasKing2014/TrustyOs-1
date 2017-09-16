/*
 * Copyright (C) 2015 spreadtrum.com
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <trusty_std.h>

#include <openssl/mem.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <lib/hwkey/hwkey.h>


#include "rpmb.h"
#include "log.h"

#define USE_DUMMY_RPMB_KEY 1

#ifdef SPRDIMGVERSION_BLOCK_INDEX
#define SPRD_IMGVERSION_BLK (SPRDIMGVERSION_BLOCK_INDEX)
#else
#define SPRD_IMGVERSION_BLK (1023 * 2)
#endif

static struct rpmb_key key;
static int is_rpmb_ready = -1;


static uint16_t rpmbproxy_get_u16(struct rpmb_u16 u16)
{
    size_t i;
    uint16_t val;

    val = 0;
    for (i = 0; i < sizeof(u16.byte); i++)
        val = val << 8 | u16.byte[i];

    return val;
}


int get_rpmb_key(void)
{
#if USE_DUMMY_RPMB_KEY
    static uint8_t rpmb_key_byte[] =  {
        0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,
        0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf};

    memcpy(&key, rpmb_key_byte, sizeof(struct rpmb_key));
#else
    const char *storage_auth_key_id = "com.android.trusty.storage_auth.rpmb";
    hwkey_session_t hwkey_session;
    uint32_t key_size = 1;
    int rc = -1;

    rc = hwkey_open();
    if (rc < 0) {
        TLOGE("%s: hwkey init failed: %d\n", __func__, rc);
        return rc;
    }

    hwkey_session = (hwkey_session_t) rc;
    key_size = sizeof(struct rpmb_key);
    rc = hwkey_get_keyslot_data(session, storage_auth_key_id, &key, &key_size);

    hwkey_close(hwkey_session);

    if (rc < 0) {
        TLOGE("%s: failed to get key: %d\n", __func__, rc);
        return rc;
    }
#endif

    is_rpmb_ready = 1;
    return 0;
}


int rpmbproxy_mac(struct rpmb_packet *packet, size_t packet_count,
                    struct rpmb_key *mac)
{
    size_t i;
    int hmac_ret;
    unsigned int md_len;
    HMAC_CTX hmac_ctx;

    if (1 != is_rpmb_ready) {
        TLOGE("rpmb key is not ready\n");
        return -1;
    }

    HMAC_CTX_init(&hmac_ctx);
    hmac_ret = HMAC_Init_ex(&hmac_ctx, &key, sizeof(key), EVP_sha256(), NULL);
    if (!hmac_ret) {
        TLOGE("HMAC_Init_ex failed\n");
        goto err;
    }
    for (i = 0; i < packet_count; i++) {
        STATIC_ASSERT(sizeof(*packet) - offsetof(typeof(*packet), data) == 284);
        if (rpmbproxy_get_u16(packet[i].req_resp) == RPMB_REQ_DATA_WRITE &&
            rpmbproxy_get_u16(packet[i].address) != SPRD_IMGVERSION_BLK) {

            TLOGE("don't write addr %d\n", rpmbproxy_get_u16(packet[i].address));
			hmac_ret = 0;
            goto err;
        }
        hmac_ret = HMAC_Update(&hmac_ctx, packet[i].data, 284);
        if (!hmac_ret) {
            TLOGE("HMAC_Update failed\n");
            goto err;
        }
    }
    hmac_ret = HMAC_Final(&hmac_ctx, mac->byte, &md_len);
    if (md_len != sizeof(mac->byte)) {
        TLOGE("bad md_len %d != %zd\n", md_len, sizeof(mac->byte));
        exit(1);
    }
    if (!hmac_ret) {
        TLOGE("HMAC_Final failed\n");
        goto err;
    }

err:
    HMAC_CTX_cleanup(&hmac_ctx);
    return hmac_ret ? 0 : -1;
}
