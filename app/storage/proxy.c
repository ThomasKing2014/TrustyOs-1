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

#include <assert.h>
#include <err.h>
#include <list.h> // for containerof
#include <stdlib.h>
#include <string.h>

#include <interface/storage/storage.h>
#include <interface/sprdimgversion/sprdimgversion.h>

#include <lib/hwkey/hwkey.h>

#include "ipc.h"
#include "session.h"
#include "rpmb.h"
#include "sprdimgversion_tipc.h"



#define USE_DUMMY_KEY 1

#define SS_ERR(args...)  fprintf(stderr, "ss: " args)

static void proxy_disconnect(struct ipc_channel_context *ctx);

static struct storage_session *proxy_context_to_session(struct ipc_channel_context *context)
{
	assert(context != NULL);
	struct storage_session *session =
	        containerof(context, struct storage_session, proxy_ctx);
	assert(session->magic == STORAGE_SESSION_MAGIC);
	return session;
}

static int get_storage_encryption_key(hwkey_session_t session, uint8_t *key,
                                      uint32_t key_size)
{
	static const struct key storage_key_derivation_data = {
		.byte = {
			0xbc, 0x10, 0x6c, 0x9e, 0xc1, 0xa4, 0x71, 0x04,
			0x83, 0xab, 0x03, 0x4b, 0x75, 0x8a, 0xb3, 0x5e,
			0xfb, 0xe5, 0x43, 0x6c, 0xe6, 0x74, 0xb7, 0xfc,
			0xee, 0x20, 0xad, 0xae, 0xfb, 0x34, 0xab, 0xd3,
		}
	};

	if (key_size != sizeof(storage_key_derivation_data.byte)) {
		return ERR_BAD_LEN;
	}

#if USE_DUMMY_KEY
	memcpy(key, storage_key_derivation_data.byte, key_size);
#else
	uint32_t kdf_version = HWKEY_KDF_VERSION_1;
	int rc = hwkey_derive(session, &kdf_version, storage_key_derivation_data.byte,
	                      key, key_size);
	if (rc < 0) {
		SS_ERR("%s: failed to get key: %d\n", __func__, rc);
		return rc;
	}
#endif

	return NO_ERROR;
}




static int get_rpmb_auth_key(hwkey_session_t session, uint8_t *key,
					uint32_t key_size)
{
#if USE_DUMMY_KEY
	static uint8_t rpmb_key_byte[] =  {
		0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,
		0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf};

	memcpy(key, rpmb_key_byte, key_size);
#else
	const char *storage_auth_key_id =
			"com.android.trusty.storage_auth.rpmb";

	int rc = hwkey_get_keyslot_data(session, storage_auth_key_id, key,
						&key_size);
	if (rc < 0) {
		SS_ERR("%s: failed to get key: %d\n", __func__, rc);
		return rc;
	}
#endif

	return NO_ERROR;
}

struct ipc_channel_context *proxy_connect(struct ipc_port_context *parent_ctx,
						const uuid_t *peer_uuid, handle_t chan_handle)
{
	struct rpmb_key rpmb_key;
	int rc,ret;

	struct storage_session *session = calloc(1, sizeof(*session));
	if (session == NULL) {
		SS_ERR("%s: out of memory\n", __func__);
		goto err_alloc_session;
	}

	session->magic = STORAGE_SESSION_MAGIC;

#if USE_DUMMY_KEY <= 0
	rc = hwkey_open();
#else
	rc = 1;
#endif
	if (rc < 0) {
		SS_ERR("%s: hwkey init failed: %d\n", __func__, rc);
		goto err_hwkey_open;
	}

	hwkey_session_t hwkey_session = (hwkey_session_t) rc;

	/* Generate encryption key */
	rc = get_storage_encryption_key(hwkey_session, session->key.byte,
						sizeof(session->key));
	if (rc < 0) {
		SS_ERR("%s: can't get storage key: (%d) \n", __func__, rc);
		goto err_get_storage_key;
	}

	/* Init RPMB key */
	rc = get_rpmb_auth_key(hwkey_session, rpmb_key.byte, sizeof(rpmb_key.byte));
	if (rc < 0) {
		SS_ERR("%s: can't get storage auth key: (%d)\n", __func__, rc);
		session->block_device.is_rpmb_init = 0;
	} else {
		session->block_device.ipc_handle = chan_handle;
        /* init rpmb */
		ret = rpmb_init(&session->block_device.rpmb_state, &session->block_device.ipc_handle, &rpmb_key);
		if (ret < 0) {
			session->block_device.is_rpmb_init = 0;
            SS_ERR("%s: rpmb_init failed (%d)\n", __func__, ret);
		} else {
			/*init rpmb fs*/
			session->block_device.dev_rpmb.dev.block_count = 0;
			rc = block_device_tipc_rpmb_init(&session->block_device, chan_handle,
								&session->key);
			if (rc < 0) {
				SS_ERR("%s: block_device_tipc_rpmb_init failed (%d)\n", __func__, rc);
			}

			/*int sprdimgversion prot*/
			session->sprd_clt_port_ctx.rpmb_state = session->block_device.rpmb_state;
			ret = sprdimgverion_create_port(&(session->sprd_clt_port_ctx.client_ctx), SPRDIMGVERSION_CLIENT_PORT);
			if (ret < 0) {
				SS_ERR("%s: create port %s failed (%d)\n", __func__, SPRDIMGVERSION_CLIENT_PORT, rc);
			} else {
				session->sprd_clt_port_ctx.is_port_created = 1;
				SS_ERR("%s: create port %s success\n", __func__, SPRDIMGVERSION_CLIENT_PORT);
			}

			if ((ret < 0) && (rc < 0)){
				rpmb_uninit(session->block_device.rpmb_state);
				session->block_device.is_rpmb_init = 0;
			} else {
				session->block_device.is_rpmb_init = 1;
			}
		}
	}

	//add because,CA may connect multiple times wthen dev_ns.block_count must be init again.
	session->block_device.dev_ns.block_count = 0;
	rc = block_device_tipc_ns_init(&session->block_device, chan_handle,
					&session->key);
	if (rc < 0) {
		SS_ERR("%s: block_device_tipc_ns_init failed (%d)\n", __func__, rc);
	}

	session->proxy_ctx.ops.on_disconnect = proxy_disconnect;

#if USE_DUMMY_KEY <= 0
	hwkey_close(hwkey_session);
#endif

	return &session->proxy_ctx;

err_init_block_device:
err_get_rpmb_key:
err_get_storage_key:
#if USE_DUMMY_KEY <= 0
	hwkey_close(hwkey_session);
#endif
err_hwkey_open:
	free(session);
err_alloc_session:
	return NULL;
}

void proxy_disconnect(struct ipc_channel_context *ctx)
{
	struct storage_session *session = proxy_context_to_session(ctx);

	SS_ERR("%s: handle 0x%x\n", __func__, ctx->common.handle);

	if (NULL == session) {
		return;
	}

	block_device_tipc_uninit(&session->block_device);

	if (session->sprd_clt_port_ctx.is_port_created) {
		ipc_port_destroy(&(session->sprd_clt_port_ctx.client_ctx));
		session->sprd_clt_port_ctx.is_port_created = 0;
	}

	if (session->block_device.is_rpmb_init) {
		rpmb_uninit(session->block_device.rpmb_state);
		session->block_device.is_rpmb_init = 0;
	}

	free(session);
}
