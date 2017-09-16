/*
 * Copyright (C) 2017 spreadtrum.com
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <list.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <trusty_std.h>

#include <openssl/mem.h>

#include <interface/sprdimgversion/sprdimgversion.h>


#include "tipc_limits.h"
#include "ipc.h"
#include "sprdimgversion_tipc.h"


/* macros to help manage debug output */
#define SS_ERR(args...)		fprintf(stderr, "sprdimgversion: " args)

#ifdef APP_STORAGE_RPMB_BLOCK_SIZE
#define RPMB_BLK_SIZE (APP_STORAGE_RPMB_BLOCK_SIZE)
#else
#define RPMB_BLK_SIZE (512)
#endif

#ifdef SPRDMODEMIMGVERSION_BLOCK_INDEX
#define SPRDMODEMIMGVERSION_BLK_IND (SPRDMODEMIMGVERSION_BLOCK_INDEX)
#else
#define SPRDMODEMIMGVERSION_BLK_IND (1022 * 2)
#endif



#define SPRDIMGVER_MAGIC 0xA50000A5

struct sprd_imgversion_t {
    uint32_t magic;
    uint32_t l_modem_imgver;
    uint32_t l_ldsp_imgver;
    uint32_t l_lgdsp_imgver;
    uint32_t pm_sys_imgver;
    uint32_t agdsp_imgver;
    uint32_t wcn_imgver;
    uint32_t gps_imgver;
    uint32_t gpu_imgver;
    uint32_t vbmeta_imgver;
    uint32_t boot_imgver;
    uint32_t recovery_imgver;
};


static int get_sprdimgversion(struct rpmb_state *rpmb_state, struct sprd_imgversion_t *imgver)
{
	uint8_t data_rd[RPMB_BLK_SIZE];
	uint16_t block_ind, block_count;
	int ret;

	memset(data_rd, 0x0, sizeof(data_rd));
	block_count = sizeof(data_rd) / RPMB_BUF_SIZE;
	block_ind = SPRDMODEMIMGVERSION_BLK_IND;
	ret = rpmb_read(rpmb_state, data_rd, block_ind, block_count);
	if(ret < 0) {
		SS_ERR("%s: read fail! return code %d \n", __func__, ret);
		return ret;
	}

	memcpy((void *)imgver, data_rd, sizeof(struct sprd_imgversion_t));

	return 0;
}

static int sprdimgversion_send_response(struct sprdimgversion_client_session *session,
                         enum sprdimgversion_err result, struct sprdimgversion_msg *msg,
                         void *out, size_t out_size)
{
	size_t resp_buf_count = 1;
	int rc = -1;

	if (out != NULL && out_size != 0) {
		++resp_buf_count;
	}

	iovec_t resp_bufs[resp_buf_count];

	msg->cmd |= SPRDIMGVERSION_RESP_BIT;
	msg->size = sizeof(struct sprdimgversion_msg) + out_size;
	msg->result = result;

	resp_bufs[0].base = msg;
	resp_bufs[0].len = sizeof(struct sprdimgversion_msg);

	if (resp_buf_count == 2) {
		resp_bufs[1].base = out;
		resp_bufs[1].len = out_size;
	}

	struct ipc_msg resp_ipc_msg = {
		.iov = resp_bufs,
		.num_iov = resp_buf_count,
	};

	rc = send_msg(session->context.common.handle, &resp_ipc_msg);

	return rc;
}


static int sprdimgversion_send_result(struct sprdimgversion_client_session *session,
                       struct sprdimgversion_msg *msg, enum sprdimgversion_err result)
{
    return sprdimgversion_send_response(session, result, msg, NULL, 0);
}


static enum sprdimgversion_err sprdimgversion_set(struct sprdimgversion_msg *msg,
                                            struct sprdimgversion_get_set_msg *req, size_t req_size,
                                            struct sprdimgversion_client_session *session)
{

	enum sprdimgversion_err result = SPRDIMGVERSION_NO_ERROR;
	uint8_t data_wr[RPMB_BLK_SIZE];
	uint16_t block_ind, block_count;
	struct sprd_imgversion_t imgver;
	int ret;

	if (req_size < sizeof(*req)) {
		SS_ERR("%s: invalid request size (%zd)\n", __func__, req_size);
		return SPRDIMGVERSION_ERR_NOT_VALID;
	}

	ret = get_sprdimgversion(session->rpmb_state, &imgver);
	if(ret < 0) {
		SS_ERR("%s:get image version fail! return code %d \n", __func__, ret);
		return SPRDIMGVERSION_ERR_GENERIC;
	}

	switch(req->img_type) {
		case IMAGE_L_MODEM:
			imgver.l_modem_imgver = req->img_version;
			break;
		case IMAGE_L_LDSP:
			imgver.l_ldsp_imgver = req->img_version;
			break;
		case IMAGE_L_LGDSP:
			imgver.l_lgdsp_imgver = req->img_version;
			break;
		case IMAGE_PM_SYS:
			imgver.pm_sys_imgver = req->img_version;
			break;
		case IMAGE_AGDSP:
			imgver.agdsp_imgver = req->img_version;
			break;
		case IMAGE_WCN:
			imgver.wcn_imgver = req->img_version;
			break;
		case IMAGE_GPS:
			imgver.gps_imgver = req->img_version;
			break;
		case IMAGE_GPU:
			imgver.gpu_imgver = req->img_version;
			break;
		case IMAGE_VBMETA:
			imgver.vbmeta_imgver = req->img_version;
			break;
		case IMAGE_BOOT:
			imgver.boot_imgver = req->img_version;
			break;
		case IMAGE_RECOVERY:
			imgver.recovery_imgver = req->img_version;
			break;
		default:
			SS_ERR("%s: invalid sprd image type %d\n", __func__, req->img_type);
			result = SPRDIMGVERSION_ERR_GENERIC;
    }

	if (result != SPRDIMGVERSION_NO_ERROR) {
		return result;
	}

	memset(data_wr, 0x0, sizeof(data_wr));
	imgver.magic = SPRDIMGVER_MAGIC;
	memcpy((void *)data_wr, &imgver, sizeof(struct sprd_imgversion_t));

	block_ind = SPRDMODEMIMGVERSION_BLK_IND;
	block_count = sizeof(data_wr) / RPMB_BUF_SIZE;
	ret = rpmb_write(session->rpmb_state, data_wr, block_ind, block_count, true);
	if (ret < 0) {
		SS_ERR("%s: write fail! return code %d \n", __func__,ret);
		result = SPRDIMGVERSION_ERR_GENERIC;
	}

	return result;
}

static int sprdimgversion_get(struct sprdimgversion_msg *msg,
                              struct sprdimgversion_get_set_msg *req, size_t req_size,
                              struct sprdimgversion_client_session *session)
{
	struct sprd_imgversion_t imgver;
	enum sprdimgversion_err result = SPRDIMGVERSION_NO_ERROR;
	int ret;

	if (req_size < sizeof(*req)) {
		SS_ERR("%s: invalid request size (%zd)\n", __func__, req_size);
		result = SPRDIMGVERSION_ERR_NOT_VALID;
		goto err;
	}

	ret = get_sprdimgversion(session->rpmb_state, &imgver);
	if(ret < 0) {
		SS_ERR("%s:get image version fail! return code %d \n", __func__, ret);
		result = SPRDIMGVERSION_ERR_GENERIC;
		goto err;
	}

	if(imgver.magic != SPRDIMGVER_MAGIC) {
		SS_ERR("%s:invalid sprd imgversion magic %x exp %x \n", __func__, imgver.magic, SPRDIMGVER_MAGIC);
		result = SPRDIMGVERSION_ERR_GENERIC;
		goto err;
	}

	switch(req->img_type) {
		case IMAGE_L_MODEM:
			req->img_version = imgver.l_modem_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_L_LDSP:
			req->img_version = imgver.l_ldsp_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_L_LGDSP:
			req->img_version = imgver.l_lgdsp_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_PM_SYS:
			req->img_version = imgver.pm_sys_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_AGDSP:
			req->img_version = imgver.agdsp_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_WCN:
			req->img_version = imgver.wcn_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_GPS:
			req->img_version = imgver.gps_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_GPU:
			req->img_version = imgver.gpu_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_VBMETA:
			req->img_version = imgver.vbmeta_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_BOOT:
			req->img_version = imgver.boot_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		case IMAGE_RECOVERY:
			req->img_version = imgver.recovery_imgver;
			result = SPRDIMGVERSION_NO_ERROR;
			break;
		default:
			SS_ERR("%s: invalid sprd image type %d\n", __func__, req->img_type);
			result = SPRDIMGVERSION_ERR_GENERIC;
    }

	if (SPRDIMGVERSION_NO_ERROR == result) {
		return sprdimgversion_send_response(session, result, msg, req, req_size);
	}

err:
	return sprdimgversion_send_result(session, msg, result);
}

static struct sprdimgversion_client_session *chan_ctx_to_client_session(struct ipc_channel_context *ctx)
{
	assert(ctx != NULL);
	struct sprdimgversion_client_session *session;

	session = containerof(ctx, struct sprdimgversion_client_session, context);
	assert(session->magic == SPRDIMGVERSION_CLIENT_SESSION_MAGIC);
	return session;
}

static int sprdimgversion_client_handle_msg(struct ipc_channel_context *ctx, void *msg_buf, size_t msg_size)
{
	struct sprdimgversion_client_session *session;
	struct sprdimgversion_msg *msg = msg_buf;
	size_t payload_len;
	enum sprdimgversion_err result;
	void *payload;

	session = chan_ctx_to_client_session(ctx);

	if (msg_size < sizeof(struct sprdimgversion_msg)) {
		SS_ERR("%s: invalid message of size (%zd)\n", __func__, msg_size);
		struct sprdimgversion_msg err_msg = {.cmd = SPRDIMGVERSION_RESP_MSG_ERR};
		sprdimgversion_send_result(session, &err_msg, SPRDIMGVERSION_ERR_NOT_VALID);
		return ERR_NOT_VALID; /* would force to close connection */
	}

	payload_len = msg_size - sizeof(struct sprdimgversion_msg);
	payload = msg->payload;


	switch (msg->cmd) {
	case SPRDIMGVERSION_GET:
		return sprdimgversion_get(msg, payload, payload_len, session);
	case SPRDIMGVERSION_SET:
		result = sprdimgversion_set(msg, payload, payload_len, session);
		break;
	default:
		SS_ERR("%s: unsupported command 0x%x\n", __func__, msg->cmd);
		result = SPRDIMGVERSION_ERR_UNIMPLEMENTED;
		break;
	}

	return sprdimgversion_send_result(session, msg, result);

}

static struct sprdimgversion_client_port_context *port_ctx_to_client_port_ctx(struct ipc_port_context *context)
{
	assert(context != NULL);

	return containerof(context, struct sprdimgversion_client_port_context, client_ctx);
}


static void sprdimgversion_client_disconnect(struct ipc_channel_context *context)
{
	struct sprdimgversion_client_session *session;

	session = chan_ctx_to_client_session(context);

	if (NULL != session) {
		free(session);
	}
}


static void client_chan_ops_init(struct ipc_channel_ops *ops)
{
	ops->on_handle_msg = sprdimgversion_client_handle_msg;
	ops->on_disconnect = sprdimgversion_client_disconnect;
}

static struct ipc_channel_context *sprdimgversion_client_connect(struct ipc_port_context *parent_ctx,
                                                  const uuid_t *peer_uuid,
                                                  handle_t chan_handle)
{
	struct sprdimgversion_client_port_context *client_port_context;
	struct sprdimgversion_client_session *client_session;

	client_port_context = port_ctx_to_client_port_ctx(parent_ctx);

	client_session = calloc(1, sizeof(*client_session));
	if (client_session == NULL) {
		SS_ERR("out of memory allocating client session\n");
		return NULL;
	}

	client_session->magic = SPRDIMGVERSION_CLIENT_SESSION_MAGIC;

	client_session->rpmb_state = client_port_context->rpmb_state;

	/* cache identity information */
	memcpy(&client_session->uuid, peer_uuid, sizeof(*peer_uuid));

	client_chan_ops_init(&client_session->context.ops);


	return &client_session->context;
}



int sprdimgverion_create_port(struct ipc_port_context *client_ctx,
                              const char *port_name)
{
	int ret;

	/* start accepting client connections */
	client_ctx->ops.on_connect = sprdimgversion_client_connect;
	ret = ipc_port_create(client_ctx, port_name,
	                      1, STORAGE_MAX_BUFFER_SIZE,
	                      IPC_PORT_ALLOW_TA_CONNECT);
	if (ret < 0) {
		SS_ERR("%s: failure initializing client port (%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}
