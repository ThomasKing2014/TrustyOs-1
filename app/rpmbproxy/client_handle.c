/*
 * Copyright (C) 2017 spreadtrum
 */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <trusty_std.h>


#include "log.h"
#include "client_handle.h"
#include "rpmbproxy_ipc.h"
#include "rpmbproxy.h"



static int send_resp(struct event_context *ctx,
                         enum rpmbproxy_res result,
                         struct rpmbproxy_msg *msg,
                         void *out, size_t out_size)
{
    size_t resp_buf_count = 1;
    int rc = -1;

    if (result == RPMBPROXY_NO_ERROR && NULL != out && out_size > 0) {
        ++resp_buf_count;
    }

    iovec_t resp_bufs[resp_buf_count];

    msg->cmd |= RPMBPROXY_RESP_BIT;
    msg->size = sizeof(struct rpmbproxy_msg) + out_size;
    msg->result = result;

    resp_bufs[0].base = msg;
    resp_bufs[0].len = sizeof(struct rpmbproxy_msg);

    if (resp_buf_count == 2) {
        resp_bufs[1].base = out;
        resp_bufs[1].len = out_size;
    }

    struct ipc_msg resp_ipc_msg = {
        .iov = resp_bufs,
        .num_iov = resp_buf_count,
    };

    rc = send_msg(ctx->handle, &resp_ipc_msg);

    return rc;
}

static int handle_rpmbproxy_mac(struct event_context *ctx,
                struct rpmbproxy_msg *msg,
                struct rpmbproxy_mac_req *req,
                size_t req_len)
{
    enum rpmbproxy_res result = RPMBPROXY_NO_ERROR;
    uint32_t rpmb_packet_num = 0;
    struct rpmb_packet *rpmb_pacs = NULL;
    struct rpmb_key mac;
    int rc = -1;

    if (req_len < sizeof(*req)) {
        TLOGE("%s: invalid request size (%zd)\n", __func__, req_len);
        result = RPMBPROXY_ERR_NOT_VALID;
        goto err_invalid_input;
    }

    rpmb_pacs = (struct rpmb_packet *)req->payload;
    rpmb_packet_num = req->rpmb_packet_num;

    if (req_len - sizeof(*req) != rpmb_packet_num * sizeof(struct rpmb_packet)){
        TLOGE("%s: invalid rpmb packet number (%zd), %d, %d, %d\n", __func__, rpmb_packet_num,
				req_len, sizeof(*req), sizeof(struct rpmb_packet));
        result = RPMBPROXY_ERR_NOT_VALID;
        goto err_invalid_input;
    }

    rc = rpmbproxy_mac(rpmb_pacs, rpmb_packet_num, &mac);
    if (0 != rc) {
        TLOGE("%s: Failed to compute rpmbmac\n", __func__);
        result = RPMBPROXY_ERR_GENERIC;
        goto err_mac;
    }

     result = RPMBPROXY_NO_ERROR;
    return send_resp(ctx, result, msg, &mac, sizeof(struct rpmb_key));

err_mac:
err_invalid_input:
    return send_resp(ctx, result, msg, NULL, 0);
}


int handle_clt_msg (struct event_context *ctx, void *msg_buf, size_t msg_size)
{

    struct rpmbproxy_msg *msg = msg_buf;
    enum rpmbproxy_res result;
    size_t payload_len;
    void *payload;


    if (msg_size < sizeof(struct rpmbproxy_msg)) {
        TLOGE("%s: invalid message of size (%zd)\n", __func__, msg_size);
        struct rpmbproxy_msg err_msg = {.cmd = RPMBPROXY_RESP_MSG_ERR};
        return send_resp(ctx, RPMBPROXY_ERR_NOT_VALID, &err_msg, NULL, 0);
    }

    payload_len = msg_size - sizeof(struct rpmbproxy_msg);
    payload = msg->payload;


    switch (msg->cmd) {
    case RPMBPROXY_MAC:
        return handle_rpmbproxy_mac(ctx, msg, payload, payload_len);
    default:
        TLOGE("%s: unsupported command 0x%x\n", __func__, msg->cmd);
        result = RPMBPROXY_ERR_UNIMPLEMENTED;
        break;
    }

    return send_resp(ctx, result, msg, NULL, 0);

}
