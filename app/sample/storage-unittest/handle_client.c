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

#include <lib/storage/storage.h>


#include "log.h"
#include "handle_client.h"
#include "storage_ipc.h"


extern void run_all_tests(const char *port);

static int send_res(struct evt_context *ctx,
                         enum storage_unittest_res result,
                         struct storage_unittest_msg *msg,
                         void *out, size_t out_size)
{
	size_t resp_buf_count = 1;
	int rc = -1;

	if (result == UNITTEST_RES_COMPLETE && NULL != out && out_size > 0) {
		++resp_buf_count;
	}

	iovec_t resp_bufs[resp_buf_count];

	msg->cmd |= STORAGE_UNITTEST_RESP_BIT;
	msg->size = sizeof(struct storage_unittest_msg) + out_size;
	msg->result = result;

	resp_bufs[0].base = msg;
	resp_bufs[0].len = sizeof(struct storage_unittest_msg);

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

static int storage_unittest_nsw_ser(struct evt_context *ctx, const char *port,
                                struct storage_unittest_msg *msg,
                                char *fname, size_t fname_len)

{
    enum storage_unittest_res result = UNITTEST_RES_COMPLETE;
    storage_session_t ss;
    file_handle_t handle;
    uint32_t data_buf[256];
    int rc = -1;


    struct storage_unittest_msg err_msg = {.cmd = STORAGE_UNITTEST_RESP_ERR};


	if (0 >= fname_len) {
		TLOGE("%s: invalid fname size (%zd)\n", __func__, fname_len);
        result = UNITTEST_RES_NOT_VALID;
		goto err_invalid_size;
	}

    rc = storage_open_session(&ss, port);
    if (0 > rc) {
        TLOGE("failed (%d) to open session\n", rc);
        result = UNITTEST_RES_OPEN_SESS_FAIL;
        goto err_open_session;
    }

    rc = storage_open_file(ss, &handle, fname, 0, 0);
    if (0 > rc) {
        TLOGE("failed (%d) to open file %s\n", rc, fname);
        result = UNITTEST_RES_OPEN_FILE_FAIL;
        goto err_open_file;
    }

    rc = storage_read(handle, 0, data_buf, sizeof(data_buf));
    if (0 > rc) {
        TLOGE("failed (%d) to read file %s\n", rc, fname);
        result = UNITTEST_RES_READ_FILE_FAIL;
        goto err_read_file;
    }

	result = UNITTEST_RES_COMPLETE;
	return send_res(ctx, result, msg, data_buf, rc);

err_read_file:
	storage_close_file(handle);
err_open_file:
	storage_close_session(ss);
err_open_session:
err_invalid_size:
	return send_res(ctx, result, &err_msg, NULL, 0);
}


int test_file_rename(struct evt_context *ctx, const char *port, 
                     struct storage_unittest_msg *msg)
{
    storage_session_t session_;
    file_handle_t handle;
    enum storage_unittest_res result = UNITTEST_RES_COMPLETE;
    int rc = -1;
    storage_off_t  data_len = 256;
	uint32_t data_buf[data_len + 1];
    const char *old_file_name = "test_file_rename_1";
    const char *new_file_name = "test_file_rename_2";


	struct storage_unittest_msg err_msg = {.cmd = STORAGE_UNITTEST_RESP_ERR};


    rc = storage_open_session(&session_, port);
    if (0 > rc) {
        TLOGE("storage_open_session(%s) failed!\n", port);
		result = UNITTEST_RES_OPEN_SESS_FAIL;
        goto err;
    }

	rc = storage_delete_file(session_, old_file_name, STORAGE_OP_COMPLETE);
	rc = storage_delete_file(session_, new_file_name, STORAGE_OP_COMPLETE);

    rc = storage_open_file(session_, &handle, old_file_name, STORAGE_FILE_OPEN_CREATE, 0);
    if ( 0 > rc) {
        TLOGE("storage_open_file(%s) failed! return %d\n", old_file_name, rc);
		result = UNITTEST_RES_OPEN_FILE_FAIL;
        goto err1;
    }

    memset(data_buf, 0x55, data_len);
	rc = storage_write(handle, 0, data_buf, data_len, 0);
    if ( rc != (int)data_len ) {
        TLOGE("storage_write() failed! return %d\n", rc);
        goto out;
    }

    storage_close_file(handle);
    storage_end_transaction(session_, STORAGE_OP_COMPLETE);
    storage_close_session(session_);


    //rename
    rc = storage_open_session(&session_, port);
    if (0 > rc) {
        TLOGE("storage_open_session(%s) failed!\n", port);
        goto err;
    }
	rc = storage_rename_file(session_, old_file_name, new_file_name, STORAGE_OP_COMPLETE);
    if ( 0 > rc) {
        TLOGE("storage_rename_file(%s,%s) failed! return %d\n", old_file_name, new_file_name, rc);
        storage_close_session(session_);
        goto err;
    }
    storage_end_transaction(session_, STORAGE_OP_COMPLETE);
    storage_close_session(session_);


    rc = storage_open_session(&session_, port);
    if (0 > rc) {
        TLOGE("storage_open_session(%s) failed!\n", port);
        goto err;
    }

    rc = storage_open_file(session_, &handle, new_file_name, 0, 0);
    if ( 0 > rc) {
        TLOGE("storage_open_file(%s) failed! return %d\n", new_file_name, rc);
		result = UNITTEST_RES_OPEN_FILE_FAIL;
        goto err1;
    }

    rc = storage_read(handle, 0, data_buf, data_len);
    if ( rc != (int)data_len) {
	    TLOGE("ReadPattern() failed!\n");
	    goto out;
    }

    result = UNITTEST_RES_COMPLETE;
	return send_res(ctx, result, msg, NULL, 0);

out:
    storage_close_file(handle);
err1:
    storage_close_session(session_);
err:
	return send_res(ctx, result, &err_msg, NULL, 0);

}


extern int sprdimgversion_test_set(void);
extern int sprdimgversion_test_get(void);



int handle_client_msg (struct evt_context *ctx, void *msg_buf, size_t msg_size)
{

	struct storage_unittest_msg *msg = msg_buf;
    enum storage_unittest_res result;
	size_t payload_len;
	void *payload;


	if (msg_size < sizeof(struct storage_unittest_msg)) {
		TLOGE("%s: invalid message of size (%zd)\n", __func__, msg_size);
        struct storage_unittest_msg err_msg = {.cmd = STORAGE_UNITTEST_RESP_ERR};
        return send_res(ctx, UNITTEST_RES_NOT_VALID, &err_msg, NULL, 0);
	}

    payload_len = msg_size - sizeof(struct storage_unittest_msg);
	payload = msg->payload;


	switch (msg->cmd) {
	case STORAGE_UNITTEST_ALL:
		TLOGI("SS-unittest: running all\n");
        run_all_tests(STORAGE_CLIENT_TD_PORT);
        run_all_tests(STORAGE_CLIENT_TDEA_PORT);
        run_all_tests(STORAGE_CLIENT_TP_PORT);
        TLOGI("SS-unittest: complete!");
        result = UNITTEST_RES_COMPLETE;
		break;
	case STORAGE_UNITTEST_TD:
        run_all_tests(STORAGE_CLIENT_TD_PORT);
        result = UNITTEST_RES_COMPLETE;
        break;
	case STORAGE_UNITTEST_TP:
		run_all_tests(STORAGE_CLIENT_TP_PORT);
        result = UNITTEST_RES_COMPLETE;
		break;
	case STORAGE_UNITTEST_TDEA:
		run_all_tests(STORAGE_CLIENT_TDEA_PORT);
        result = UNITTEST_RES_COMPLETE;
		break;
	case STORAGE_UNITTEST_TD_NSW_SER:
		return storage_unittest_nsw_ser(ctx, STORAGE_CLIENT_TD_PORT, msg, payload, payload_len);
	case STORAGE_UNITTEST_TP_NSW_SER:
		return storage_unittest_nsw_ser(ctx, STORAGE_CLIENT_TP_PORT, msg, payload, payload_len);
	case STORAGE_UNITTEST_TDEA_NSW_SER:
		return storage_unittest_nsw_ser(ctx, STORAGE_CLIENT_TDEA_PORT, msg, payload, payload_len);
	case STORAGE_UNITTEST_TD_RENAME:
		return test_file_rename(ctx, STORAGE_CLIENT_TD_PORT, msg);
	case STORAGE_UNITTEST_TP_RENAME:
		return test_file_rename(ctx, STORAGE_CLIENT_TP_PORT, msg);
	case STORAGE_UNITTEST_TDEA_RENAME:
		return test_file_rename(ctx, STORAGE_CLIENT_TDEA_PORT, msg);
	case SPRDIMGVERSION_UNITTEST_GET:
		sprdimgversion_test_get();
		result = UNITTEST_RES_COMPLETE;
		break;
	case SPRDIMGVERSION_UNITTEST_SET:
		sprdimgversion_test_set();
		result = UNITTEST_RES_COMPLETE;
		break;
	default:
		TLOGE("%s: unsupported command 0x%x\n", __func__, msg->cmd);
		result = UNITTEST_RES_UNIMPLEMENTED;
		break;
	}

	return send_res(ctx, result, msg, NULL, 0);

}
