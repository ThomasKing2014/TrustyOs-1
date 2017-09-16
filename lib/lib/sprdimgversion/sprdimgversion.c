/*
 * Copyright (C) 2017 spreadtrum.com
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <trusty_std.h>
#include <stdio.h>

#include <lib/sprdimgversion/sprdimgversion.h>

#define LOG_TAG "libsprdimgversion"
#define TLOGE(fmt, ...) \
	    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)



static int sprdimgversion_check_res(struct sprdimgversion_msg *msg, int res)
{

	if ((size_t)res < sizeof(*msg)) {
		TLOGE("invalid msg length (%zd < %zd)\n", res, sizeof(*msg));
		return ERR_NOT_VALID;
	}

	switch(msg->result) {
		case SPRDIMGVERSION_NO_ERROR:
			return res - sizeof(*msg);
		case SPRDIMGVERSION_ERR_NOT_VALID:
			TLOGE("cmd 0x%x: parameter is invalid\n", msg->cmd);
			return ERR_NOT_VALID;
		case SPRDIMGVERSION_ERR_UNIMPLEMENTED:
			TLOGE("cmd 0x%x: is unhandles command\n", msg->cmd);
			return ERR_NOT_VALID;
		case SPRDIMGVERSION_ERR_GENERIC:
			TLOGE("cmd 0x%x: internal server error\n", msg->cmd);
			return ERR_GENERIC;
		default:
			TLOGE("cmd 0x%x: unhandled server response %u\n", msg->cmd, msg->result);
	}

	return ERR_GENERIC;
}


static ssize_t sprdimgversion_get_res(sprdimgversion_session_t session,
                            struct iovec *rx_iovs, uint rx_iovcnt)

{
	uevent_t ev;
	struct ipc_msg_info mi;
	struct ipc_msg rx_msg = {
		.iov = rx_iovs,
		.num_iov = rx_iovcnt,
	};

	if (!rx_iovcnt)
		return 0;

    /* wait for reply */
	int rc = wait(session, &ev, -1);
	if (rc != NO_ERROR) {
		TLOGE("%s: interrupted waiting for response", __func__);
		return rc;
	}

	rc = get_msg(session, &mi);
	if (rc != NO_ERROR) {
		TLOGE("%s: failed to get_msg (%d)\n", __func__, rc);
		return rc;
	}

	rc = read_msg(session, mi.id, 0, &rx_msg);
	put_msg(session, mi.id);
	if (rc < 0) {
		TLOGE("%s: failed to read msg (%d)\n", __func__, rc);
		return rc;
	}

	if ((size_t)rc != mi.len) {
		TLOGE("%s: partial message read (%zd vs. %zd)\n",
              __func__, (size_t)rc, mi.len);
		return ERR_IO;
	}

	return rc;
}


static int sprdimgversion_wait_to_send(handle_t session, struct ipc_msg *msg)
{
	struct uevent ev;
	int rc;

	rc = wait(session, &ev, -1);
	if (rc < 0) {
		TLOGE("failed to wait for outgoing queue to free up\n");
		return rc;
	}

	if (ev.event & IPC_HANDLE_POLL_SEND_UNBLOCKED) {
		return send_msg(session, msg);
	}

	if (ev.event & IPC_HANDLE_POLL_MSG) {
		return ERR_BUSY;
	}

	if (ev.event & IPC_HANDLE_POLL_HUP) {
		return ERR_CHANNEL_CLOSED;
	}

	return rc;
}


static ssize_t sprdimgversion_send_req(sprdimgversion_session_t session,
                         struct iovec *tx_iovs, uint tx_iovcnt,
                         struct iovec *rx_iovs, uint rx_iovcnt)
{
	ssize_t rc;

	struct ipc_msg tx_msg = {
		.iov = tx_iovs,
		.num_iov = tx_iovcnt,
	};

	rc = send_msg(session, &tx_msg);
	if (rc == ERR_NOT_ENOUGH_BUFFER) {
		rc = sprdimgversion_wait_to_send(session, &tx_msg);
	}

	if (rc < 0) {
		TLOGE("%s: failed (%d) to send_msg\n", __func__, (int)rc);
		return rc;
	}

	rc = sprdimgversion_get_res(session, rx_iovs, rx_iovcnt);
	if (rc < 0) {
		TLOGE("%s: failed (%d) to get response\n", __func__, (int)rc);
		return rc;
	}

	return rc;
}


/*
*@session   session handle retrieved from sprdimgversion_open
*@imgType   The image which need to write the version
*@swVersion return image version
*Return value: zero is ok
*/
int sprd_set_imgversion(sprdimgversion_session_t session, antirb_image_type imgType, unsigned int swVersion)
{
	struct sprdimgversion_msg msg = { .cmd = SPRDIMGVERSION_SET};
	struct sprdimgversion_get_set_msg req = { .img_type = imgType, .img_version = swVersion };
	struct iovec tx[2] = {{&msg, sizeof(msg)}, {&req, sizeof(req)}};
	struct iovec rx[1] = {{&msg, sizeof(msg)}};

	ssize_t rc = sprdimgversion_send_req(session, tx, 2, rx, 1);

	return sprdimgversion_check_res(&msg, rc);
}

/*
*@session   session handle retrieved from sprdimgversion_open
*@imgType   The image which need to get the version
*@swVersion return image version
*Return value: zero is ok
*
*/
int sprd_get_imgversion(sprdimgversion_session_t session, antirb_image_type imgType, unsigned int* swVersion)
{
	struct sprdimgversion_msg msg = { .cmd = SPRDIMGVERSION_GET};
	struct sprdimgversion_get_set_msg req = { .img_type = imgType, .img_version = 0 };
	struct iovec tx[2] = {{&msg, sizeof(msg)}, {&req, sizeof(req)}};
	struct iovec rx[2] = {{&msg, sizeof(msg)}, {&req, sizeof(req)}};

	if (swVersion == NULL) {
		return ERR_NOT_VALID;
	}

	ssize_t rc = sprdimgversion_send_req(session, tx, 2, rx, 2);

	rc = sprdimgversion_check_res(&msg, rc);


	if (rc < 0) { return rc;}

	if (rc < (ssize_t)sizeof(req)) {
		TLOGE("%s: response lenth error,%d,exp %d\n", __func__, (int)rc, sizeof(req));
		return ERR_NOT_VALID;
	}

	*swVersion = req.img_version;

	return 0;
}

/**
 * sprdimgversion_open() - Opens a trusty sprdimgversion session.
 *
 * Return: 0 on success, * or an error code < 0 on
 * failure.
 */
int sprdimgversion_open(sprdimgversion_session_t *session)
{
	long ret;

	ret = connect(SPRDIMGVERSION_CLIENT_PORT, 0);
	if (ret < 0) {
		return ret;
	} else {
		*session = ret;
		return 0;
	}
}

/**
* sprdimgversion_close() - Closes the session.
*/
void sprdimgversion_close(sprdimgversion_session_t session)
{
	close(session);
}
