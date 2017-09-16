/*
 * Copyright (C) 2017 spreadtrum
 */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>

#include <trusty_std.h>

#include "log.h"
#include "storage_ipc.h"



int main(void)
{
    int rc;

    struct evt_context ctx;



    TLOGI ("Welcome to storage unittest!!!\n");

	ctx.evt_handler = port_evt_handle;
    //create port
    rc = port_create(STORAGE_UNITTEST_PROXY_PORT, 1,
            STORAGE_UNITTEST_MAX_BUFFER_SIZE, IPC_PORT_ALLOW_NS_CONNECT);

    if (rc < 0) {
		TLOGE("failed (%d) to create port STORAGE_UNITTEST_PROXY_PORT\n", rc);
		return rc;
	}

    handle_t port_handle = (handle_t) rc;
	rc = set_cookie(port_handle, &ctx);
	if (rc < 0) {
		TLOGE("Failed to set cookie on port STORAGE_UNITTEST_PROXY_PORT (%d)\n", rc);
		close(port_handle);
	}
    ctx.handle = port_handle;


	TLOGI("waiting for android application to triger\n");
    uevent_t event;
	for (;;) {
		event.handle = INVALID_IPC_HANDLE;
		event.event = 0;
		event.cookie = NULL;

		int rc = wait_any(&event, -1);
		if (rc == NO_ERROR) {
            dispatch_evt(&event);
		}
		if (rc < 0) {
            TLOGE("wait_any failed (%d)", rc);
            break;
        }

	}

    close(port_handle);

    return 0;
}
