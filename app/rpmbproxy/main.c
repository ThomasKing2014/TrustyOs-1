/*
 * Copyright (C) 2017 spreadtrum.com
 */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <trusty_std.h>

#include "log.h"
#include "rpmbproxy_ipc.h"
#include "rpmbproxy.h"




int main(void)
{
    struct event_context ctx;
    int rc;


    rc = get_rpmb_key();
    if (0 != rc) {
        TLOGE("Failed to get rpmb key,to exit.\n");
        return rc;
    }

    ctx.evt_handler = port_event_handle;
    //create port
    rc = port_create(RPMBPROXY_PORT, 1,
            RPMBPROXY_MAX_BUFFER_SIZE, IPC_PORT_ALLOW_NS_CONNECT);
    if (rc < 0) {
        TLOGE("failed (%d) to create port RPMBPROXY_PORT\n", rc);
        return rc;
    }

    handle_t port_handle = (handle_t) rc;
    rc = set_cookie(port_handle, &ctx);
    if (rc < 0) {
        TLOGE("Failed to set cookie on port RPMBPROXY_PORT (%d)\n", rc);
        close(port_handle);
    }
    ctx.handle = port_handle;



    TLOGI("waiting for android application to connect\n");
    uevent_t event;
    for (;;) {
        event.handle = INVALID_IPC_HANDLE;
        event.event = 0;
        event.cookie = NULL;

        int rc = wait_any(&event, -1);
        if (rc == NO_ERROR) {
            event_dispatch(&event);
        }
        if (rc < 0) {
            TLOGE("wait_any failed (%d)", rc);
            break;
        }
    }
    TLOGI("exiting port RPMBPROXY_PORT\n");

    close(port_handle);

    return 0;
}
