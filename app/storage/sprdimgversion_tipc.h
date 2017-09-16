/*
 * Copyright (C) 2017 spreadtrum.com
 */

#pragma once

#include "ipc.h"
#include "rpmb.h"


#define SPRDIMGVERSION_CLIENT_SESSION_MAGIC 0x53535343 // SSSC


struct sprdimgversion_client_port_context {
	int is_port_created;
	struct rpmb_state *rpmb_state;
	struct ipc_port_context client_ctx;
};


/*
 * Structure that tracks state associated with a session.
 */
struct sprdimgversion_client_session {
	uint32_t magic;
	uuid_t uuid;
	struct rpmb_state *rpmb_state;
	struct ipc_channel_context context;
};


int sprdimgverion_create_port(struct ipc_port_context *client_ctx, const char *port_name);
