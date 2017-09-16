/*
 * Copyright (C) 2017 spreadtrum.com
 *
 */
#pragma once

#include "rpmb.h"

int rpmbproxy_mac(struct rpmb_packet *packet, size_t packet_count,
                  struct rpmb_key *mac);
int get_rpmb_key(void);
