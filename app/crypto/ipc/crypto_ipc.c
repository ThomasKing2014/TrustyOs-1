/*
 * The MIT License (MIT)
 * Copyright (c) 2008-2015 Travis Geiselbrecht
 * Copyright (c) 2016, Spreadtrum Communications.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <err.h>
#include <list.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_std.h>

#include <app/crypto/crypto_ipc.h>
#include <interface/hwrng/hwrng.h>
#include <interface/hwkey/hwkey.h>

static bool handle_port_errors(const uevent_t *ev);
static int restart_service(cipc_srv_state_t *state);

static void hwrng_handle_port(const uevent_t *ev);
static void hwkey_handle_port(const uevent_t *ev);

static const cipc_srv_t _services[] =
{
	/* HWRNG */
	{
		.name = HWRNG_PORT,
		.msg_num = 1,
		.msg_size = 1024,
		.port_flags = IPC_PORT_ALLOW_ALL,
		.port_handler = hwrng_handle_port,
	},
	/* HWKEY */
	{
		.name = HWKEY_PORT,
		.msg_num = 1,
		.msg_size = 1024,
		.port_flags = IPC_PORT_ALLOW_ALL,
		.port_handler = hwkey_handle_port,
	}
};

static cipc_srv_state_t _srv_states[countof(_services)] = {
	[0 ... (countof(_services) - 1)] = {
		.port = INVALID_IPC_HANDLE,
	}
};

/* hwrng service */
static void hwrng_handle_port(const uevent_t *ev)
{
	if (handle_port_errors(ev)) {
		return;
	}

	hwrng_msg_handle(ev);
}

/* hwkey service */
static void hwkey_handle_port(const uevent_t *ev)
{
	if (handle_port_errors(ev)) {
		return;
	}

	hwkey_msg_handle(ev);
}

static cipc_srv_state_t *get_srv_state(const uevent_t *ev)
{
	return containerof(ev->cookie, struct crypto_ipc_srv_state, handler);
}

/*
 *  Handle common port errors
 */
static bool handle_port_errors(const uevent_t *ev)
{
	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
		/* should never happen with port handles */
		TLOGI("error event (0x%x) for port (%d)\n",
		       ev->event, ev->handle);

		/* recreate service */
		//restart_service(get_srv_state(ev));
		close(ev->handle);
		return true;
	}

	return false;
}

static void _destroy_service(cipc_srv_state_t *state)
{
	if (!state) {
		TLOGI("non-null state expected\n");
		return;
	}

	/* free state if any */
	if (state->priv) {
		free(state->priv);
		state->priv = NULL;
	}

	/* close port */
	if (state->port != INVALID_IPC_HANDLE) {
		int rc = close(state->port);
		if (rc != NO_ERROR) {
			TLOGI("Failed (%d) to close port %d\n", rc, state->port);
		}
		state->port = INVALID_IPC_HANDLE;
	}

	/* reset handler */
	state->service = NULL;
	state->handler.proc = NULL;
	state->handler.priv = NULL;
}

/*
 *  Create service
 */
static int _create_service(const cipc_srv_t *srv, cipc_srv_state_t *state)
{
	if (!srv || !state) {
		TLOGI("null service specified\n");
		return ERR_INVALID_ARGS;
	}

	/* create port */
	int rc = port_create(srv->name, srv->msg_num, srv->msg_size,
			     srv->port_flags);
	if (rc < 0) {
		TLOGI("Failed (%d) to create port\n", rc);
		return rc;
	}

	/* setup port state  */
	state->port = (handle_t)rc;
	state->handler.proc = srv->port_handler;
	state->handler.priv = state;
	state->service = srv;
	state->priv = NULL;

	/* attach handler to port handle */
	rc = set_cookie(state->port, &state->handler);
	if (rc < 0) {
		TLOGI("Failed (%d) to set cookie on port %d\n",
		      rc, state->port);
		goto err_set_cookie;
	}

	return NO_ERROR;

err_calloc:
err_set_cookie:
	_destroy_service(state);
	return rc;
}

/*
 *  Initialize all services
 */
static int init_services(void)
{
	TLOGI ("Init crypto services!!!\n");

	for (uint i = 0; i < countof(_services); i++) {
		int rc = _create_service(&_services[i], &_srv_states[i]);
		if (rc < 0) {
			TLOGI("Failed (%d) to create service %s\n",
			      rc, _services[i].name);
			return rc;
		}
	}

	return 0;
}

/*
 *  Kill all servoces
 */
static void kill_services(void)
{
	TLOGI ("Terminating crypto services\n");

	/* close any opened ports */
	for (uint i = 0; i < countof(_services); i++) {
		_destroy_service(&_srv_states[i]);
	}
}

/*
 *  Restart specified service
 */
static int restart_service(cipc_srv_state_t *state)
{
	if (!state) {
		TLOGI("non-null state expected\n");
		return ERR_INVALID_ARGS;
	}

	const cipc_srv_t *srv = state->service;
	_destroy_service(state);
	return _create_service(srv, state);
}

/*
 *  Dispatch event
 */
static void dispatch_event(const uevent_t *ev)
{
	assert(ev);

	if (ev->event == IPC_HANDLE_POLL_NONE) {
		/* not really an event, do nothing */
		TLOGI("got an empty event\n");
		return;
	}

	if (ev->handle == INVALID_IPC_HANDLE) {
		/* not a valid handle  */
		TLOGI("got an event (0x%x) with invalid handle (%d)",
		      ev->event, ev->handle);
		return;
	}

	/* check if we have handler */
	cipc_event_handler_t *handler = ev->cookie;
	if (handler && handler->proc) {
		/* invoke it */
		handler->proc(ev);
		return;
	}

	/* no handler? close it */
	TLOGI("no handler for event (0x%x) with handle %d\n",
	       ev->event, ev->handle);
	close(ev->handle);

	return;
}

/*
 *  Main entry point of service task
 */
int main(void)
{
	int rc;
	uevent_t event;

	/* Initialize service */
	rc = init_services();
	if (rc != NO_ERROR ) {
		TLOGI("Failed (%d) to init service", rc);
		kill_services();
		return -1;
	}

	/* handle events */
	while (true) {
		event.handle = INVALID_IPC_HANDLE;
		event.event  = 0;
		event.cookie = NULL;
		rc = wait_any(&event, -1);
		if (rc < 0) {
			TLOGI("wait_any failed (%d)", rc);
			continue;
		}
		if (rc == NO_ERROR) { /* got an event */
			dispatch_event(&event);
		}
	}

	kill_services();
	return 0;
}
