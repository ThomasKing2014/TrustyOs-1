/*
 * Copyright (C) 2017 spreadtrum.com
 */

#pragma once

#include <compiler.h>
#include <sys/types.h>

#include <trusty_ipc.h>
#include <interface/sprdimgversion/sprdimgversion.h>


typedef handle_t sprdimgversion_session_t;


/**
 * sprdimgversion_open() - Opens a trusty sprdimgversion session.
 *
 * Return: 0 on success, * or an error code < 0 on
 * failure.
 */
int sprdimgversion_open(sprdimgversion_session_t *session);

/**
 * sprdimgversion_close() - Closes the session.
 */
void sprdimgversion_close(sprdimgversion_session_t session);


/*
*@session   session handle retrieved from sprdimgversion_open
*@imgType   The image which need to get the version
*@swVersion return image version
*Return value: zero is ok
*
*/
int sprd_get_imgversion(sprdimgversion_session_t session, antirb_image_type imgType, unsigned int* swVersion);

/*
*@session   session handle retrieved from sprdimgversion_open
*@imgType   The image which need to write the version
*@swVersion return image version
*Return value: zero is ok
*/
int sprd_set_imgversion(sprdimgversion_session_t session, antirb_image_type imgType, unsigned int swVersion);
