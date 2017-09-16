/*
 * Copyright (C) 2017 spreadtrum.com
 */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <trusty_std.h>

#include <lib/sprdimgversion/sprdimgversion.h>


#include "log.h"


int sprdimgversion_test_get(void)
{
	unsigned int version = 0;
	sprdimgversion_session_t session;
	int ret;

	ret = sprdimgversion_open(&session);
	if (ret < 0) {
		TLOGE("sprdimgversion_open error: %d\n", ret);
		return -1;
	}

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_L_MODEM, &version);
	TLOGE("get IMAGE_L_MODEM version : %d, %d\n", version,ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_L_LDSP, &version);
	TLOGE("get IMAGE_L_LDSP version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_L_LGDSP, &version);
	TLOGE("get IMAGE_L_LGDSP version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_PM_SYS, &version);
	TLOGE("get IMAGE_PM_SYS version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_AGDSP, &version);
	TLOGE("get IMAGE_AGDSP version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_WCN, &version);
	TLOGE("get IMAGE_WCN version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_GPS, &version);
	TLOGE("get IMAGE_GPS version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_GPU, &version);
	TLOGE("get IMAGE_GPU version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_VBMETA, &version);
	TLOGE("get IMAGE_VBMETA version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_BOOT, &version);
	TLOGE("get IMAGE_BOOT version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_RECOVERY, &version);
	TLOGE("get IMAGE_RECOVERY version : %d, %d\n", version, ret);

	version = 0;
	ret = sprd_get_imgversion(session, IMAGE_SYSTEM, &version);
	TLOGE("get IMAGE_SYSTEM version : %d, %d\n", version, ret);

	sprdimgversion_close(session);

	return 0;
}


int sprdimgversion_test_set(void)
{
	unsigned int version = 1;
	sprdimgversion_session_t session;
	int ret;

	ret = sprdimgversion_open(&session);
	if (ret < 0) {
		TLOGE("sprdimgversion_open error: %d\n", ret);
		return -1;
	}

	ret = sprd_set_imgversion(session, IMAGE_L_MODEM, version);
	TLOGE("set IMAGE_L_MODEM version : %d, %d\n", version,ret);

	ret = sprd_set_imgversion(session, IMAGE_L_LDSP, version);
	TLOGE("set IMAGE_L_LDSP version : %d, %d\n", version, ret);


	ret = sprd_set_imgversion(session, IMAGE_L_LGDSP, version);
	TLOGE("set IMAGE_L_LGDSP version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_PM_SYS, version);
	TLOGE("set IMAGE_PM_SYS version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_AGDSP, version);
	TLOGE("set IMAGE_AGDSP version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_WCN, version);
	TLOGE("set IMAGE_WCN version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_GPS, version);
	TLOGE("set IMAGE_GPS version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_GPU, version);
	TLOGE("set IMAGE_GPU version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_VBMETA, version);
	TLOGE("set IMAGE_VBMETA version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_BOOT, version);
	TLOGE("set IMAGE_BOOT version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_RECOVERY, version);
	TLOGE("set IMAGE_RECOVERY version : %d, %d\n", version, ret);

	ret = sprd_set_imgversion(session, IMAGE_SYSTEM, version);
	TLOGE("set IMAGE_SYSTEM version : %d, %d\n", version, ret);


	sprdimgversion_close(session);

	return 0;
}
