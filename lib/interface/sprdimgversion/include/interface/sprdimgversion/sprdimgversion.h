/*
 * Copyright (C) 2017 spreadtrum.com
 */

#pragma once

#include <stdint.h>


/*
 * @SPRDIMGVERION_CLIENT_PORT:     Port used by clients that require sprd imgage version.
 */
#define SPRDIMGVERSION_CLIENT_PORT   "com.spreadtrum.sprdimgversion"



enum sprdimgversion_cmd {
	SPRDIMGVERSION_REQ_SHIFT = 1,
	SPRDIMGVERSION_RESP_BIT  = 1,

	SPRDIMGVERSION_RESP_MSG_ERR   = SPRDIMGVERSION_RESP_BIT,

	SPRDIMGVERSION_GET    = 1 << SPRDIMGVERSION_REQ_SHIFT,
	SPRDIMGVERSION_SET      = 2 << SPRDIMGVERSION_REQ_SHIFT,
};

/**
 * enum sprdimgversion_err - error codes for sprdimgversion protocol
 * @SPRDIMGVERSION_NO_ERROR:           all OK
 * @SPRDIMGVERSION_ERR_GENERIC:        unknown error.
 * @SPRDIMGVERSION_ERR_NOT_VALID:      input not valid.
 */
enum sprdimgversion_err {
	SPRDIMGVERSION_NO_ERROR          = 0,
	SPRDIMGVERSION_ERR_GENERIC       = 1,
	SPRDIMGVERSION_ERR_NOT_VALID     = 2,
	SPRDIMGVERSION_ERR_UNIMPLEMENTED = 3,
};


typedef enum enAntiRBImageType {
	IMAGE_VBMETA = 0,
	IMAGE_BOOT,
	IMAGE_RECOVERY,
	IMAGE_SYSTEM,
	IMAGE_VENDOR,
	IMAGE_L_MODEM,
	IMAGE_L_LDSP,
	IMAGE_L_LGDSP,
	IMAGE_PM_SYS,
	IMAGE_AGDSP,
	IMAGE_WCN,
	IMAGE_GPS,
	IMAGE_GPU,
	IMAGE_TYPE_END
} antirb_image_type;


/**
 * struct sprdimgversion_get_set_msg - message format for SPRDIMGVERSION_GET/SPRDIMGVERSION_GET
 * @size:   the size of the file
 */
struct sprdimgversion_get_set_msg {
	enum enAntiRBImageType img_type;
	unsigned int img_version;
};


/**
 * struct sprdimgversion_msg - generic req/resp format for all sprdimgversion commands
 * @cmd:        one of enum storage_cmd
 * @op_id:      client chosen operation identifier.
 * @size:       total size of the message including this header
 * @result:     one of enum sprdimgversion_err
 * @payload:    beginning of command specific message format
 */
struct sprdimgversion_msg {
	uint32_t cmd;
	uint32_t op_id;
	uint32_t size;
	int32_t  result;
	uint8_t  payload[0];
};
