/*
 * Copyright (c) 2015, Spreadtrum.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define LOG_TAG "TrustyProduction"
#include <cutils/log.h>

#include <trusty/tipc.h>

#include "tee_production.h"
#include "production_ipc.h"
#include <cutils/properties.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define BLOCK_SIZE (4)
#define UID_BLOCK_START (0)
#define UID_BLOCK_END (1)
#define UID_BLOCK_LEN (UID_BLOCK_END - UID_BLOCK_START + 1)
#define MAX_TRANS_SIZE 4024  //for keybox CA transfort to TA


#define UID_LENGTH   (17)
#define PROPERTY_VALUE_MAX 128

#undef DIS_EFUSE_DEBUG
#define DIS_EFUSE_DEBUG 1

#if DIS_EFUSE_DEBUG
#define DEV_NODE "/dev/sprd_otp_ap_efuse"
#else
#define DEV_NODE "/dev/sprd_dummy_otp"
#endif

extern int rpmb_program_key(uint8_t *key_byte, size_t key_len);
extern int production_efuse_secure_is_enabled(void);
extern int production_efuse_secure_enable(void);

static int handle_ = 0;

int trusty_production_connect(void){
    ALOGD("%s enter\n", __func__);
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, PRODUCTION_PORT);
    if (rc < 0) {
        ALOGD("tipc_connect() failed! \n");
        return rc;
    }
    handle_ = rc;
    ALOGD("handle = %d \n", handle_);
    return 0;
}

int trusty_production_call(uint32_t cmd, void * in, uint32_t in_size, uint8_t * out, uint32_t * out_size){
    ALOGD("Enter %s, cmd is %02x, in_size = %d \n", __func__, cmd, in_size);
    if (handle_ == 0) {
        ALOGD("not connected\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(production_message);
    production_message *msg = malloc(msg_size) ;
    msg->cmd = cmd;
    msg->msg_code = 0 ;
    memcpy(msg->payload, in, in_size);

    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGD("failed to send cmd (%d) to %s: %s\n", cmd,
        PRODUCTION_PORT, strerror(errno));
        return -errno;
    }

    rc = read(handle_, out, *out_size);
    if (rc < 0) {
        ALOGD("failed to retrieve response for cmd (%d) to %s: %s\n",
                cmd, PRODUCTION_PORT, strerror(errno));
        return -errno;
    }

    if ((size_t) rc < sizeof(production_message)) {
        ALOGD("invalid response size (%d)\n", (int) rc);
        return -EINVAL;
    }

    msg = (production_message*) out;

    if ((cmd | PRODUCTION_RESP_BIT) != msg->cmd) {
        ALOGD("invalid command (%d)", msg->cmd);
        return -EINVAL;
    }

    *out_size = ((size_t) rc) - sizeof(production_message);
    ALOGD("CA read rsp from TA, rsp cmd is %x, msg->msg_code is %x, out_size is %d\n", msg->cmd, msg->msg_code, *out_size);
    return msg->msg_code;
}

void trusty_production_disconnect() {
    if (handle_ != 0) {
        tipc_close(handle_);
    }
}

static uint8_t *sec_memcpy_invert(uint8_t *dest, const uint8_t *src, unsigned int count)
{
    char *tmp = dest;
    const char *s = src+count-1;

    while (count--)
        *tmp++ = *s--;
    return dest;
}

static void organize_rsp(uint16_t msg_id, int msg_code, uint8_t* msg_data, uint32_t * out_size, uint8_t* rsp, uint32_t* rsp_len){
    ALOGD("production CA organize_rsp, start!\n");
    uint32_t length=8;
    uint16_t id = 0 ;
    uint8_t flag=RSP_FLAG;
    int return_code = msg_code;
    uint8_t* command_data;
    uint8_t xor_data;
    if(*out_size>0 && msg_data!=NULL){
        length += *out_size;
        command_data = msg_data;
    }
    *rsp_len = length+4;
    ALOGD("production CA organize_rsp, rsp_len is %d, return_code is %x, out_size is %d.\n",*rsp_len, return_code, *out_size);
    switch(msg_id){
        case CMD_SYSTEM_INIT:
            id=RSP_SYSTEM_INIT;
            break;
        case CMD_GET_UID:
            id=RSP_GET_UID;
            break;
        case CMD_SET_RTC:
            id=RSP_SET_RTC;
            break;
        case CMD_SET_ROTPK:
            id=RSP_SET_ROTPK;
            break;
        case CMD_GET_ROTPK:
            id=RSP_GET_ROTPK;
            break;
        case CMD_SYSTEM_CLOSE:
            id=RSP_SYSTEM_CLOSE;
            break;
        case CMD_CHECK_SECURE:
            id=RSP_CHECK_SECURE;
            break;
        case CMD_GET_DEVICE_ID:
             id=RSP_GET_DEVICE_ID;
             break;
        case CMD_SEND_KEYBOX:
             id=RSP_SEND_KEYBOX;
            break;
    }
    ALOGD("%s id is %x\n", __func__, id);
    memcpy(rsp, &length, sizeof(uint32_t));
    memcpy(rsp+4, &id, sizeof(uint16_t));
    memcpy(rsp+6, &flag, sizeof(uint8_t));
    memcpy(rsp+7, &return_code, sizeof(int));
    if(*out_size>0 && msg_data!=NULL){
        memcpy(rsp+11, command_data, *out_size);
    }
    xor_data = rsp[0];
    int i = 0;
    for(i=1;i<*rsp_len-1;i++){
        xor_data ^= rsp[i];
    }
    rsp[*rsp_len-1] = xor_data;
}

static int efuse_block_read(unsigned int blk, unsigned int *read_data)
{
    int fd = -1, ret = PROD_OK;
    off_t curpos, offset;

    if (read_data == NULL)
        return PROD_ERROR_GET_UID;

    fd = open(DEV_NODE, O_RDWR);
    if (fd < 0) {
        ALOGE("%s()->Line:%d; %s open error, fd = %d. \n",
                __FUNCTION__, __LINE__, DEV_NODE, fd);
        return PROD_ERROR_GET_UID;
    }

    offset = blk * BLOCK_SIZE;
    curpos = lseek(fd, offset, SEEK_CUR);
    if (curpos == -1) {
        ALOGE("%s()->Line:%d; lseek error\n", __FUNCTION__, __LINE__);
        close(fd);
        return PROD_ERROR_GET_UID;
    }

    ret = read(fd, read_data, sizeof(unsigned int));
    if (ret <= 0) {
        ALOGE("%s()->Line:%d; read efuse block(%d) data error, retcode = %d; \n",
                __FUNCTION__, __LINE__, blk, ret);
        close(fd);
        return PROD_ERROR_GET_UID;
    }

    close(fd);
    return ret;
}

static int efuse_uid_read(uint8_t *uid, uint32_t* out_size)
{
    unsigned int block0, block1;
    unsigned int x, y, wafer_id;
    unsigned int LOTID_0, LOTID_1, LOTID_2, LOTID_3, LOTID_4, LOTID_5;
    unsigned char values[UID_LENGTH + 1] = {0};

    ALOGD("%s()->Line:%d; enter\n", __FUNCTION__, __LINE__);

    if ((NULL == uid) || (NULL == out_size))
        return PROD_ERROR_GET_UID;

    efuse_block_read(0, &block0);
    efuse_block_read(1, &block1);

    y = block1 & 0x7F;
    x = (block1 >> 7) & 0x7F;
    wafer_id = (block1 >> 14) & 0x1F;
    LOTID_0 = (block1 >> 19) & 0x3F;
    LOTID_1 = (block1 >> 25) & 0x3F;
    LOTID_2 = block0 & 0x3F;
    LOTID_3 = (block0 >> 6) & 0x3F;
    LOTID_4 = (block0 >> 12) & 0x3F;
    LOTID_5 = (block0 >> 18) & 0x3F;

    sprintf(values, "%c%c%c%c%c%c%02d%03d%03d", LOTID_5 + 48, LOTID_4 + 48,
            LOTID_3 + 48, LOTID_2 + 48, LOTID_1 + 48, LOTID_0 + 48,
            wafer_id, x, y);
    strncpy(uid, values, sizeof(values));
    *out_size = strlen(values);
    ALOGD("%s()->Line:%d; uid = %s, len = %d \n",
            __FUNCTION__, __LINE__, uid, *out_size);
    return PROD_OK;
}

static int storageproxyd_start(void){
	ALOGD("Enter %s, \n", __func__);
	char is_ok[PROPERTY_VALUE_MAX] = {'\0'};
	property_get("vold.realdata.mount", is_ok, "");
	ALOGD("property:vold.realdata.mount:%s\n",is_ok);
	if(strncmp(is_ok, "ok",2)){
		ALOGD("set storageproxyd_start ok\n");
		property_set("vold.realdata.mount", "ok");
	}else{
	ALOGD("storageproxyd_start is ready:%s\n",is_ok);
	}
	return 0;
}

/*
* @device_id:output,to get device id value
* @out_size:output,to get device id length
*/
int get_device_id(uint8_t * device_id, uint32_t * out_size){
	ALOGD("Enter %s, \n", __func__);
	if (NULL == device_id){
        ALOGD("%s()->Line:%d; device id is NULL \n", __FUNCTION__, __LINE__);
		*out_size = 0;
        return PROD_ERROR_GET_DEVICE_ID;
    }

	property_get("ro.boot.serialno", (char *)device_id, "0");
	*out_size = strlen((char *)device_id);
	ALOGD("%s()->Line:%d; device_id = %s *out_size =%d \n", __FUNCTION__, __LINE__, (char *)device_id,*out_size);
	return PROD_OK;
}

uint32_t TEECex_SendMsg_To_TEE(uint8_t* msg, uint32_t msg_len, uint8_t* rsp, uint32_t* rsp_len){
    int result = PROD_OK;
    ALOGD("%s production enter\n", __func__);
    result = trusty_production_connect();
    if(result!=0){
        ALOGD("production trusty_production_connect failed with ret = %d", result);
        return PROD_ERROR_UNKNOW;
    }
    /*parse msg, get command_data */
    command_header commandHeader;
    uint8_t* command_data = NULL ;

    uint32_t data_len = 0;

    sec_memcpy_invert(&commandHeader.length,msg,sizeof(uint32_t));
    sec_memcpy_invert(&commandHeader.id,msg+sizeof(uint32_t),sizeof(uint16_t));
    sec_memcpy_invert(&commandHeader.flag,msg+sizeof(uint32_t)+sizeof(uint16_t),sizeof(uint8_t));
    sec_memcpy_invert(&commandHeader.uuid,msg+sizeof(uint32_t)+sizeof(uint16_t)+sizeof(uint8_t),sizeof(uuid_t));
    sec_memcpy_invert(&commandHeader.command_id,msg+sizeof(uint32_t)+sizeof(uint16_t)+sizeof(uint8_t)+sizeof(uuid_t),sizeof(uint32_t));
    ALOGD("commandHeader.length is %x, commandHeader.id is %x, commandHeader.flag is %x, commandHeader.command_id is %x \n",
    commandHeader.length, commandHeader.id, commandHeader.flag, commandHeader.command_id);

    data_len = commandHeader.length-25;
    ALOGD("production CA get commandData len is %d, data is ", data_len);
    if(data_len>0){
        // has command_data
        command_data =(uint8_t*)(msg + 27);
    }
    /*typedef struct _production_message {
      uint32_t cmd;
      int msg_code;
      uint8_t payload[0];
    }production_message;
    because of out_data_size = 64 , payload need 64 Bytes ,struct _production_message need 72 Bytes*/
    uint8_t out[72] = {0};
    uint32_t out_data_size = 64;
    production_message *return_msg;
    ALOGD("production CA parse_msg, then start switch, commandHeader.id is %x\n", commandHeader.id);
    switch(commandHeader.id){
    case CMD_SYSTEM_INIT:// system init
        ALOGD("production CA command_system_init\n");
        ALOGD("production CA begin to write secure \n");
        if(!production_efuse_secure_is_enabled())
            production_efuse_secure_enable();
        ALOGD("production CA has write secure \n");
        result = trusty_production_call(PRODUCTION_SYSTEM_INIT, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out; //return_msg initialize
        if(result == PROD_OK){
            ALOGD("production CA command_system_init, start rpmb_program_key!\n");
            // get RPMB key, then write RPMB to EMMC driver
            result = rpmb_program_key(return_msg->payload, out_data_size); // payload need 64 Bytes
            ALOGD("rpmb result:%d\n",result);
            if(result == 0){
                result = storageproxyd_start();
            }
            if(result == 0){
                ALOGD("production CA rpmb_program_key, success!\n");
                organize_rsp(commandHeader.id, PROD_OK, NULL, &out_data_size, rsp, rsp_len);
            }else{
                ALOGD("production CA rpmb_program_key error, result is %x !\n", result);
                organize_rsp(commandHeader.id, PROD_ERROR_WR_RPMB, NULL, &out_data_size, rsp, rsp_len);
            }
        }
        else{
            ALOGD("production CA command_system_init, error!\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
            if(result == PROD_ERROR_LCS_SECURE)
                result = 0;
        }
        break;
    case CMD_GET_UID:// get uid
        ALOGD("production CA command_get_uid\n");
        result = efuse_uid_read(out, &out_data_size);
        if(result == PROD_OK){
            ALOGD("production CA getUID success !\n");
            organize_rsp(commandHeader.id, result, out, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA getUID failed !\n");
            organize_rsp(commandHeader.id, result, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_SET_RTC:// set RTC
        ALOGD("production CA command_set_rtc\n");
        break;
    case CMD_SET_ROTPK:
        ALOGD("production CA command_set_rotpk\n");
        result = trusty_production_call(PRODUCTION_SET_ROTPK, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        if(result == PROD_ERROR_LCS_SECURE)
            result = 0;
        break;
    case CMD_GET_ROTPK:
        ALOGD("production CA command_get_rotpk\n");
        result = trusty_production_call(PRODUCTION_GET_ROTPK, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            organize_rsp(commandHeader.id, return_msg->msg_code, return_msg->payload, &out_data_size, rsp, rsp_len);
        }else{
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_SYSTEM_CLOSE:// system close
        ALOGD("production CA command_system_close\n");
        result = trusty_production_call(PRODUCTION_SYSTEM_CLOSE, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        break;
    case CMD_CHECK_SECURE:// get lcs
        ALOGD("production CA command_check_secure\n");
        result = trusty_production_call(PRODUCTION_CHECK_SECURE, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
		int sec_enable = 0;
		out_data_size = 0;
		if(production_efuse_secure_is_enabled() && return_msg->payload[0])
			sec_enable = 1;
        organize_rsp(commandHeader.id, sec_enable, NULL, &out_data_size, rsp, rsp_len);
        //organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        break;
	case CMD_GET_DEVICE_ID://get device id
        ALOGD("production CA command_get_device_id\n");
        result = get_device_id(out, &out_data_size);
        if(result == PROD_OK){
            ALOGD("production CA get device id success !\n");
            organize_rsp(commandHeader.id, result, out, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA get device id failed !\n");
            organize_rsp(commandHeader.id, result, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
	case CMD_SEND_KEYBOX://send keybox
        ALOGD("production CA command_send_keybox,data_len=%d\n",data_len);
		uint32_t trans_len = MAX_TRANS_SIZE;
		//memset(return_msg,0,sizeof(production_message));
		while(data_len){
			if(trans_len > data_len)
				trans_len = data_len;
			ALOGD("command_send_keybox,trans_len=%d\n",trans_len);
			//memset(out,0,sizeof(out));
			out_data_size = sizeof(production_message);
			result = trusty_production_call(PRODUCTION_SEND_KEYBOX, command_data, trans_len, out, &out_data_size);
			//result = trusty_production_call(PRODUCTION_SEND_KEYBOX, trans_data, trans_len, out, &out_data_size);
			data_len -= trans_len;
			command_data += trans_len;
			return_msg = (production_message*) out;
			if(result < 0){
				organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
				break;
			}
		}
        //result = trusty_production_call(PRODUCTION_SEND_KEYBOX, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            ALOGD("production CA send keybox success !\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, return_msg->payload, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA send keybox fail !\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    default:
        ALOGD("command is not supported\n");
        result = PROD_ERROR_UNKNOW;
        break;
    }
    trusty_production_disconnect();
    return result;
}
