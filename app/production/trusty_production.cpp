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

extern "C" {
#include <trusty_std.h>
#include "crc16.h"
#include <stdio.h>
}
#include <io_device_def.h>

#include "ipc/production_ipc.h"
#include "trusty_production.h"
#include <lib/hwkey/hwkey.h>
#include <sec_efuse_api.h>
#include "keybox_tools.h"

namespace production{
#define KEYBOX_HASH_LENGTH 2
#define MAX_TRANS_SIZE 4024  //for keybox CA transfort to TA
uint8_t keybox_sum[20*1024];
static uint32_t keybox_count = 0;


static int sec_memcmp(const uint8_t *cs, const uint8_t *st, unsigned int count)
{
	const uint8_t *su1, *su2;
	int res = 0;
	for (su1 = cs, su2 = st; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
	return res;
}

static int get_rpmb_auth_key(uint8_t *key, uint32_t key_size)
{
    int rc = hwkey_open();
    if (rc < 0) {
        LOG_I("%s: hwkey init failed: %d\n", __FUNCTION__, rc);
        return PROD_ERROR_GET_RPMB;
    }
    hwkey_session_t hwkey_session = (hwkey_session_t) rc;
    const char *storage_auth_key_id = "com.android.trusty.storage_auth.rpmb";
    rc = hwkey_get_keyslot_data(hwkey_session, storage_auth_key_id, key, &key_size);
    hwkey_close(hwkey_session);
    if (rc < 0) {
        LOG_I("%s: failed to get key: %d\n", __FUNCTION__, rc);
        return PROD_ERROR_GET_RPMB;
    }
    return PROD_OK;
}

TrustyProduction::TrustyProduction() {
}

long TrustyProduction::SystemInit(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size){
    LOG_I("Enter %s \n", __FUNCTION__);
    int result = PROD_OK;
    unsigned * pLcs = NULL ;
    pLcs = (unsigned *)malloc(sizeof(pLcs));
    if(pLcs == NULL)
    {
    	LOG_I("%s pLcs malloc error \n", __FUNCTION__);
        return PROD_ERROR_UNKNOW ;
    }
    // check lcs status
    result = ioctl(IO_DEVICE_EFUSE, RD_EFUSE_LCS, pLcs);
    LOG_I("%s ioctl IO_DEVICE_EFUSE, result is %d, pLcs is %x\n", __FUNCTION__, result, *pLcs);
    if(result != PROD_OK){
		free(pLcs) ;
        return PROD_ERROR_GET_LCS;
    }else{
        if(*pLcs == SECURE_LCS){
            // ROTPK has been programed, do not program again
            LOG_I("%s pLcs is SECURE_LCS, return PROD_ERROR_LCS_SECURE\n", __FUNCTION__);
            //return PROD_OK;
        }else if(*pLcs == CHIP_MANUFACTURE_LCS){
            LOG_I("%s pLcs is CHIP_MANUFACTURE_LCS, return PROD_ERROR_NOT_WR_HUK\n", __FUNCTION__);
            free(pLcs) ;
            return PROD_ERROR_NOT_WR_HUK;
            /*// HUK is not programmed, program and lock it.
            result = ioctl(IO_DEVICE_EFUSE, WR_EFUSE_HUK, NULL);
            if(result != PROD_OK)
                return PROD_ERROR_WR_HUK;*/
        }
    }

    // Program the KCE key and lock it (optional)
    if(msg->payload != NULL && data_len > 0){
        // has KCE key, program it
        LOG_I("%s start write efuse kce, data_len is %d, payload is %s \n", __FUNCTION__, data_len, msg->payload);
        result = ioctl(IO_DEVICE_EFUSE, WR_EFUSE_KCE, msg->payload);
        if(result != PROD_OK){
            LOG_I("%s write efuse kce error, result is %d\n", __FUNCTION__, result);
            free(pLcs) ;
            return PROD_ERROR_WR_KCE;
        }
        LOG_I("%s write efuse kce sucess \n", __FUNCTION__);
    }
    LOG_I("%s Derive the RPMB key\n", __FUNCTION__);
    // Derive the RPMB key form HUK, return the RPMB key to CA
    uint8_t payload[RPMB_KEY_LEN];
    result = get_rpmb_auth_key(payload, RPMB_KEY_LEN);
    if(result != PROD_OK){
	free(pLcs) ;
        return result;
    }
    memcpy(out, payload, RPMB_KEY_LEN);
    *out_size = RPMB_KEY_LEN;
    /*LOG_I("%s start print RPMB key:\n", __FUNCTION__);
    int m = 0;
    for(m=0;m<RPMB_KEY_LEN;m++){
        LOG_I("%2x \n", payload[m]);
    }
    LOG_I("%s end print RPMB key:\n", __FUNCTION__);*/
    free(pLcs) ;
    return result;
}

long TrustyProduction::SystemClose(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size){
    int result = PROD_OK;
    return result;
}
long TrustyProduction::SetROTPK(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size){
    int result = PROD_OK;

    unsigned * pLcs = NULL ;
    pLcs = (unsigned *)malloc(sizeof(pLcs));
    if(pLcs == NULL)
    {
    	LOG_I("%s pLcs malloc error \n", __FUNCTION__);
        return PROD_ERROR_UNKNOW ;
    }
    // check lcs status
    result = ioctl(IO_DEVICE_EFUSE, RD_EFUSE_LCS, pLcs);
    LOG_I("%s ioctl IO_DEVICE_EFUSE, result is %d, pLcs is %x\n", __FUNCTION__, result, *pLcs);
    if(result != PROD_OK){
        free(pLcs);
        return PROD_ERROR_GET_LCS;
    }else{
        if(*pLcs == SECURE_LCS){
            // ROTPK has been programed, do not program again
            LOG_I("%s pLcs is SECURE_LCS, return PROD_ERROR_LCS_SECURE\n", __FUNCTION__);
            //return PROD_OK;
        }else if(*pLcs == CHIP_MANUFACTURE_LCS){
            LOG_I("%s pLcs is CHIP_MANUFACTURE_LCS, return PROD_ERROR_NOT_WR_HUK\n", __FUNCTION__);
	    free(pLcs);
            return PROD_ERROR_NOT_WR_HUK;
        }
    }

    // program the public key hash(ROTPK) and lock it
    uint8_t iodata[2] = {0x0, 0x0};
    result = ioctl(IO_DEVICE_EFUSE, WR_EFUSE_ROTPK, iodata);
    if(result != PROD_OK){
        LOG_E("%s write efuse rotpk Error, result is %x\n", __FUNCTION__, result);
	free(pLcs);
        return PROD_ERROR_WR_ROTPK;
    }
    free(pLcs);
    return result;
}
long TrustyProduction::GetROTPK(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size){
    int result = PROD_OK;
    uint8_t rotpk[EFUSE_ROTPK_KEY_LEN];
    // get the public key hash(ROTPK)
    result = ioctl(IO_DEVICE_EFUSE, RD_EFUSE_ROTPK, rotpk);
    if(result != PROD_OK){
        LOG_E("%s get efuse rotpk0 Error, result is %d\n", __FUNCTION__, result);
        return PROD_ERROR_GET_ROTPK;
    }
    memcpy(out, rotpk, EFUSE_ROTPK_KEY_LEN);
    *out_size = EFUSE_ROTPK_KEY_LEN;
    return result;
}

/*
 add for checkx tool, to check if the production has been finished
 */
long TrustyProduction::CheckSecureEnable(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size){
    int result = PROD_OK;
    unsigned * pLcs = NULL ;

    pLcs = (unsigned *)malloc(sizeof(pLcs));
    if(pLcs == NULL)
    {
        LOG_I("%s pLcs malloc error \n", __FUNCTION__);
	return -1 ; //wqc add 2017-7-18 error malloc  
    }
    // check lcs status
    result = ioctl(IO_DEVICE_EFUSE, RD_EFUSE_LCS, pLcs);
    LOG_I("%s ioctl IO_DEVICE_EFUSE, result is %d, pLcs is %x\n", __FUNCTION__, result, *pLcs);
    if(*pLcs != SECURE_LCS){
        // ROTPK has not been programed, production operation did not finish, return 0
        LOG_I("%s pLcs != SECURE_LCS return 0 \n", __FUNCTION__);
        out[0] = 0;
    }else{
        LOG_I("%s pLcs == SECURE_LCS return 1 \n", __FUNCTION__);
        out[0] = 1;
    }
    *out_size = 1;
    free(pLcs);
    return result;
}

long TrustyProduction::SetRTC(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size){
    int result = PROD_OK;
    return result;
}

long TrustyProduction::SendKeybox(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size){
    int result = PROD_OK;
	unsigned short temp_crc_value = 0;
	unsigned short *crc_value = 0;

	if(data_len == MAX_TRANS_SIZE){
		memcpy((uint8_t *)(keybox_sum + keybox_count * MAX_TRANS_SIZE),msg->payload,MAX_TRANS_SIZE);
		keybox_count++;
		LOG_I("func:%s,line:%d,keybox_count:%d\n", __FUNCTION__,__LINE__,keybox_count);
		return result;
	}else{
		memcpy((uint8_t *)(keybox_sum + keybox_count * MAX_TRANS_SIZE),msg->payload,data_len);
	}

	LOG_I("func:%s,line:%d,keybox_count:%d\n", __FUNCTION__,__LINE__,keybox_count);
	crc_value = (unsigned short*)(keybox_sum+keybox_count * MAX_TRANS_SIZE+data_len - KEYBOX_HASH_LENGTH);
	/*between this add cal keybox hash*/
	temp_crc_value = crc16(temp_crc_value, (unsigned char *)keybox_sum, (keybox_count * MAX_TRANS_SIZE+data_len - KEYBOX_HASH_LENGTH));
	LOG_I("%s keybox CRC by pass is %d, by cal is:%d\n", __FUNCTION__,*crc_value,temp_crc_value);
	/*between this add cal keybox hash*/
	if (*crc_value != temp_crc_value) {
		LOG_E("%s cmp keybox CRC value Error, result is %d\n", __FUNCTION__, PROD_ERROR_SEND_KEYB);
        return PROD_ERROR_SEND_KEYB;
	}
	using namespace keymaster;
	{
    KeyboxTools write_keybox(keybox_sum, (keybox_count * MAX_TRANS_SIZE+data_len - KEYBOX_HASH_LENGTH));
	printf("begin write keybox\n");
	//write_keybox.SaveKeyboxToRpmb();
	}
	using namespace production;
    return result;
}
}
