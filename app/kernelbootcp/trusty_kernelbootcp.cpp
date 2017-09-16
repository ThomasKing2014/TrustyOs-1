/*
 * Copyright 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#include <openssl/hmac.h>
#include <err.h>

extern "C" {
#include <trusty_std.h>
}

#include "io_device_def.h"
#include <kernel/thread.h>
#include "sprd_pal_kbcverify.h"
#include "trusty_kernelbootcp.h"
#include "sprd_pal_firewall.h"

namespace kernelbootcp {

//TrustyKernelBootCp::TrustyKernelBootCp() : KernelBootCp() {
TrustyKernelBootCp::TrustyKernelBootCp() {
}

long TrustyKernelBootCp::OpenSession() {
    TLOGI("OpenSession() \n");
    return 0;
}

void TrustyKernelBootCp::CloseSession() {
    TLOGI("CloseSession() \n");
}

void TrustyKernelBootCp::hexdump(const char *title, const unsigned char *s, int l)
{
    int n=0;

    printf("%s",title);
    for( ; n < l ; ++n)
    {
        if((n%16) == 0)
            printf("\n%04x",n);
        printf(" %02x",s[n]);
    }
    printf("\n");
}

long TrustyKernelBootCp::kbc_verify_all(uint8_t *in_buf, uint32_t in_size)
{
    int result = 0;

    TLOGI("TA:kbc_verify_all() \n");
    dump_table((KBC_LOAD_TABLE_S *)in_buf);
    result = ioctl(IO_DEVICE_FIREWALL, SEC_FIREWALL_LOCK_CP_DRR, NULL);
    TLOGI("TA:SEC_FIREWALL_LOCK_CP_DRR() ret = %d\n", result);

    result = ioctl(IO_DEVICE_SBVERIFY, SEC_KBC_VERIFY_ALL, in_buf);
    TLOGI("TA:kbc_verify_all() ret = %d\n", result);

    result = ioctl(IO_DEVICE_SBVERIFY, SEC_KBC_START_CP, NULL);
    TLOGI("TA:SEC_KBC_START_CP() ret = %d\n", result);

    result = ioctl(IO_DEVICE_FIREWALL, SEC_PREPARE_FIREWALL_DATA, NULL);
    TLOGI("TA:SEC_PREPARE_FIREWALL_DATA() ret = %d\n", result);
    return result;
}

void TrustyKernelBootCp::dump_table(KBC_LOAD_TABLE_S  *table)
{
    int           i = 0;
    KBC_IMAGE_S  *tmp_table = &(table->modem);

    for (i = 0; i < 4; i ++) {
        TLOGI("dump_table() len = %x maplen = %x addr = %llx \n",
              tmp_table->img_len, tmp_table->map_len, tmp_table->img_addr);
        tmp_table ++;
    }
    TLOGI("dump_table() flag = %d \n", table->flag);
    TLOGI("dump_table() is_packed = %d \n", table->is_packed);
}

long TrustyKernelBootCp::kbc_unlock_ddr()
{
    int result = 0;

    TLOGI("TA:kbc_unlock_ddr() \n");
    result = ioctl(IO_DEVICE_SBVERIFY, SEC_KBC_STOP_CP, NULL);
    TLOGI("TA:SEC_KBC_STOP_CP() ret = %d\n", result);

    result = ioctl(IO_DEVICE_FIREWALL, SEC_FIREWALL_UNLOCK_CP_DDR, NULL);
    TLOGI("TA:SEC_FIREWALL_UNLOCK_CP_DDR() ret = %d\n", result);
    return result;
}

}
