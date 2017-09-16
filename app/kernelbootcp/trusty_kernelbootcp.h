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

#ifndef TRUSTY_KERNELBOOTCP_H_
#define TRUSTY_KERNELBOOTCP_H_

#include <trusty_std.h>
#include <stdio.h>

#define LOG_TAG "trusty_kernelbootcp"
#define TLOGE(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)

//Add for open debug
#define LOCAL_TRACE 1


#if LOCAL_TRACE
#define TLOGI(fmt, ...) \
    fprintf(stdout, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)
#else
#define TLOGI(fmt, ...)
#endif

namespace kernelbootcp {

#define HASH_BYTE_LEN    32

typedef struct{
    uint64_t img_addr;     // the base address of image to verify
    uint32_t img_len;      // length of image
    uint8_t  pubkhash[HASH_BYTE_LEN]; // pubkey hash for verifying image
    uint32_t flag;         // sprd or sanda plan
}kbcImgInfo;

typedef struct {
    uint64_t img_addr;  // the base address of image to verify
    uint32_t img_len;   // length of image
    uint32_t map_len;   // mapping length
} KBC_IMAGE_S;

typedef struct {
  KBC_IMAGE_S modem;
  KBC_IMAGE_S ldsp;
  KBC_IMAGE_S tgdsp;
  KBC_IMAGE_S pm_sys;
  uint16_t    flag;      // sprd or sanda plan
  uint16_t    is_packed; // is packed image
  uint8_t     cntcert[1024];
} KBC_LOAD_TABLE_S;

//class TrustyKernelBootCp : public KernelBootCp {
class TrustyKernelBootCp {
public:
    TrustyKernelBootCp();

    long OpenSession();
    void CloseSession();
    long kbc_unlock_ddr();
    long kbc_verify_all(uint8_t *in_buf, uint32_t in_size);

protected:

private:
    void hexdump(const char *title, const unsigned char *s, int l);
    void dump_table(KBC_LOAD_TABLE_S  *table);

};

}

#endif // TRUSTY_KERNELBOOTCP_H_
