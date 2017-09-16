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

#pragma once

#ifndef TRUSTY_PRODUCTION_H_
#define TRUSTY_PRODUCTION_H_

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <UniquePtr.h>

typedef enum enWrEfuseOp{
  WR_EFUSE_HUK,
  WR_EFUSE_KCE,
  WR_EFUSE_ROTPK,
  RD_EFUSE_ROTPK,
  RD_EFUSE_LCS,
  WR_EFUSE_BUTT
} wr_efuse_op;

namespace production{
class TrustyProduction{
    public:
        TrustyProduction();
        long SystemInit(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size);
        long SystemClose(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size);
        long SetROTPK(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size);
        long GetROTPK(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size);
        long SetRTC(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size);
        long CheckSecureEnable(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size);
		long SendKeybox(production_message* msg, uint32_t data_len, uint8_t* out, uint32_t* out_size);
};
}
#endif
