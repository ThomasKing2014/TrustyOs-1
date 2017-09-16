/*
 * Copyright (c) 2016 spreadtrum, Inc.
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

#include <stdlib.h>
#include <stdio.h>
#include <arch/ops.h>
#include <platform.h>
#include <kernel/thread.h>
#include <kernel/vm.h>
#include <lib/sm.h>
#include <lib/sm/smcall.h>
#include <lk/init.h>
#include <lib/sm/sm_err.h>
#include <debug.h>
#include <err.h>
#include <pow2.h>
#include <list.h>
#include <string.h>
#include "sprdsec.h"
#ifdef CONFIG_SPRD_SECBOOT
#include "sprdsecureboot.h"
#ifdef CONFIG_VBOOT_V2
#include "tos_avb_pub.h"
#endif
#endif
#ifdef CONFIG_SPRD_FIREWALL
#include "sprd_firewall.h"
#endif

ns_data_t s_ns_key[SEC_MAX];

#define HASH_LEN 32

static void save_ns_data(cmd_info id, void *vaddr, uint32_t len)
{
	uint32_t i;
	uint8_t *ptr = (uint8_t *)vaddr;
	if (SEC_HW_KEY == id) {
		dprintf(SPEW,"hwkey hash from uboot is:\n");
		for (i = 0; i < HASH_LEN; i++) {
			dprintf(SPEW,"%02x",ptr[i]);
		}
		dprintf(SPEW,"\n");
	} else if (SEC_PUBLIC_KEY == id) {
		dprintf(SPEW,"public key from uboot is:\n");
		for (i = 0; i < len; i++) {
			dprintf(SPEW,"%02x",ptr[i]);
		}
		dprintf(SPEW,"\n");
	}
	memcpy(s_ns_key[id].val, vaddr, len);
	s_ns_key[id].len = len;
	dprintf(SPEW,"data has been saved!\n");
}

static long process_ns_call(smc32_args_t *args, cmd_info id)
{
	status_t ret;
	uint32_t ns_paddr;
	uint32_t ns_plen;
	void *vaddr = NULL;

	ns_paddr = args->params[0];
	ns_plen = args->params[1];
	dprintf(SPEW,"from uboot smc...addr:0x%x len:0x%x\n", ns_paddr,ns_plen);
	ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "sprdsec",
			 PAGE_SIZE, &vaddr, PAGE_SIZE_SHIFT, ns_paddr,
			 0,
			 ARCH_MMU_FLAG_NS | ARCH_MMU_FLAG_PERM_NO_EXECUTE |
			 ARCH_MMU_FLAG_CACHED);

	if (ret != NO_ERROR) {
		dprintf(SPEW,"can not map phy addr, ret:%d\n", ret);
		return ret;
	}

	save_ns_data(id, vaddr, ns_plen);
	ret = vmm_free_region(vmm_get_kernel_aspace(),(vaddr_t)vaddr);
	if (ret != NO_ERROR) {
		dprintf(SPEW,"can not unmap virt addr, ret:%d\n", ret);
		return ret;
	}
	return NO_ERROR;
}
static long process_sip_call(smc32_args_t *args)
{
	/* funcid(such as FUNCTYPE_VERIFY_IMG) is in args->params[0]
	 * should use switch(args->params[0]) style */
	long res;

	dprintf(SPEW," args->params[0] is 0x%x. ###\n", args->params[0]);

	switch (args->params[0]) {
#ifdef CONFIG_VBOOT_V2
	case FUNCTYPE_VBOOT_VERIFY_IMG:
		res = sprd_vboot_image_verify(args);
		break;
	case FUNCTYPE_VBOOT_SET_VERSION:
		res = sprd_vboot_set_version(args);
		break;
#endif

#ifdef CONFIG_SPRD_SECBOOT
	case FUNCTYPE_VERIFY_IMG:
		res = process_ns_image_verify(args);
		break;

	case FUNCTYPE_GET_HBK:
		res = process_ns_save_hbkey(args);
		break;
	/*add fastboot cmd for sharkl2*/
	case FUNCTYPE_GET_LCS:
		res = process_ns_get_lcs(args);
		break;
	case FUNCTYPE_GET_SOCID:
		res = process_ns_get_socid(args);
		break;
	case FUNCTYPE_SET_RMA:
		res = process_ns_set_rma(args);
		break;
#endif
#ifdef CONFIG_SPRD_FIREWALL
	case FUNCTYPE_SET_SECURE_RANGE_PARAM:
		res = sprd_get_memory_parameters(args);
		break;
#endif
	default:
		res = SM_ERR_UNDEFINED_SMC;
		break;
	}
	return res;
}

static long sprdsec_fastcall(smc32_args_t *args)
{
	long res = SM_ERR_UNDEFINED_SMC;
	switch (args->smc_nr) {
	case SMC_SC_SIP_INFO:
		dprintf(SPEW,"have got sip smc all from uboot###\n");
		res = process_sip_call(args);
		break;

	default:
		res = SM_ERR_UNDEFINED_SMC;
		break;
	}
	return res;
}

static long sprdsec_stdcall(smc32_args_t *args)
{
	long res;
	switch (args->smc_nr) {
	case SMC_SC_PUBKEY_INFO:
		res = process_ns_call(args, SEC_PUBLIC_KEY);
		break;

	case SMC_SC_HWKEY_INFO:
		res = process_ns_call(args, SEC_HW_KEY);
		break;

	default:
		res = SM_ERR_UNDEFINED_SMC;
		break;
	}
	return res;
}

static smc32_entity_t sprdsec_sm_entity = {
	.stdcall_handler = sprdsec_stdcall,
};

static smc32_entity_t sprdsec_sip_entity = {
        .fastcall_handler = sprdsec_fastcall,
};

static void sprdsec_init(uint level)
{
	int err;

	err = sm_register_entity(SMC_ENTITY_SPRDSEC, &sprdsec_sm_entity);
	if (err) {
		printf("trusty error register entity: %d\n", SMC_ENTITY_SPRDSEC);
	}
        err = sm_register_entity(SMC_ENTITY_SIP, &sprdsec_sip_entity);
        if (err) {
                printf("trusty error register entity: %d\n", SMC_ENTITY_SIP);
        }

}
LK_INIT_HOOK(sprdsec, sprdsec_init, LK_INIT_LEVEL_APPS);

