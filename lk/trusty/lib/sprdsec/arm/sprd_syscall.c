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
#include <lib/trusty/sys_fd.h>
#include "sprdsec.h"

#define SEC_BYTES_LEN 32

static uint32_t sec_mem_pos = 0;

static int32_t get_secmem_rng(void)
{
	status_t ret;
	void *vaddr = NULL;
	uint32_t sec_paddr = MEMBASE+MEMSIZE-PAGE_SIZE;
	ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "sprdrng",
			 PAGE_SIZE, &vaddr, PAGE_SIZE_SHIFT, sec_paddr,
			 0, ARCH_MMU_FLAG_PERM_NO_EXECUTE |
			 ARCH_MMU_FLAG_CACHED);

	if (ret != NO_ERROR) {
		dprintf(SPEW,"can not map sec addr, ret:%d\n", ret);
		return ERR_GENERIC;
	}

	memcpy(s_ns_key[SEC_RNG].val, vaddr, PAGE_SIZE);
	s_ns_key[SEC_RNG].len = PAGE_SIZE;
	ret = vmm_free_region(vmm_get_kernel_aspace(),(vaddr_t)vaddr);
	if (ret != NO_ERROR) {
		dprintf(SPEW,"can not unmap virt addr, ret:%d\n", ret);
		return ERR_GENERIC;
	}
	return NO_ERROR;
}

static int32_t sys_std_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr)
{
	int32_t res;
	void *secptr;
	int i;
	uint8_t fake_pubkey[264];

	if (!user_ptr) {
		return ERR_INVALID_ARGS;
	}
	switch(cmd) {
		case SEC_PUBLIC_KEY:
			if (s_ns_key[SEC_PUBLIC_KEY].len) {
				copy_to_user(user_ptr, s_ns_key[SEC_PUBLIC_KEY].val, s_ns_key[SEC_PUBLIC_KEY].len);
				res = s_ns_key[SEC_PUBLIC_KEY].len;
			} else {
				dprintf(SPEW,"there is no public key yet, give you fake data\n");
				memset(fake_pubkey,0xFF,264);
				copy_to_user(user_ptr, fake_pubkey, 264);
				res = 264;
			}
			break;

		case SEC_HW_KEY:
			if (s_ns_key[SEC_HW_KEY].len) {
				copy_to_user(user_ptr, s_ns_key[SEC_HW_KEY].val, s_ns_key[SEC_HW_KEY].len);
				res = s_ns_key[SEC_HW_KEY].len;
			} else {
				res = -1;
			}
			break;

		case SEC_RNG:
			if (!s_ns_key[SEC_RNG].len) {
				if (get_secmem_rng()) {
					return ERR_GENERIC;
				}
			}
			if (sec_mem_pos*SEC_BYTES_LEN <= PAGE_SIZE-SEC_BYTES_LEN) {
				secptr = s_ns_key[SEC_RNG].val+sec_mem_pos*SEC_BYTES_LEN;
				sec_mem_pos++;
			} else {
				secptr = s_ns_key[SEC_RNG].val;
				sec_mem_pos = 1;
			}
			dprintf(SPEW,"RNG  from kernel is:\n");
			for (i = 0; i < SEC_BYTES_LEN; i++) {
				dprintf(SPEW,"%02x",((uint8_t*)secptr)[i]);
			}
			dprintf(SPEW,"\n");
			copy_to_user(user_ptr, secptr, SEC_BYTES_LEN);
			res = SEC_BYTES_LEN;
			break;

		default:
			res = ERR_NOT_SUPPORTED;
			break;
	}
	return res;
}


static const struct sys_fd_ops sys_std_in_op = {
	.ioctl = sys_std_ioctl,
};


static void sprdioctl_init(uint level)
{
	status_t  err;
	err = install_sys_fd_handler(0, &sys_std_in_op);
	if (err) {
		dprintf(SPEW,"can not install std in handler: %d\n", err);
	}
}
LK_INIT_HOOK(sprd_ioctl, sprdioctl_init, LK_INIT_LEVEL_APPS);
