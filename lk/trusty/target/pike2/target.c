#include <debug.h>
#include <arch/arm.h>
#include <platform.h>
#include <trace.h>
#include <assert.h>
#include <list.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <kernel/vm.h>

#define MT_PERM_SHIFT	3
#define MT_SEC_SHIFT	4
#define MT_EXECUTE_SHIFT	5

extern ulong lk_boot_args[4];
extern uint32_t arm_kernel_translation_table[];

typedef enum  {
	/*
	 * Memory types supported.
	 * These are organised so that, going down the list, the memory types
	 * are getting weaker; conversely going up the list the memory types are
	 * getting stronger.
	 */
	MT_DEVICE,
	MT_NON_CACHEABLE,
	MT_MEMORY,
	/* Values up to 7 are reserved to add new memory types in the future */

	MT_RO		= 0 << MT_PERM_SHIFT,
	MT_RW		= 1 << MT_PERM_SHIFT,

	MT_SECURE	= 0 << MT_SEC_SHIFT,
	MT_NS		= 1 << MT_SEC_SHIFT,

	/*
	 * Access permissions for instruction execution are only relevant for
	 * normal read-only memory, i.e. MT_MEMORY | MT_RO. They are ignored
	 * (and potentially overridden) otherwise:
	 *  - Device memory is always marked as execute-never.
	 *  - Read-write normal memory is always marked as execute-never.
	 */
	MT_EXECUTE		= 0 << MT_EXECUTE_SHIFT,
	MT_EXECUTE_NEVER	= 1 << MT_EXECUTE_SHIFT,
} mmap_attr_t;

typedef struct mmap_region {
	unsigned long long	base_pa;
	unsigned int		base_va;
	unsigned int		size;
	mmap_attr_t		attr;
} mmap_region_t;

typedef struct trusty_sp_args {
        /*'spag'*/
        unsigned int magic;
        /*input*/
        mmap_region_t *mmap;
        /*ouput*/
        unsigned int phy_pgd;
} trusty_sp_args_t;

trusty_sp_args_t *atf_args;


#define APB_EB0		0x402e0000
#define TS_CFG		0x402e0028
#define SYS_FRT_VALUE	0x40400000

#define CA7_TS1_EB	(1 << 29)
#define CA7_TS0_EB	(1 << 28)

#define CSYSREQ_TS_LP_0	(1 << 8)
#define CSYSREQ_TS_LP_1	(1 << 10)
#define CSYSREQ_TS_LP_2	(1 << 12)


void target_early_init(void)
{
	*(volatile unsigned int*)APB_EB0 |= (CA7_TS1_EB | CA7_TS0_EB);
	*(volatile unsigned int*)TS_CFG |= CSYSREQ_TS_LP_0 | CSYSREQ_TS_LP_1 | CSYSREQ_TS_LP_2;
	*(volatile unsigned int*)SYS_FRT_VALUE = 1;
}

void target_init(void)
{
	int err;

	atf_args = (trusty_sp_args_t*)lk_boot_args[0];

	uint32_t offset = ((unsigned int)atf_args) & (PAGE_SIZE - 1);

	uint32_t paddr = ROUNDDOWN(((uint32_t)atf_args), PAGE_SIZE);

	/*enought of pagesize FIXME*/
	size_t size   = PAGE_SIZE;

	void  *vptr_base;

	trusty_sp_args_t  *vargs = NULL;

	dprintf(INFO,"lk_boot_args[0] = 0x%lx\n", lk_boot_args[0]);
	/*map*/

	err = vmm_alloc_physical(vmm_get_kernel_aspace(), "atfargs",
				 size, &vptr_base, PAGE_SIZE_SHIFT, paddr,
				 0,
				ARCH_MMU_FLAG_PERM_NO_EXECUTE | ARCH_MMU_FLAG_CACHED);
		if (!err) {
			vargs = (trusty_sp_args_t *)(vptr_base + offset);
		} else {
			TRACEF("Error mapping atf boot args: %d\n", err);
			asm("b .");
		}


	ASSERT(vargs->magic == 'sprg');


	uint32_t mmapoffset =  (unsigned int)(vargs->mmap) & (PAGE_SIZE - 1);
	uint32_t mmappaddr = ROUNDDOWN(((unsigned int)vargs->mmap), PAGE_SIZE);
	void*    atfvmap_base;
	mmap_region_t* vmatf = NULL;
	mmap_region_t* m;

	err = vmm_alloc_physical(vmm_get_kernel_aspace(), "atfmmap",
				 size, &atfvmap_base, PAGE_SIZE_SHIFT, (uint32_t)mmappaddr,
				 0,
				ARCH_MMU_FLAG_PERM_NO_EXECUTE | ARCH_MMU_FLAG_CACHED);
	if (!err) {
		vmatf= (mmap_region_t*)(atfvmap_base + mmapoffset);
	} else {
		TRACEF("Error mapping atf mmap args: %d\n", err);
		asm("b .");
	}


	m = vmatf;
	for(m = vmatf; m->size != 0; m ++) {
		uint32_t pa =  m->base_pa;
		void *va = (void*)pa;
		uint32_t sz = m->size;
		uint32_t flags = 0;

		switch ((uint32_t)m->attr) {
			case 0x2:
				flags = ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_RO;
				break;
			case 0x8:
				flags = ARCH_MMU_FLAG_PERM_NO_EXECUTE | ARCH_MMU_FLAG_UNCACHED;
				break;
			case 0xa:
				flags = ARCH_MMU_FLAG_CACHED;
				break;
			default:
				ASSERT(!"NOT SUPPORT ATTR\n");


		}

		ASSERT(IS_PAGE_ALIGNED(pa));
		ASSERT(IS_PAGE_ALIGNED(sz));

		TRACEF("va = 0x%x , pa =0x%x\n",(uint32_t)va,pa);

		if((pa + sz) < 0x80000000) {
			err = arch_mmu_map((uint32_t)va, pa, sz / PAGE_SIZE, flags);
			TRACEF("arch_mmu_map returns %d\n", err);
			ASSERT(err >= 0);
			continue;
		}


		err = vmm_alloc_physical(vmm_get_kernel_aspace(), "atfzone",
					 sz, &va, PAGE_SIZE_SHIFT, pa,
					 VMM_FLAG_VALLOC_SPECIFIC, flags);
		if (err) {
			TRACEF("Error mapping mmap zone: %d, 0x%x\n",err, (uint32_t)m->base_pa);
			//asm("b .");
		}
	}


	TRACEF("trusty map ATF ok\n");

	vargs->phy_pgd = (uint32_t)arm_kernel_translation_table;
}
