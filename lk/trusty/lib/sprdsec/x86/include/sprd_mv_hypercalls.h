#ifndef _SPRD_MV_HYPERCALLS_H
#define _SPRD_MV_HYPERCALLS_H

//#include "sprd_typedef.h"

/*NOTE: this hirq_info stuff must be consistent with guest_vm.h */
struct hirq_info_t {
	uint32_t host_pending_flag;
	uint32_t lvl1;
	uint32_t lvl2[16];
};

struct vcpu_stolen_cpu_time_stats {
	/*
	 * accumulated counter for cpu time taken away from vcpu
	 * while it was active (preempted)
	 */
	volatile uint64_t active_stolen_cpu_count;

	/*
	 * accumulated counter for cpu time taken away from vcpu
	 * while it was idle
	 */
	volatile uint64_t idle_stolen_cpu_count;

	/* period for stolen cpu time counters in nsec */
	uint32_t stolen_cpu_counter_period_nsec;

};

/**
 * @brief Shared data between the MobileVisor and the guest
 *
 * This data structure defines the shared data between
 * the MobileVisor and the guest.
 */
struct vmm_shared_data {
	/** @brief Guest OS ID
	 *
	 * Each guest has a unique ID. This is used for various
	 * IPC APIs such as xirq posting.
	 * For SMP guests, each VCPU will have the same OS ID.
	 */
	const uint32_t os_id;

	/** @brief Shared memory start address
	 *
	 * This field contains the physical start address for
	 * the shared memory region.
	 * The guest is expected to map in the shared memory
	 * region into its virtual address space.
	 */
	const uint64_t ivmc_shmem_paddr;

	/** @brief Shared memory size
	 *
	 * This field contains the size of the shared memory region.
	 * The guest is expected to map in the shared memory region
	 * into its virtual address space.
	 */
	const uint64_t ivmc_shmem_size;

	/** @brief Secured shared memory start address
	 *
	 * This field contains the physical start address for
	 * the secured shared memory region.
	 * The guest is expected to map in the secured shared memory
	 * region into its virtual address space.
	 */
	const uint64_t ivmc_sec_shmem_paddr;

	/** @brief Secured shared memory size
	 *
	 * This field contains the size of the secured shared memory 
	 * region.
	 * The guest is expected to map in the secured shared memory
	 * region into its virtual address space.
	 */
	const uint64_t ivmc_sec_shmem_size;


	/** @brief OS command line for the guest
	 *
	 * Each guest will have a command line. Apart from the usual
	 * parameters (e.g. in the case of Linux), it also contains
	  * the virtual device information
	 */
	const int8_t vm_cmdline[512];

	/** @brief hirq info exchanged between guest and host
	 *
	 **/
	struct hirq_info_t hirq_info;

	/** @brief PM control shared data
	 *
	 */
	/*pm_control_shared_data_t pm_control_shared_data; */

	/** @brief System idle flag
	 *
	 * Only used by VCPU who is the power manager owner for a physical CPU
	 * If set, indicates that system is idle,
	 * i.e. no pending tasks or interrupts
	 */
	volatile uint32_t system_idle;

	/** @brief Platform reboot initiation status
	 *
	 * Indicates if a platform reboot has been initiated.
	 * If >0, platform reboot has been initiated,
	 * guests should perform reboot housecleaning accordingly.
	 * and finally invoke VMCALL_STOP_VCPU for each vcpu.
	 */
	const volatile uint32_t is_platform_reboot_initiated;

	/** @brief VCPU stolen cpu time stats
	 *
	 * This gives stats of cpu time stolen from vcpu
	 * while it was active/idle.
	 */
	struct vcpu_stolen_cpu_time_stats stolen_cpu_time_stats;

	/** @brief Shared data for pal
	 *
	 * This is used internally for PAL shared data
	 */
	uint32_t pal_shared_mem_data[256];
};

#endif
