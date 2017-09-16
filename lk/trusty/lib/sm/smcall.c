/*
 * Copyright (c) 2013 Google Inc. All rights reserved
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

/* Reference:
 * ARM document DEN 0028A: SMC CALLING CONVENTION
 * version: 0.9.0
 */

#include <compiler.h>
#include <debug.h>
#include <err.h>
#include <trace.h>
#include <kernel/mutex.h>
#include <kernel/timer.h>
#include <lib/sm.h>
#include <lib/sm/smcall.h>
#include <lib/sm/sm_err.h>
#include <lk/init.h>
#include <string.h>
#include <arch/ops.h>
#if WITH_LIB_VERSION
#include <version.h>
#endif

#ifdef  WITH_LIB_SM_MONITOR
#include <arch/arm/mmu.h>
#include <platform/debug.h>
#endif

extern uint32_t __data_start;
extern uint32_t _end_of_ram;

void sleep_wakeup_set(void);
uint32_t secondary_jump_addr;
unsigned int hotin[4];

#define LOCAL_TRACE	1

static mutex_t smc_table_lock = MUTEX_INITIAL_VALUE(smc_table_lock);

/* Defined elsewhere */
long smc_fiq_exit(smc32_args_t *args);
long smc_fastcall_secure_monitor(smc32_args_t *args);

#define TRACE_SMC(msg, args)	do {			\
	u_int _i;					\
	LTRACEF("%s\n", msg);				\
	LTRACEF("SMC: 0x%x (%s entity %d function 0x%x)\n", \
			(args)->smc_nr,			\
			SMC_IS_FASTCALL(args->smc_nr) ? "Fastcall" : "Stdcall", \
			SMC_ENTITY(args->smc_nr), SMC_FUNCTION(args->smc_nr)); \
	for(_i = 0; _i < SMC_NUM_PARAMS; _i++)		\
		LTRACEF("param%d: 0x%x\n", _i, (args)->params[_i]); \
} while (0)

long smc_undefined(smc32_args_t *args)
{
	TRACE_SMC("Undefined monitor call!", args);
	return SM_ERR_UNDEFINED_SMC;
}

/* Restarts should never be dispatched like this */
static long smc_restart_stdcall(smc32_args_t *args)
{
	TRACE_SMC("Unexpected stdcall restart!", args);
	return SM_ERR_UNEXPECTED_RESTART;
}

/*
 * Switch to secure mode and return. This function does no work on its own,
 * but if an interrupt is pending, it will be handled, and can in turn trigger a
 * context switch that will perform other secure work.
 */
static long smc_nop_stdcall(smc32_args_t *args)
{
	return 0;
}

static smc32_handler_t sm_stdcall_function_table[] = {
	[SMC_FUNCTION(SMC_SC_RESTART_LAST)] = smc_restart_stdcall,
	[SMC_FUNCTION(SMC_SC_LOCKED_NOP)] = smc_nop_stdcall,
	[SMC_FUNCTION(SMC_SC_RESTART_FIQ)] = smc_restart_stdcall,
	[SMC_FUNCTION(SMC_SC_NOP)] = smc_undefined, /* reserve slot in table, not called */
};

static long smc_stdcall_secure_monitor(smc32_args_t *args)
{
	u_int function = SMC_FUNCTION(args->smc_nr);
	smc32_handler_t handler_fn = NULL;

	if (function < countof(sm_stdcall_function_table))
		handler_fn = sm_stdcall_function_table[function];

	if (!handler_fn)
		handler_fn = smc_undefined;

	return handler_fn(args);
}

long smc_fiq_exit(smc32_args_t *args)
{
	sm_intc_fiq_exit();
	return 1; /* 0: reeenter fiq handler, 1: return */
}

static long smc_fiq_enter(smc32_args_t *args)
{
	return sm_intc_fiq_enter();
}


extern int wakeup_flag;
extern void _arch_disable_ints(void);

void sleep_wakeup_set(void)
{
	wakeup_flag = 1;
}

#if WITH_LIB_SM_MONITOR
static long sm_smc_cpu_suspend(smc32_args_t *args)
{
//	lk_init_level_all(LK_INIT_FLAG_CPU_SUSPEND);
	sleep_wakeup_set();

	_arch_disable_ints();

	uint32_t sctlr = arm_read_sctlr();
	sctlr &= ~(1<<2); // dis dcache
	arm_write_sctlr(sctlr);

	__asm__ volatile("dsb");
	__asm__ volatile("isb");

	//arch_disable_cache(DCACHE);

	unsigned int size = ((uint32_t)&_end_of_ram) - ((uint32_t)&__data_start);
	arch_clean_invalidate_cache_range((addr_t) &__data_start, size);
	__asm__ volatile("dsb");
	__asm__ volatile("isb");

/*dis SMP*/
//	uint32_t actlr = arm_read_actlr();
//	actlr &= ~(1<<6);
//	arm_write_actlr(actlr);

	arm_after_invalidate_tlb_barrier();

	LTRACEF("entering[%s]-------\n",__func__);
	return 0;
}

static long sm_smc_cpu_resume(smc32_args_t *args)
{
//	lk_init_level_all(LK_INIT_FLAG_CPU_RESUME);

	LTRACEF("entering---------------------------[%s]\n",__func__);
	return 0;
}
#else /*no sm monitor on v8*/
static long smc_cpu_suspend(smc32_args_t *args)
{
	lk_init_level_all(LK_INIT_FLAG_CPU_SUSPEND);
	return 0;
}

static long smc_cpu_resume(smc32_args_t *args)
{
	lk_init_level_all(LK_INIT_FLAG_CPU_RESUME);
	return 0;
}
#endif

#ifdef WITH_HOTPLUG
static long smc_cpu_up(smc32_args_t *args)
{
	uint32_t hotplug_cpu_id;
	secondary_jump_addr = args->params[0];
	hotplug_cpu_id = args->params[1];
	LTRACEF("cpu_%d is gonna power on, jump_addr = 0x%x\n",hotplug_cpu_id,secondary_jump_addr);

	if  (1 == hotin[hotplug_cpu_id])
		hotin[hotplug_cpu_id] += 1;

	return 0;
}

#if 0
uint64_t read_cntpct(void);
uint64_t a_time;
uint64_t b_time;
int fg;
#define t_printf(flag) \
 { \
	fg = flag; \
	while(1) { \
		if(fg == 0){ \
			a_time = read_cntpct(); \
			break; \
		} \
		b_time = read_cntpct(); \
		LTRACEF("----TIME=%lld\n",b_time - a_time); \
		break; \
	} \
 }
#endif

static long smc_cpu_down(smc32_args_t *args)
{
	unsigned int size;

	uint32_t hotplug_cpu_id;

	hotplug_cpu_id = args->params[0];
	LTRACEF("entering[%s]:cpuid=%d,cpu is %d\n",__func__, hotplug_cpu_id, arch_curr_cpu_num());

	hotin[hotplug_cpu_id] = 1;

	_arch_disable_ints();

	uint32_t sctlr = arm_read_sctlr();
	sctlr &= ~(1<<2); // dis dcache
	arm_write_sctlr(sctlr);

	__asm__ volatile("dsb");
	__asm__ volatile("isb");

	size = ((uint32_t)&_end_of_ram) - ((uint32_t)&__data_start);
	arch_clean_invalidate_cache_range((addr_t) &__data_start, size);

	__asm__ volatile("dsb");
	__asm__ volatile("isb");

/*dis SMP*/
//	uint32_t actlr = arm_read_actlr();
//	actlr &= ~(1<<6);
//	arm_write_actlr(actlr);

	arm_after_invalidate_tlb_barrier();

	LTRACEF("cpu_%d is gonnaaaa power down\n",hotplug_cpu_id);

	return 0;
}
#endif

static long smc_cpu_can_down(smc32_args_t *args)
{
	uint32_t unplug_cpu_id = args->params[0];

	if (!timer_queue_is_empty(unplug_cpu_id)) {
		LTRACEF("this cpu has active timer, can not unplug!\n");
		return -1;
	}
	return 0;
}

#if WITH_LIB_VERSION
static long smc_get_version_str(smc32_args_t *args)
{
	int32_t index = args->params[0];
	size_t version_len = strlen(lk_version);

	if (index == -1)
		return version_len;

	if ((size_t)index >= version_len)
		return SM_ERR_INVALID_PARAMETERS;

	return lk_version[index];
}
#endif

smc32_handler_t sm_fastcall_function_table[] = {
	[SMC_FUNCTION(SMC_FC_REQUEST_FIQ)] = smc_intc_request_fiq,
	[SMC_FUNCTION(SMC_FC_FIQ_EXIT)] = smc_fiq_exit,
	[SMC_FUNCTION(SMC_FC_GET_NEXT_IRQ)] = smc_intc_get_next_irq,
	[SMC_FUNCTION(SMC_FC_FIQ_ENTER)] = smc_fiq_enter,
#if !WITH_LIB_SM_MONITOR
	[SMC_FUNCTION(SMC_FC_CPU_SUSPEND)] = smc_cpu_suspend,
	[SMC_FUNCTION(SMC_FC_CPU_RESUME)] = smc_cpu_resume,
#else
	[SMC_FUNCTION(SMC_FC_CPU_SUSPEND)] = sm_smc_cpu_suspend,
	[SMC_FUNCTION(SMC_FC_CPU_RESUME)] = sm_smc_cpu_resume,
#endif
#if WITH_LIB_VERSION
	[SMC_FUNCTION(SMC_FC_GET_VERSION_STR)] = smc_get_version_str,
#endif
	[SMC_FUNCTION(SMC_FC_API_VERSION)] = smc_sm_api_version,
#if WITH_HOTPLUG
	[SMC_FUNCTION(SMC_FC_CPU_UP)] = smc_cpu_up,
	[SMC_FUNCTION(SMC_FC_CPU_DOWN)] = smc_cpu_down,
#endif
	[SMC_FUNCTION(SMC_FC_CPU_CAN_DOWN)] = smc_cpu_can_down,
};

uint32_t sm_nr_fastcall_functions = countof(sm_fastcall_function_table);

/* SMC dispatch tables */
smc32_handler_t sm_fastcall_table[SMC_NUM_ENTITIES] = {
	[0 ... SMC_ENTITY_SECURE_MONITOR - 1] = smc_undefined,
	[SMC_ENTITY_SECURE_MONITOR] = smc_fastcall_secure_monitor,
	[SMC_ENTITY_SECURE_MONITOR + 1 ... SMC_NUM_ENTITIES - 1] = smc_undefined
};

smc32_handler_t sm_stdcall_table[SMC_NUM_ENTITIES] = {
	[0 ... SMC_ENTITY_SECURE_MONITOR - 1] = smc_undefined,
	[SMC_ENTITY_SECURE_MONITOR] = smc_stdcall_secure_monitor,
	[SMC_ENTITY_SECURE_MONITOR + 1 ... SMC_NUM_ENTITIES - 1] = smc_undefined
};

status_t sm_register_entity(uint entity_nr, smc32_entity_t *entity)
{
	status_t err = NO_ERROR;

	if (entity_nr >= SMC_NUM_ENTITIES)
		return ERR_INVALID_ARGS;

	if (entity_nr >= SMC_ENTITY_RESERVED && entity_nr < SMC_ENTITY_TRUSTED_APP)
		return ERR_NOT_ALLOWED;

	if (!entity)
		return ERR_INVALID_ARGS;

	if (!entity->fastcall_handler && !entity->stdcall_handler)
		return ERR_NOT_VALID;

	mutex_acquire(&smc_table_lock);

	/* Check if entity is already claimed */
	if (sm_fastcall_table[entity_nr] != smc_undefined ||
		sm_stdcall_table[entity_nr] != smc_undefined) {
		err = ERR_ALREADY_EXISTS;
		goto unlock;
	}

	if (entity->fastcall_handler)
		sm_fastcall_table[entity_nr] = entity->fastcall_handler;

	if (entity->stdcall_handler)
		sm_stdcall_table[entity_nr] = entity->stdcall_handler;
unlock:
	mutex_release(&smc_table_lock);
	return err;
}
