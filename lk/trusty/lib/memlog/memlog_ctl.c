/*
 * trusty management interface.
 *
 *	  Copyright spreadtrum Corp 2017
 *	  Author(s): wangxw <wangxw@spreadst.com>,
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

//#define SMC_ENTITY_SYSCTL       53  /* Used for secure -> nonsecure sysctl */

#define SMC_SC_SYSCTL_SET_CONSOLE   SMC_STDCALL_NR(SMC_ENTITY_SYSCTL, 0)
#define SMC_SC_SYSCTL_GET_CONSOLE   SMC_STDCALL_NR(SMC_ENTITY_SYSCTL, 1)
#define SMC_SC_SYSCTL_SET_LOGLEVEL  SMC_STDCALL_NR(SMC_ENTITY_SYSCTL, 2)
#define SMC_SC_SYSCTL_GET_LOGLEVEL  SMC_STDCALL_NR(SMC_ENTITY_SYSCTL, 3)


extern long console;
extern long loglevel;

static long trusty_sysctl_stdcall(smc32_args_t *args)
{
    long val = -1;

	switch (args->smc_nr) {
	case SMC_SC_SYSCTL_SET_CONSOLE:
		console = args->params[0];
		return 0;
	case SMC_SC_SYSCTL_GET_CONSOLE:
		return console;
	case SMC_SC_SYSCTL_SET_LOGLEVEL:
		val = args->params[0];
		if ((SPEW >= val) && (val >= 0)) {
		    loglevel = val;
		    return 0;
		} else {
            return SM_ERR_INVALID_PARAMETERS;
		}
	case SMC_SC_SYSCTL_GET_LOGLEVEL:
		return loglevel;
	default:
		return SM_ERR_UNDEFINED_SMC;
	}
	return 0;
}

static smc32_entity_t trusty_sysctl_entity = {
	.stdcall_handler = trusty_sysctl_stdcall,
};

static void trusty_sysctl_init(uint level)
{
	int err;

	err = sm_register_entity(SMC_ENTITY_SYSCTL, &trusty_sysctl_entity);
	if (err) {
		printf("trusty error register entity: %d\n", err);
	}
}
LK_INIT_HOOK(trusty_sysctl, trusty_sysctl_init, LK_INIT_LEVEL_APPS);
