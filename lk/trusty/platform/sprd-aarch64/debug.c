/*
 * The MIT License (MIT)
 * Copyright (c) 2008-2015 Travis Geiselbrecht
 * Copyright (c) 2017, Spreadtrum Communications.
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

#include <kernel/thread.h>
#include <kernel/vm.h>
#include <lk/init.h>
#include <platform/debug.h>
#include <platform/plat_common_def.h>
#include <reg.h>
#include "smc.h"

#define DR (0x00)
#define FR (0x0c)

#ifndef UART_NUM
#define UART_BASE (UART1)
#else
#if UART_NUM == 0
#define UART_BASE (UART0)
#elif UART_NUM == 1
#define UART_BASE (UART1)
#elif UART_NUM == 2
#define UART_BASE (UART2)
#elif UART_NUM == 3
#define UART_BASE (UART3)
#endif
#endif

#define UARTREG(reg)  (*REG32((UART_BASE) + (reg)))

static int uart_putc(char c)
{

    /* spin while fifo is full */
    while (UARTREG(FR) & (0x7f<<8))
        ;
    UARTREG(DR) = c;

    return 1;
}

void platform_dputc(char c)
{
	if (c == '\n')
		uart_putc('\r');
	uart_putc(c);
}

int platform_dgetc(char *c, bool wait)
{
	if (!wait) {
		if (UARTREG(FR) & (1<<4)) {
			/* fifo empty */
			return -1;
		}
		*c = UARTREG(DR) & 0xff;
		return 0;
	} else {
		while ((UARTREG(FR) & (1<<4))) {
			// XXX actually block on interrupt
			thread_yield();
		}

		*c = UARTREG(DR) & 0xff;
		return 0;
	}
}


#if 0
void platform_dputc(char c)
{
	generic_arm64_smc(SMC_FC_DEBUG_PUTC, c, 0, 0);
}

int platform_dgetc(char *c, bool wait)
{
	int ret = -1;

	while (wait)
		thread_sleep(100);

	return ret;
}
#endif
