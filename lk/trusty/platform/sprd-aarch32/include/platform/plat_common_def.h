/*
 * Copyright (c) 2012 Travis Geiselbrecht
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
#ifndef __PLATFORM_COMMON_DEF_H
#define __PLATFORM_COMMON_DEF_H

#define REGISTER_BANK_0_PADDR (0x70000000)
#define REGISTER_BANK_2_PADDR (0x12000000)
#define REGISTER_BANK_3_PADDR (0x40200000)
#define REGISTER_BANK_4_PADDR (0x40400000)


#define REGISTER_BANK_0_VADDR (0x70000000) /* use identry map for now */
#define REGISTER_BANK_2_VADDR (0x12000000) //GIC BASE
#define REGISTER_BANK_3_VADDR (0x40200000) //apb
#define REGISTER_BANK_4_VADDR (0x40400000) //ts0/1


/* hardware base addresses */
#define SECONDARY_BOOT_ADDR (REGISTER_BANK_0_VADDR + 0x110030)


#define UART0 (REGISTER_BANK_0_VADDR + 0x0)
#define UART1 (REGISTER_BANK_0_VADDR + 0x100000)
#define UART2 (REGISTER_BANK_0_VADDR + 0x200000)
#define UART3 (REGISTER_BANK_0_VADDR + 0x300000)

#define GIC0   (REGISTER_BANK_2_VADDR + 0x00000)
//#define GIC1   (REGISTER_BANK_2_VADDR + 0x10000)
//#define GIC2   (REGISTER_BANK_2_VADDR + 0x20000)
//#define GIC3   (REGISTER_BANK_2_VADDR + 0x30000)
#define GICBASE(n) (GIC0 + (n) * 0x10000)

/* interrupts */
#define ARM_GENERIC_TIMER_INT 29
#define TIMER01_INT 34
#define TIMER23_INT 35
//#define UART0_INT 37
#define UART1_INT 38
//#define UART2_INT 39
//#define UART3_INT 40

#define MAX_INT 160

#endif

