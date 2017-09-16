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


#define REGISTER_BANK_0_VADDR (KERNEL_ASPACE_BASE + KERNEL_ASPACE_SIZE - 0x1000000) /* kernel space final 16M,size 0x400000 */
//#define REGISTER_BANK_0_VADDR (0x70000000) /* use identry map for now */

#define REGISTER_BANK_0_SIZE (0x400000)


#define UART0 (REGISTER_BANK_0_VADDR + 0x0)
#define UART1 (REGISTER_BANK_0_VADDR + 0x100000)
#define UART2 (REGISTER_BANK_0_VADDR + 0x200000)
#define UART3 (REGISTER_BANK_0_VADDR + 0x300000)

#endif
