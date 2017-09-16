/*
 * Copyright (c) 2008-2014 Travis Geiselbrecht
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

#include <ctype.h>
#include <debug.h>
#include <stdlib.h>
#include <printf.h>
#include <stdio.h>
#include <list.h>
#include <string.h>
#include <arch/ops.h>
#include <platform.h>
#include <platform/debug.h>
#include <kernel/thread.h>

#if WITH_LIB_SM
#define PRINT_LOCK_FLAGS SPIN_LOCK_FLAG_IRQ_FIQ
#else
#define PRINT_LOCK_FLAGS SPIN_LOCK_FLAG_INTERRUPTS
#endif

#if defined(ENABLE_CONSOLE)
long console = 1;
#else
long console = 0;
#endif

#if LK_DEBUGLEVEL > 0
long loglevel = LK_DEBUGLEVEL;
#else
long loglevel = 0;
#endif

int print_to_memlog = 0;



static spin_lock_t print_spin_lock = 0;
static struct list_node print_callbacks = LIST_INITIAL_VALUE(print_callbacks);

#if WITH_MEMLOG_EARLY
#include <kernel/timer.h>

#define EARLY_LOG_BUF_LEN (1024 * 8)

static char early_log_buf[EARLY_LOG_BUF_LEN];
static int early_log_buf_pos = 0;
static int early_logprint_done = 0;

static timer_t early_logprint_timer;

static enum handler_return early_logprint_timer_cb(struct timer* timer,
										lk_time_t now, void* arg)
{
	print_callback_t *cb;

	list_for_every_entry(&print_callbacks, cb, print_callback_t, entry) {
		if (cb->print && early_log_buf_pos > 0) {
			cb->print(cb, early_log_buf, early_log_buf_pos);
			early_log_buf_pos = 0;
		} else
			return INT_NO_RESCHEDULE;
	}

	return INT_RESCHEDULE;
}

#endif /* WITH_MEMLOG_EARLY  */

/* print lock must be held when invoking out, outs, outc */
static void out_count(const char *str, size_t len)
{
	print_callback_t *cb;
	size_t i;

	if (print_to_memlog) {
#if WITH_MEMLOG_EARLY
		if (early_log_buf_pos > 0 && early_logprint_done == 0) {
			early_logprint_done = 1;

			timer_initialize(&early_logprint_timer);
			timer_set_oneshot(&early_logprint_timer, 3000,
					  early_logprint_timer_cb, NULL);
		}
#endif
		if (console) {
			/* write out the serial port */
			for (i = 0; i < len; i++) {
				platform_dputc(str[i]);
			}
		} else {
			/* print to any registered loggers */
			list_for_every_entry(&print_callbacks, cb, print_callback_t, entry) {
				cb->print(cb, str, len);
			}
		}//
	} else {
#if WITH_MEMLOG_EARLY
		if (early_log_buf_pos < EARLY_LOG_BUF_LEN) {
			size_t unused, filled;

			unused = EARLY_LOG_BUF_LEN - early_log_buf_pos;
			filled = ((unused > len) ? len : unused);

			memcpy(early_log_buf + early_log_buf_pos, str, filled);
			early_log_buf_pos += filled;
		}
#endif
		if (console) {
			/* write init log to the serial port */
			for (i = 0; i < len; i++) {
				platform_dputc(str[i]);
			}
		}
	}
}

static void out_string(const char *str)
{
	out_count(str, strlen(str));
}

static void out_char(char c)
{
	out_count(&c, 1);
}

static int input_char(char *c)
{
	return platform_dgetc(c, true);
}

void register_print_callback(print_callback_t *cb)
{
	spin_lock_saved_state_t state;

	spin_lock_save(&print_spin_lock, &state, PRINT_LOCK_FLAGS);
	list_add_head(&print_callbacks, &cb->entry);
	spin_unlock_restore(&print_spin_lock, state, PRINT_LOCK_FLAGS);
}

void unregister_print_callback(print_callback_t *cb)
{
	spin_lock_saved_state_t state;

	spin_lock_save(&print_spin_lock, &state, PRINT_LOCK_FLAGS);
	list_delete(&cb->entry);
	spin_unlock_restore(&print_spin_lock, state, PRINT_LOCK_FLAGS);
}

void spin(uint32_t usecs)
{
	lk_bigtime_t start = current_time_hires();

	while ((current_time_hires() - start) < usecs)
		;
}

void _panic(void *caller, const char *fmt, ...)
{
	dprintf(ALWAYS, "panic (caller %p): ", caller);

	va_list ap;
	va_start(ap, fmt);
	_dvprintf(fmt, ap);
	va_end(ap);

	platform_halt(HALT_ACTION_HALT, HALT_REASON_SW_PANIC);
}

static int __debug_stdio_fputc(void *ctx, int c)
{
	_dputc(c);
	return 0;
}

static int __debug_stdio_fputs(void *ctx, const char *s)
{
	return _dputs(s);
}

static int __debug_stdio_fgetc(void *ctx)
{
	char c;
	int err;

	err = input_char(&c);
	if (err < 0)
		return err;
	return (unsigned char)c;
}

static int __debug_stdio_vfprintf(void *ctx, const char *fmt, va_list ap)
{
	return _dvprintf(fmt, ap);
}

#define DEFINE_STDIO_DESC(id)						\
	[(id)]	= {							\
		.ctx		= &__stdio_FILEs[(id)],			\
		.fputc		= __debug_stdio_fputc,			\
		.fputs		= __debug_stdio_fputs,			\
		.fgetc		= __debug_stdio_fgetc,			\
		.vfprintf	= __debug_stdio_vfprintf,		\
	}

FILE __stdio_FILEs[3] = {
	DEFINE_STDIO_DESC(0), /* stdin */
	DEFINE_STDIO_DESC(1), /* stdout */
	DEFINE_STDIO_DESC(2), /* stderr */
};
#undef DEFINE_STDIO_DESC

#if !DISABLE_DEBUG_OUTPUT

void _dputc(char c)
{
	spin_lock_saved_state_t state;

	spin_lock_save(&print_spin_lock, &state, PRINT_LOCK_FLAGS);
	out_char(c);
	spin_unlock_restore(&print_spin_lock, state, PRINT_LOCK_FLAGS);
}

int _dputs(const char *str)
{
	spin_lock_saved_state_t state;

	spin_lock_save(&print_spin_lock, &state, PRINT_LOCK_FLAGS);
	out_string(str);
	spin_unlock_restore(&print_spin_lock, state, PRINT_LOCK_FLAGS);

	return 0;
}

int _dwrite(const char *ptr, size_t len)
{
	spin_lock_saved_state_t state;

	spin_lock_save(&print_spin_lock, &state, PRINT_LOCK_FLAGS);
	out_count(ptr, len);
	spin_unlock_restore(&print_spin_lock, state, PRINT_LOCK_FLAGS);

	return 0;
}

static int _dprintf_output_func(const char *str, size_t len, void *state)
{
	size_t n = strnlen(str, len);

	out_count(str, n);
	return n;
}

int _dprintf(const char *fmt, ...)
{
	spin_lock_saved_state_t state;
	int err;
	va_list ap;

	va_start(ap, fmt);
	spin_lock_save(&print_spin_lock, &state, PRINT_LOCK_FLAGS);
	err = _printf_engine(&_dprintf_output_func, NULL, fmt, ap);
	spin_unlock_restore(&print_spin_lock, state, PRINT_LOCK_FLAGS);
	va_end(ap);

	return err;
}

int _dvprintf(const char *fmt, va_list ap)
{
	spin_lock_saved_state_t state;
	int err;

	spin_lock_save(&print_spin_lock, &state, PRINT_LOCK_FLAGS);
	err = _printf_engine(&_dprintf_output_func, NULL, fmt, ap);
	spin_unlock_restore(&print_spin_lock, state, PRINT_LOCK_FLAGS);

	return err;
}

void hexdump(const void *ptr, size_t len)
{
	addr_t address = (addr_t)ptr;
	size_t count;

	for (count = 0 ; count < len; count += 16) {
		union {
			uint32_t buf[4];
			uint8_t  cbuf[16];
		} u;
		size_t s = ROUNDUP(MIN(len - count, 16), 4);
		size_t i;

		printf("0x%08lx: ", address);
		for (i = 0; i < s / 4; i++) {
			u.buf[i] = ((const uint32_t *)address)[i];
			printf("%08x ", u.buf[i]);
		}
		for (; i < 4; i++) {
			printf("         ");
		}
		printf("|");

		for (i=0; i < 16; i++) {
			char c = u.cbuf[i];
			if (i < s && isprint(c)) {
				printf("%c", c);
			} else {
				printf(".");
			}
		}
		printf("|\n");
		address += 16;
	}
}

void hexdump8(const void *ptr, size_t len)
{
	addr_t address = (addr_t)ptr;
	size_t count;
	size_t i;

	for (count = 0 ; count < len; count += 16) {
		printf("0x%08lx: ", address);
		for (i=0; i < MIN(len - count, 16); i++) {
			printf("0x%02hhx ", *(const uint8_t *)(address + i));
		}
		printf("\n");
		address += 16;
	}
}

#endif // !DISABLE_DEBUG_OUTPUT

// vim: set noexpandtab:
