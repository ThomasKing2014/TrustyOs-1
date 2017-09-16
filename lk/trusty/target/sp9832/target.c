#include <sys/types.h>

extern lk_bigtime_t (*target_clk_htime)(void);

lk_bigtime_t clk_target_htime(void)
{	/*1ms tick*/
	lk_bigtime_t t = (lk_bigtime_t)(*(volatile unsigned int*)(0x40230004));
	return t * 1000;
}

void target_early_init(void)
{
	*(volatile unsigned int*)0x402e0000 |= (0x3 << 28);
	*(volatile unsigned int*)0x402e0028 |= (0x1 << 8) | (0x1 << 10) | (0x1 << 12);
	*(volatile unsigned int*)0x40400000 = 1;
	*(volatile unsigned int*)0x40410000 = 1;

	/*init a garget clk*/
	target_clk_htime = clk_target_htime;
}
