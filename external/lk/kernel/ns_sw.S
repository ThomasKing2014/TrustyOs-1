
#define MODE_USR 0x10
#define MODE_FIQ 0x11
#define MODE_IRQ 0x12
#define MODE_SVC 0x13
#define MODE_MON 0x16
#define MODE_ABT 0x17
#define MODE_UND 0x1b
#define MODE_SYS 0x1f
#define MODE_SVC_IRQ_DISABLED	0x93
#define MODE_SVC_IRQ_FIQ_DISABLED	0xd3

#define SM_SCR_NONSECURE	0x5
#define SM_SCR_SECURE		0x0

#define FUNCTION(x) .global x; .type x,STT_FUNC; x:

#ifndef SMP_CPU_ID_BITS
#define SMP_CPU_ID_BITS 8
#endif

/* sets SCR.NS bit to 1 (assumes monitor mode) */
.macro SWITCH_SCR_TO_NONSECURE, tmp
	mov	\tmp, #SM_SCR_NONSECURE
	mcr	p15, 0, \tmp, c1, c1, 0
	isb
.endm

FUNCTION(switch_to_ns)
        cps     #MODE_MON
        SWITCH_SCR_TO_NONSECURE r3
        cps     #MODE_SVC
        ldr lr, =secondary_jump_addr
	ldr lr, [lr]
        bx lr



FUNCTION(sm_ret_ns)
	clrex
	mov r0,r0
	ldr r1,=0xdeedbeef
	ldr r2,=track_the
       /* figure out our cpu number */
	mrc     p15, 0, r3, c0, c0, 5 /* read MPIDR */
       /* mask off the bottom bits to test cluster number:cpu number */
       ubfx    r3, r3, #0, #SMP_CPU_ID_BITS
       mov r4,#4
       mul r3,r3,r4
	
       str r1,[r2, r3]	

	smc #0
	b .

	






