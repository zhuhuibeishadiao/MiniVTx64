#pragma once
//#include <ntddk.h>
#include <Ntifs.h>
//#include <wdf.h>

extern ULONG __cdecl DbgPrint(_In_z_ _Printf_format_string_ PCSTR Format, ...);
#define FGP_VT_KDPRINT(_x_) \
	DbgPrint("FGP [VT] : [#%d][IRQL=0x%x](%s): ", KeGetCurrentProcessorNumber(), KeGetCurrentIrql(), __FUNCTION__);\
	DbgPrint _x_;
//
//===============================================================================================
//
// VT-X
//
//===============================================================================================
//

#define CPUID_EPT_HIDE_VISCODE		0x1000
#define CPUID_EPT_REVEAL_VISCODE	0x1001
/*
*windows地址转译
*参考bp
*/

#define	PML4_BASE	0xFFFFF6FB7DBED000
#define	PDP_BASE	0xFFFFF6FB7DA00000
#define	PD_BASE		0xFFFFF6FB40000000
#define	PT_BASE		0xFFFFF68000000000


/*
*page define
*/
#define P_PRESENT			0x01
#define P_WRITABLE			0x02
#define P_USERMODE			0x04
#define P_WRITETHROUGH		0x08
#define P_CACHE_DISABLED	0x10
#define P_ACCESSED			0x20
#define P_DIRTY				0x40
#define P_LARGE				0x80
#define P_GLOBAL			0x100



#define KGDT64_NULL (0 * 16)    // NULL descriptor
#define KGDT64_R0_CODE (1 * 16) // kernel mode 64-bit code
#define KGDT64_R0_DATA (1 * 16) + 8     // kernel mode 64-bit data (stack)
#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code
#define KGDT64_R3_DATA (2 * 16) + 8     // user mode 32-bit data
#define KGDT64_R3_CODE (3 * 16) // user mode 64-bit code
#define KGDT64_SYS_TSS (4 * 16) // kernel mode system task state
#define KGDT64_R3_CMTEB (5 * 16)        // user mode 32-bit TEB
#define KGDT64_R0_CMCODE (6 * 16)       // kernel mode 32-bit code

#pragma pack (push, 1)


#define VIRTDBG_POOLTAG 0xbad0bad0

#define ITL_TAG	'LTI'

/* 
* Attribute for segment selector. This is a copy of bit 40:47 & 52:55 of the
* segment descriptor. 
*/
typedef unsigned           char   Bit8u;
typedef   signed           char   Bit8s;
typedef unsigned short     int    Bit16u;
typedef signed short       int    Bit16s;
typedef unsigned           int    Bit32u;
typedef   signed           int    Bit32s;
typedef unsigned long long int    Bit64u;
typedef   signed long long int    Bit64s;

typedef Bit32u VM_BOOL;
typedef Bit64u VM_Address;
typedef Bit64u VM_PHY_Address;

typedef union
{
  USHORT UCHARs;
  struct
  {
    USHORT type:4;              /* 0;  Bit 40-43 */
    USHORT s:1;                 /* 4;  Bit 44 */
    USHORT dpl:2;               /* 5;  Bit 45-46 */
    USHORT p:1;                 /* 7;  Bit 47 */
    // gap!       
    USHORT avl:1;               /* 8;  Bit 52 */
    USHORT l:1;                 /* 9;  Bit 53 */
    USHORT db:1;                /* 10; Bit 54 */
    USHORT g:1;                 /* 11; Bit 55 */
    USHORT Gap:4;
  } fields;
} SEGMENT_ATTRIBUTES;

typedef struct _TSS64
{
  ULONG Reserved0;
  PVOID RSP0;
  PVOID RSP1;
  PVOID RSP2;
  ULONG64 Reserved1;
  PVOID IST1;
  PVOID IST2;
  PVOID IST3;
  PVOID IST4;
  PVOID IST5;
  PVOID IST6;
  PVOID IST7;
  ULONG64 Reserved2;
  USHORT Reserved3;
  USHORT IOMapBaseAddress;
} TSS64, *PTSS64;

typedef struct _SEGMENT_SELECTOR
{
  USHORT sel;
  SEGMENT_ATTRIBUTES attributes;
  ULONG32 limit;
  ULONG64 base;
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
  USHORT limit0;
  USHORT base0;
  UCHAR base1;
  UCHAR attr0;
  UCHAR limit1attr1;
  UCHAR base2;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef struct _INTERRUPT_GATE_DESCRIPTOR
{
  USHORT TargetOffset1500;
  USHORT TargetSelector;
  UCHAR InterruptStackTable;
  UCHAR Attributes;
  USHORT TargetOffset3116;
  ULONG32 TargetOffset6332;
  ULONG32 Reserved;
} INTERRUPT_GATE_DESCRIPTOR,
 *PINTERRUPT_GATE_DESCRIPTOR;

#pragma pack (pop)

#define LA_ACCESSED		0x01
#define LA_READABLE		0x02    // for code segments
#define LA_WRITABLE		0x02    // for data segments
#define LA_CONFORMING	0x04    // for code segments
#define LA_EXPANDDOWN	0x04    // for data segments
#define LA_CODE			0x08
#define LA_STANDARD		0x10
#define LA_DPL_0		0x00
#define LA_DPL_1		0x20
#define LA_DPL_2		0x40
#define LA_DPL_3		0x60
#define LA_PRESENT		0x80

#define LA_LDT64		0x02
#define LA_ATSS64		0x09
#define LA_BTSS64		0x0b
#define LA_CALLGATE64	0x0c
#define LA_INTGATE64	0x0e
#define LA_TRAPGATE64	0x0f

#define HA_AVAILABLE	0x01
#define HA_LONG			0x02
#define HA_DB			0x04
#define HA_GRANULARITY	0x08

typedef enum SEGREGS
{
  ES = 0,
  CS,
  SS,
  DS,
  FS,
  GS,
  LDTR,
  TR
};

#define DIVIDE_ERROR_EXCEPTION 0
#define DEBUG_EXCEPTION 1
#define NMI_INTERRUPT 2
#define BREAKPOINT_EXCEPTION 3
#define OVERFLOW_EXCEPTION 4
#define BOUND_EXCEPTION 5
#define INVALID_OPCODE_EXCEPTION 6
#define DEVICE_NOT_AVAILABLE_EXCEPTION 7
#define DOUBLE_FAULT_EXCEPTION 8
#define COPROCESSOR_SEGMENT_OVERRUN 9
#define INVALID_TSS_EXCEPTION 10
#define SEGMENT_NOT_PRESENT 11
#define STACK_FAULT_EXCEPTION 12
#define GENERAL_PROTECTION_EXCEPTION 13
#define PAGE_FAULT_EXCEPTION 14
#define X87_FLOATING_POINT_ERROR 16
#define ALIGNMENT_CHECK_EXCEPTION 17
//#define MACHINE_CHECK_EXCEPTION 18
#define SIMD_FLOATING_POINT_EXCEPTION 19

#define EXTERNAL_INTERRUPT 0
#define HARDWARE_EXCEPTION 3
#define SOFTWARE_INTERRUPT 4
#define PRIVILEGED_SOFTWARE_EXCEPTION 5
#define SOFTWARE_EXCEPTION 6
#define OTHER_EVENT 7

#define EFER_LME     (1<<8)
#define EFER_LMA     (1<<10)


/*
 * INVVPID 指令的 cache 刷新类型
 */
#define INDIVIDUAL_ADDRESS_INVALIDATION                 0
#define SINGLE_CONTEXT_INVALIDATION                     1
#define ALL_CONTEXT_INVALIDATION                        2
#define SINGLE_CONTEXT_EXCLUDE_GLOBAL_INVALIDATION      3
/*
 * Intel CPU flags in CR0
 */
#define X86_CR0_PE              0x00000001      /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              0x00000002      /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              0x00000004      /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              0x00000008      /* Task Switched            (RW) */
#define X86_CR0_ET              0x00000010      /* Extension type           (RO) */
#define X86_CR0_NE              0x00000020      /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              0x00010000      /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              0x00040000      /* Alignment Checking       (RW) */
#define X86_CR0_NW              0x20000000      /* Not Write-Through        (RW) */
#define X86_CR0_CD              0x40000000      /* Cache Disable            (RW) */
#define X86_CR0_PG              0x80000000      /* Paging                   (RW) */

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VME		0x0001  /* enable vm86 extensions */
#define X86_CR4_PVI		0x0002  /* virtual interrupts flag enable */
#define X86_CR4_TSD		0x0004  /* disable time stamp at ipl 3 */
#define X86_CR4_DE		0x0008  /* enable debugging extensions */
#define X86_CR4_PSE		0x0010  /* enable page size extensions */
#define X86_CR4_PAE		0x0020  /* enable physical address extensions */
#define X86_CR4_MCE		0x0040  /* Machine check enable */
#define X86_CR4_PGE		0x0080  /* enable global pages */
#define X86_CR4_PCE		0x0100  /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200  /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400  /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE		0x2000  /* enable VMX */

/*
 * Intel CPU  MSR
 */

 /* MSRs & bits used for VMX enabling */

#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_FEATURE_CONTROL 		0x03a
#define MSR_IA32_VMX_PINBASED_CTLS		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484
#define MSR_IA32_VMX_PROCBASED_CTLS2   0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP      0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS   0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x48E

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9

#define MSR_IA32_MTRRCAP			0xfe
#define MSR_IA32_MTRR_DEF_TYPE			0x2ff
#define MSR_IA32_MTRR_PHYSBASE(n)		(0x200 + 2*(n))
#define MSR_IA32_MTRR_PHYSMASK(n)		(0x200 + 2*(n) + 1)
#define MSR_IA32_MTRR_FIX64K_00000		0x250
#define MSR_IA32_MTRR_FIX16K_80000		0x258
#define MSR_IA32_MTRR_FIX16K_A0000		0x259
#define MSR_IA32_MTRR_FIX4K_C0000		0x268
#define MSR_IA32_MTRR_FIX4K_C8000		0x269
#define MSR_IA32_MTRR_FIX4K_D0000		0x26a
#define MSR_IA32_MTRR_FIX4K_D8000		0x26b
#define MSR_IA32_MTRR_FIX4K_E0000		0x26c
#define MSR_IA32_MTRR_FIX4K_E8000		0x26d
#define MSR_IA32_MTRR_FIX4K_F0000		0x26e
#define MSR_IA32_MTRR_FIX4K_F8000		0x26f

/* x86-64 MSR */

#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compatibility mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084   /* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100                /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101                /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */ 


#define RT_BIT(bit)                             ( 1U << (bit) )
#define RT_BIT_32(bit)                          ( UINT32_C(1) << (bit) )
#define RT_BIT_64(bit)                          ( UINT64_C(1) << (bit) )

# define INT8_C(Value)      (Value)
# define INT16_C(Value)     (Value)
# define INT32_C(Value)     (Value)
# define INT64_C(Value)     (Value ## LL)
# define UINT8_C(Value)     (Value)
# define UINT16_C(Value)    (Value)
# define UINT32_C(Value)    (Value ## U)
# define UINT64_C(Value)    (Value ## ULL)
# define INTMAX_C(Value)    INT64_C(Value)
# define UINTMAX_C(Value)   UINT64_C(Value)



/** @name DR6
 * @{ */
/** Bit 0 - B0 - Breakpoint 0 condition detected. */
#define X86_DR6_B0                          RT_BIT(0)
/** Bit 1 - B1 - Breakpoint 1 condition detected. */
#define X86_DR6_B1                          RT_BIT(1)
/** Bit 2 - B2 - Breakpoint 2 condition detected. */
#define X86_DR6_B2                          RT_BIT(2)
/** Bit 3 - B3 - Breakpoint 3 condition detected. */
#define X86_DR6_B3                          RT_BIT(3)
/** Mask of all the Bx bits. */
#define X86_DR6_B_MASK                      UINT64_C(0x0000000f)
/** Bit 13 - BD - Debug register access detected. Corresponds to the X86_DR7_GD bit. */
#define X86_DR6_BD                          RT_BIT(13)
/** Bit 14 - BS - Single step */
#define X86_DR6_BS                          RT_BIT(14)
/** Bit 15 - BT - Task switch. (TSS T bit.) */
#define X86_DR6_BT                          RT_BIT(15)
/** Value of DR6 after powerup/reset. */
#define X86_DR6_INIT_VAL                    UINT64_C(0xFFFF0FF0)
/** Bits which must be 1s in DR6. */
#define X86_DR6_RA1_MASK                    UINT64_C(0xffff0ff0)
/** Bits which must be 0s in DR6. */
#define X86_DR6_RAZ_MASK                    RT_BIT_64(12)
/** Bits which must be 0s on writes to DR6. */
#define X86_DR6_MBZ_MASK                    UINT64_C(0xffffffff00000000)
/** @} */





/** Value of DR7 after powerup/reset. */
#define X86_DR7_INIT_VAL                    0x400

/** Bit 13 - GD - General detect enable. Enables emulators to get exceptions when
 * any DR register is accessed. */
#define X86_DR7_GD                          RT_BIT(13)


/** Bits which reads as 1s. */
#define X86_DR7_RA1_MASK                    (RT_BIT(10))
/** Bits which reads as zeros. */
#define X86_DR7_RAZ_MASK                    UINT64_C(0x0000d800)




#define CR0 0
#define CR3 3
#define CR4 4
#define CR8 8

#define DR_0 0
#define DR_1 1
#define DR_2 2
#define DR_3 3
#define DR_6 6
#define DR_7 7

#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8 8
#define R9 9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15
#define RIP 16
#define PDPTR 17

//
// Used by the cpuid instruction when eax=1
//

typedef struct _VMX_FEATURES {
    unsigned SSE3        :1;        // SSE3 Extensions
    unsigned RES1        :2;
    unsigned MONITOR     :1;        // MONITOR/WAIT
    unsigned DS_CPL      :1;        // CPL qualified Debug Store
    unsigned VMX         :1;        // Virtual Machine Technology
    unsigned RES2        :1;
    unsigned EST         :1;        // Enhanced Intel? Speedstep Technology
    unsigned TM2         :1;        // Thermal monitor 2
    unsigned SSSE3       :1;        // SSSE3 extensions
    unsigned CID         :1;        // L1 context ID
    unsigned RES3        :2;
    unsigned CX16        :1;        // CMPXCHG16B
    unsigned xTPR        :1;        // Update control
    unsigned PDCM        :1;        // Performance/Debug capability MSR
    unsigned RES4        :2;
    unsigned DCA         :1;
    unsigned RES5        :13;
} VMX_FEATURES;

typedef struct _IA32_FEATURE_CONTROL_MSR {
    unsigned Lock            :1;        // Bit 0 is the lock bit - cannot be
                                        // modified once lock is set, controled by BIOS
    unsigned VmxonInSmx      :1;
    unsigned VmxonOutSmx     :1;
    unsigned Reserved2       :29;
    unsigned Reserved3       :32;
} IA32_FEATURE_CONTROL_MSR;

typedef struct _CR4_REG {
    unsigned VME        :1;            // Virtual Mode Extensions
    unsigned PVI        :1;            // Protected-Mode Virtual Interrupts
    unsigned TSD        :1;            // Time Stamp Disable
    unsigned DE         :1;            // Debugging Extensions
    unsigned PSE        :1;            // Page Size Extensions
    unsigned PAE        :1;            // Physical Address Extension
    unsigned MCE        :1;            // Machine-Check Enable
    unsigned PGE        :1;            // Page Global Enable
    unsigned PCE        :1;            // Performance-Monitoring Counter Enable
    unsigned OSFXSR     :1;            // OS Support for FXSAVE/FXRSTOR
    unsigned OSXMMEXCPT :1;            // OS Support for Unmasked SIMD Floating-Point Exceptions
    unsigned Reserved1  :2;            //
    unsigned VMXE       :1;            // Virtual Machine Extensions Enabled
    unsigned Reserved2  :18;           //
} CR4_REG, *PCR4_REG;


typedef struct _RFLAGS {
    unsigned CF:1;
    unsigned Reserved1:1;
    unsigned PF:1;
    unsigned Reserved2:1;
    unsigned AF:1;
    unsigned Reserved3:1;
    unsigned ZF:1;
    unsigned SF:1;
    unsigned TF:1;
    unsigned IF:1;
    unsigned DF:1;
    unsigned OF:1;
    unsigned IOPL:2;
    unsigned NT:1;
    unsigned Reserved4:1;
    unsigned RF:1;
    unsigned VM:1;
    unsigned AC:1;
    unsigned VIF:1;
    unsigned VIP:1;
    unsigned ID:1;
    unsigned Reserved5:10;
} RFLAGS, *PRFLAGS;

#define TF 0x100 

typedef union _DR6 {
    ULONG Value;
    struct {
        unsigned B0:1;
        unsigned B1:1;
        unsigned B2:1;
        unsigned B3:1;
        unsigned Reserved1:10;
        unsigned BD:1;
        unsigned BS:1;
        unsigned BT:1;
        unsigned Reserved2:16;
    };
} DR6, *PDR6;

typedef union _DR7 {
    ULONG Value;
    struct {
        unsigned L0:1;
        unsigned G0:1;
        unsigned L1:1;
        unsigned G1:1;
        unsigned L2:1;
        unsigned G2:1;
        unsigned L3:1;
        unsigned G3:1;
        unsigned LE:1;
        unsigned GE:1;
        unsigned Reserved1:3;
        unsigned GD:1;
        unsigned Reserved2:2;
        unsigned RW0:2;
        unsigned LEN0:2;
        unsigned RW1:2;
        unsigned LEN1:2;
        unsigned RW2:2;
        unsigned LEN2:2;
        unsigned RW3:2;
        unsigned LEN3:2;
    };
} DR7, *PDR7;

typedef union _IA32_DEBUGCTL_MSR
{
    ULONG Value;
    struct {
        unsigned LBR:1;
        unsigned BTF:1;
        unsigned Reserved1:4;
        unsigned TR:1;
        unsigned BTS:1;
        unsigned BTINT:1;
        unsigned BTS_OFF_OS:1;
        unsigned BTS_OFF_USR:1;
        unsigned FREEZE_LBRS_ON_PMI:1;
        unsigned FREEZE_PERFMON_ON_PMI:1;
        unsigned Reserved2:1;
        unsigned FREEZE_WHILE_SMM_EN:1;
    };
} IA32_DEBUGCTL_MSR, *PIA32_DEBUGCTL_MSR;

typedef struct _MSR {
    ULONG Lo;
    ULONG Hi;
} MSR, *PMSR;

typedef struct _VMX_BASIC_MSR {
    unsigned RevId:32;
    unsigned szVmxOnRegion:12;
    unsigned ClearBit:1;
    unsigned Reserved:3;
    unsigned PhysicalWidth:1;
    unsigned DualMonitor:1;
    unsigned MemoryType:4;
    unsigned VmExitInformation:1;
    unsigned Reserved2:9;
} VMX_BASIC_MSR, *PVMX_BASIC_MSR;

typedef struct _GUEST_REGS
{
  ULONG64 dr0;
  ULONG64 dr1;
  ULONG64 dr2;
  ULONG64 dr3;
  ULONG64 dr6;
  ULONG64 dr7;

  ULONG64 rax;                  
  ULONG64 rcx;
  ULONG64 rdx;                 
  ULONG64 rbx;
  ULONG64 rsp;                  
  ULONG64 rbp;
  ULONG64 rsi;                  
  ULONG64 rdi;
  ULONG64 r8;                   
  ULONG64 r9;
  ULONG64 r10;                  
  ULONG64 r11;
  ULONG64 r12;                  
  ULONG64 r13;
  ULONG64 r14;                  
  ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;

USHORT _Cs();
USHORT _Ds();
USHORT _Es();
USHORT _Ss();
USHORT _Fs();
USHORT _Gs();
ULONG64 _Cr0();
ULONG64 _Cr2();
VOID _SetCr2(ULONG64 NewCr2);
ULONG64 _Cr3();
ULONG64 _Cr4();
VOID _SetCr4(ULONG32 mask);

ULONG64 _Cr8();
ULONG64 _Rflags();
ULONG64 _Rsp();

ULONG64 _IdtBase();
USHORT _IdtLimit();
ULONG64 _GdtBase();
USHORT _GdtLimit();
USHORT _Ldtr();

USHORT _TrSelector();

ULONG64 _Rbx();
ULONG64 _Rax();

ULONG64 _TSC();

ULONG64 _Dr0();
ULONG64 _Dr1();
ULONG64 _Dr2();
ULONG64 _Dr3();
ULONG64 _Dr6();
ULONG64 _SetDr0();
ULONG64 _SetDr1();
ULONG64 _SetDr2();
ULONG64 _SetDr3();
ULONG64 _SetDr6();

ULONG64 _SetCr3(PVOID NewCr3);
ULONG64 _SetCr8(ULONG64 NewCr8);

VOID _CpuId(ULONG32 fn, OUT PULONG32 ret_eax, OUT PULONG32 ret_ebx, OUT
        PULONG32 ret_ecx, OUT PULONG32 ret_edx);

ULONG64 _ReadMsr(ULONG32 reg);
ULONG64 Asm_ReadMsr(ULONG64 uIndex);
VOID _WriteMsr(ULONG32 reg, ULONG64 MsrValue);

VOID _VmxOn(PHYSICAL_ADDRESS PA);
VOID _VmxOff(ULONG64 Rip, ULONG64 Rsp);
ULONG64 _ReadVMCS(ULONG32 Encoding);
VOID _WriteVMCS(ULONG32 Encoding, ULONG64 Value);
VOID Vmx_VmWrite(ULONG64 uField, ULONG64 uValue);
VOID _VmPtrLd(PHYSICAL_ADDRESS PA);
VOID _VmClear(PHYSICAL_ADDRESS PA);
ULONG _VmLaunch();
VOID _VmResume();

ULONG32 _VmFailValid();
ULONG32 _VmFailInvalid();

VOID _GuestEntryPoint();
VOID _ExitHandler();
NTSTATUS _StartVirtualization();

VOID _StopVirtualization();
VOID _GuestExit();

VOID _Int3();
VOID _Invd();

VOID _InvalidatePage(ULONG64 Page);
VOID _SetInterrupts();
VOID _ClearInterrupts();

VOID _InitSpinLock(PULONG32 Lock);
VOID _AcquireSpinLock(PULONG32 Lock);
VOID _ReleaseSpinLock(PULONG32 Lock);
ULONG64 _GetMaxPhyaddr(INT8 CpuCap);

//VOID _RushTLB();
//VOID _EptInvept(int ext, VOID* addr);
VOID _spin_lock_release(KSPIN_LOCK* plock);
VOID _spin_lock_acquire(KSPIN_LOCK* plock);
VOID _spin_lock_init(KSPIN_LOCK* plock);

VOID _invept(ULONG64 ext,ULONG64 operand_addr);
VOID _invvpid(ULONG64 ext, ULONG64 operand_addr);

UINT16 hw_cpu_id(void);
VOID Asm_Rdtsc(ULONG64 p1, ULONG64 p2);

VOID _InitSplit(UINT32 vmcallcpde, UINT64 trans);
VOID _SetMeasure(UINT32 vmcallcpde, UINT64 b, UINT64 c);


////////////// VMX.H //////////////////

typedef union _SHORT_CPU
{
	struct {
		UINT8 LowPart;
		INT8 HighPart;
	};
	struct {
		UINT8 LowPart;
		INT8 HighPart;
	} u;
	ULONG32 QuadPart;
}SHORT_CPU;

typedef SHORT_CPU *LPSSHORT_CPU;

typedef struct _VIRT_CPU {
    PVOID Self;
    ULONG32 ProcessorNumber;
    PVOID VMXON_va;
    PHYSICAL_ADDRESS VMXON_pa;
    PVOID VMCS_va;
    PHYSICAL_ADDRESS VMCS_pa;
    PVOID HostKernelStackBase;
    PVOID MSR_bitmap_va;
    PHYSICAL_ADDRESS MSR_bitmap_pa;
	PVOID Ep4ta_Base_va;
	PHYSICAL_ADDRESS Ep4ta_Base_pa;
    ULONG32 State;
    ULONG32 Mailbox;
	VM_PHY_Address phys_pdpt, phys_pd, phys_pt;
	VM_Address pdpt, pd, pt;
	Bit64u temp64;
} VIRT_CPU, *PVIRT_CPU;

#define STATE_RUNNING 1
#define STATE_FROZEN 2
#define STATE_BREAKIN 3
#define STATE_DEBUGGED 4

#define IPI_FREEZE 1
#define IPI_FROZEN 2
#define IPI_RESUME 3
#define IPI_RUNNING 4

typedef enum _VMM_IA32_MODEL_SPECIFIC_REGISTERS {
	IA32_VMM_MSR_DEBUGCTL = 0,
	IA32_VMM_MSR_EFER,
	IA32_VMM_MSR_PAT,
	IA32_VMM_MSR_SYSENTER_ESP,
	IA32_VMM_MSR_SYSENTER_EIP,
	IA32_VMM_MSR_SYSENTER_CS,
	IA32_VMM_MSR_SMBASE,
	IA32_VMM_MSR_PERF_GLOBAL_CTRL,
	IA32_VMM_MSR_FEATURE_CONTROL,
	IA32_VMM_MSR_STAR,
	IA32_VMM_MSR_LSTAR,
	IA32_VMM_MSR_FMASK,
	IA32_VMM_MSR_FS_BASE,
	IA32_VMM_MSR_GS_BASE,
	IA32_VMM_MSR_KERNEL_GS_BASE,

	// the count of supported model specific registers
	IA32_VMM_MSR_COUNT
} VMM_IA32_MODEL_SPECIFIC_REGISTERS;


/*
 * VMX Exit Reasons
 */

#define VMX_EXIT_REASONS_FAILED_VMENTRY 0x80000000

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_INTERRUPT   7

#define EXIT_REASON_NMI_WINDOW          8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM					17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF               26
#define EXIT_REASON_VMXON                27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE       33
#define EXIT_REASON_MSR_LOADING       34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MACHINE_CHECK		  41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_EOI_INDUCED         45
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP				51
#define EXIT_REASON_PREEMPTION_TIMER    52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64


#define VMX_MAX_GUEST_VMEXIT	EXIT_REASON_TPR_BELOW_THRESHOLD

typedef struct _MOV_CR_QUALIFICATION {
    unsigned ControlRegister:4;
    unsigned AccessType:2;
    unsigned LMSWOperandType:1;
    unsigned Reserved1:1;
    unsigned Register:4;
    unsigned Reserved2:4;
    unsigned LMSWSourceData:16;
    unsigned Reserved3:32;
} MOV_CR_QUALIFICATION, *PMOV_CR_QUALIFICATION;

typedef struct _MOV_DR_QUALIFICATION {
	unsigned DebugRegIndex:3;
	unsigned Reserved1:1;
	unsigned DirectionAccess:1;
	unsigned Reserved2:3;
	unsigned GeneralReg:4;
	unsigned Reserved3:20;
	unsigned Reserved4:32;
} MOV_DR_QUALIFICATION, *PMOV_DR_QUALIFICATION;

typedef struct _INTERRUPT_INFO_FIELD {
    unsigned Vector:8;
    unsigned InterruptionType:3;
    unsigned ErrorCodeValid:1;
    unsigned NMIUnblocking:1;
    unsigned Reserved:18;
    unsigned Valid:1;
} INTERRUPT_INFO_FIELD, *PINTERRUPT_INFO_FIELD;

typedef struct _INTERRUPT_INJECT_INFO_FIELD{
    unsigned Vector:8;
    unsigned InterruptionType:3;
    unsigned DeliverErrorCode:1;
    unsigned Reserved:19;
    unsigned Valid:1;
} INTERRUPT_INJECT_INFO_FIELD, *PINTERRUPT_INJECT_INFO_FIELD;

typedef struct _DEBUG_EXIT_QUALIFICATION {
    unsigned B0:1;
    unsigned B1:1;
    unsigned B2:1;
    unsigned B3:1;
    unsigned Reserved:9;
    unsigned BD:1;
    unsigned BS:1;
    unsigned Reserved2:17;
    unsigned Reserved3:32;
} DEBUG_EXIT_QUALIFICATION, *PDEBUG_EXIT_QUALIFICATION;


#define MOV_TO_CR 0
#define MOV_FROM_CR 1
#define CLTS 2
#define LMSW 3
#define MOV_TO_DR 0
#define MOV_FROM_DR 1

#define CPU_BASED_VIRTUAL_INTR_PENDING  0x00000004
#define CPU_BASED_USE_TSC_OFFSETING     0x00000008
#define CPU_BASED_HLT_EXITING           0x00000080
#define CPU_BASED_INVDPG_EXITING        0x00000200
#define CPU_BASED_MWAIT_EXITING         0x00000400
#define CPU_BASED_RDPMC_EXITING         0x00000800
#define CPU_BASED_RDTSC_EXITING         0x00001000
#define CPU_BASED_CR8_LOAD_EXITING      0x00080000
#define CPU_BASED_CR8_STORE_EXITING     0x00100000
#define CPU_BASED_TPR_SHADOW            0x00200000
#define CPU_BASED_MOV_DR_EXITING        0x00800000
#define CPU_BASED_UNCOND_IO_EXITING     0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP    0x02000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP   0x10000000
#define CPU_BASED_MONITOR_EXITING       0x20000000
#define CPU_BASED_PAUSE_EXITING         0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define PIN_BASED_EXT_INTR_MASK         0x00000001
#define PIN_BASED_NMI_EXITING           0x00000008

#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000

#define VM_ENTRY_IA32E_MODE             0x00000200
#define VM_ENTRY_SMM                    0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR     0x00000800
/* VM-execution control bits */
#define CPU_BASED_PRIMARY_HLT            7
#define CPU_BASED_CR3_WRITE_EXIT        15
#define CPU_BASED_CR3_READ_EXIT         16        
#define CPU_BASED_PRIMARY_IO            25
#define CPU_BASED_USE_MSR_BITMAPS       28
#define CPU_BASED_PRIMARY_ACTIVATE_SEC  31

#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define SECONDARY_EXEC_ENABLE_RDTSCP            0x00000008
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define SECONDARY_EXEC_WBINVD_EXITING           0x00000040
#define SECONDARY_EXEC_UNRESTRICTED_GUEST       0x00000080
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING       0x00000400

/* VMCS Encodings */
enum {
	VIRTUAL_PROCESSOR_ID = 0x00000000,
    GUEST_ES_SELECTOR = 0x00000800,
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080a,
    GUEST_LDTR_SELECTOR = 0x0000080c,
    GUEST_TR_SELECTOR = 0x0000080e,
    HOST_ES_SELECTOR = 0x00000c00,
    HOST_CS_SELECTOR = 0x00000c02,
    HOST_SS_SELECTOR = 0x00000c04,
    HOST_DS_SELECTOR = 0x00000c06,
    HOST_FS_SELECTOR = 0x00000c08,
    HOST_GS_SELECTOR = 0x00000c0a,
    HOST_TR_SELECTOR = 0x00000c0c,
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_A_HIGH = 0x00002001,
    IO_BITMAP_B = 0x00002002,
    IO_BITMAP_B_HIGH = 0x00002003,
    MSR_BITMAP = 0x00002004,
    MSR_BITMAP_HIGH = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
    TSC_OFFSET = 0x00002010,
    TSC_OFFSET_HIGH = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
	APIC_ACCESS_ADDR_FULL = 0x00002014,
	APIC_ACCESS_ADDR_HIGH = 0x00002015,
	POSTED_INTERRUPT_DESCRIPTION_ADDR_FULL = 0x00002016,
	POSTED_INTERRUPT_DESCRIPTION_ADDR_HIGH= 0x00002017,
	VM_FUNCTION_CTRL_FULL= 0x00002018,
	VM_FUNCTION_CTRL_HIGH= 0x00002019,
	EPT_POINTER_FULL= 0x0000201A,
	EPT_POINTER_HIGH= 0x0000201B,
	EOI_EXIT_BITMAP_0_FULL= 0x0000201C,
	EOI_EXIT_BITMAP_0_HIGH= 0x0000201D,
	EOI_EXIT_BITMAP_1_FULL= 0x0000201E,
	EOI_EXIT_BITMAP_1_HIGH= 0x0000201F,
	EOI_EXIT_BITMAP_2_FULL= 0x00002020,
	EOI_EXIT_BITMAP_2_HIGH= 0x00002021,
	EOI_EXIT_BITMAP_3_FULL= 0x00002022,
	EOI_EXIT_BITMAP_3_HIGH= 0x00002023,
	EPTP_LIST_ADDRESS_FULL= 0x00002024,
	EPTP_LIST_ADDRESS_HIGH= 0x00002025,
	VMREAD_BITMAP_ADDRESS_FULL= 0x00002026,
	VMREAD_BITMAP_ADDRESS_HIGH= 0x00002027,
	VMWRITE_BITMAP_ADDRESS_FULL= 0x00002028,
	VMWRITE_BITMAP_ADDRESS_HIGH= 0x00002029,
	VE_INFO_ADDRESS_FULL= 0x0000202A,
	VE_INFO_ADDRESS_HIGH= 0x0000202B,

	//64 - bit read - only fields
	GUEST_PHYSICAL_ADDR_FULL= 0x00002400,
	GUEST_PHYSICAL_ADDR_HIGH= 0x00002401,

	//64 - bit guest - state fields
	VMCS_LINK_PTR_FULL= 0x00002800,
	VMCS_LINK_PTR_HIGH= 0x00002801,
	GUEST_IA32_DEBUGCTL_FULL= 0x00002802,
	GUEST_IA32_DEBUGCTL_HIGH= 0x00002803,
	GUEST_IA32_PAT_FULL= 0x00002804,
	GUEST_IA32_PAT_HIGH= 0x00002805,
	GUEST_IA32_EFER_FULL= 0x00002806,
	GUEST_IA32_EFER_HIGH= 0x00002807,
	GUEST_IA32_PERF_CTL_FULL= 0x00002808,
	GUEST_IA32_PERF_CTL_HIGH= 0x00002809,
	GUEST_PDPTE0_FULL= 0x0000280A,
	GUEST_PDPTE0_HIGH= 0x0000280B,
	GUEST_PDPTE1_FULL= 0x0000280C,
	GUEST_PDPTE1_HIGH= 0x0000280D,
	GUEST_PDPTE2_FULL= 0x0000280E,
	GUEST_PDPTE2_HIGH= 0x0000280F,
	GUEST_PDPTE3_FULL= 0x00002810,
	GUEST_PDPTE3_HIGH= 0x00002811,

	//64 - bit host - state fields
	HOST_IA32_PAT_FULL= 0x00002C00,
	HOST_IA32_PAT_HIGH= 0x00002C01,
	HOST_IA32_EFER_FULL= 0x00002C02,
	HOST_IA32_EFER_HIGH= 0x00002C03,
	HOST_IA32_PERF_CTL_FULL= 0x00002C04,
	HOST_IA32_PERF_CTL_HIGH= 0x00002C05,
/*
    VMCS_LINK_POINTER = 0x00002800,
    VMCS_LINK_POINTER_HIGH = 0x00002801,
    GUEST_IA32_DEBUGCTL = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,*/
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
    GUEST_ES_LIMIT = 0x00004800,
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480a,
    GUEST_LDTR_LIMIT = 0x0000480c,
    GUEST_TR_LIMIT = 0x0000480e,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_AR_BYTES = 0x00004814,
    GUEST_CS_AR_BYTES = 0x00004816,
    GUEST_SS_AR_BYTES = 0x00004818,
    GUEST_DS_AR_BYTES = 0x0000481a,
    GUEST_FS_AR_BYTES = 0x0000481c,
    GUEST_GS_AR_BYTES = 0x0000481e,
    GUEST_LDTR_AR_BYTES = 0x00004820,
    GUEST_TR_AR_BYTES = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_SM_BASE = 0x00004828,
    GUEST_SYSENTER_CS = 0x0000482A,
    HOST_IA32_SYSENTER_CS = 0x00004c00,
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
    EXIT_QUALIFICATION = 0x00006400,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
    GUEST_CR0 = 0x00006800,
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680a,
    GUEST_DS_BASE = 0x0000680c,
    GUEST_FS_BASE = 0x0000680e,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681a,
    GUEST_RSP = 0x0000681c,
    GUEST_RIP = 0x0000681e,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
    GUEST_SYSENTER_ESP = 0x00006824,
    GUEST_SYSENTER_EIP = 0x00006826,
    HOST_CR0 = 0x00006c00,
    HOST_CR3 = 0x00006c02,
    HOST_CR4 = 0x00006c04,
    HOST_FS_BASE = 0x00006c06,
    HOST_GS_BASE = 0x00006c08,
    HOST_TR_BASE = 0x00006c0a,
    HOST_GDTR_BASE = 0x00006c0c,
    HOST_IDTR_BASE = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP = 0x00006c10,
    HOST_IA32_SYSENTER_EIP = 0x00006c12,
    HOST_RSP = 0x00006c14,
    HOST_RIP = 0x00006c16,
};

typedef struct {
    ULONG64 GUEST_ES_SELECTOR;
    ULONG64 GUEST_CS_SELECTOR;
    ULONG64 GUEST_SS_SELECTOR;
    ULONG64 GUEST_DS_SELECTOR;
    ULONG64 GUEST_FS_SELECTOR;
    ULONG64 GUEST_GS_SELECTOR;
    ULONG64 GUEST_LDTR_SELECTOR;
    ULONG64 GUEST_TR_SELECTOR;
    ULONG64 HOST_ES_SELECTOR;
    ULONG64 HOST_CS_SELECTOR;
    ULONG64 HOST_SS_SELECTOR;
    ULONG64 HOST_DS_SELECTOR;
    ULONG64 HOST_FS_SELECTOR;
    ULONG64 HOST_GS_SELECTOR;
    ULONG64 HOST_TR_SELECTOR;
    ULONG64 IO_BITMAP_A;
    ULONG64 IO_BITMAP_A_HIGH;
    ULONG64 IO_BITMAP_B;
    ULONG64 IO_BITMAP_B_HIGH;
    ULONG64 MSR_BITMAP;
    ULONG64 MSR_BITMAP_HIGH;
    ULONG64 VM_EXIT_MSR_STORE_ADDR;
    ULONG64 VM_EXIT_MSR_STORE_ADDR_HIGH;
    ULONG64 VM_EXIT_MSR_LOAD_ADDR;
    ULONG64 VM_EXIT_MSR_LOAD_ADDR_HIGH;
    ULONG64 VM_ENTRY_MSR_LOAD_ADDR;
    ULONG64 VM_ENTRY_MSR_LOAD_ADDR_HIGH;
    ULONG64 TSC_OFFSET;
    ULONG64 TSC_OFFSET_HIGH;
    ULONG64 VIRTUAL_APIC_PAGE_ADDR;
    ULONG64 VIRTUAL_APIC_PAGE_ADDR_HIGH;
	ULONG64 VMCS_LINK_PTR_FULL;
	ULONG64 VMCS_LINK_PTR_HIGH;
	ULONG64 GUEST_IA32_DEBUGCTL_FULL;
    ULONG64 GUEST_IA32_DEBUGCTL_HIGH;
    ULONG64 PIN_BASED_VM_EXEC_CONTROL;
    ULONG64 CPU_BASED_VM_EXEC_CONTROL;
    ULONG64 EXCEPTION_BITMAP;
    ULONG64 PAGE_FAULT_ERROR_CODE_MASK;
    ULONG64 PAGE_FAULT_ERROR_CODE_MATCH;
    ULONG64 CR3_TARGET_COUNT;
    ULONG64 VM_EXIT_CONTROLS;
    ULONG64 VM_EXIT_MSR_STORE_COUNT;
    ULONG64 VM_EXIT_MSR_LOAD_COUNT;
    ULONG64 VM_ENTRY_CONTROLS;
    ULONG64 VM_ENTRY_MSR_LOAD_COUNT;
    ULONG64 VM_ENTRY_INTR_INFO_FIELD;
    ULONG64 VM_ENTRY_EXCEPTION_ERROR_CODE;
    ULONG64 VM_ENTRY_INSTRUCTION_LEN;
    ULONG64 TPR_THRESHOLD;
    ULONG64 SECONDARY_VM_EXEC_CONTROL;
    ULONG64 VM_INSTRUCTION_ERROR;
    ULONG64 VM_EXIT_REASON;
    ULONG64 VM_EXIT_INTR_INFO;
    ULONG64 VM_EXIT_INTR_ERROR_CODE;
    ULONG64 IDT_VECTORING_INFO_FIELD;
    ULONG64 IDT_VECTORING_ERROR_CODE;
    ULONG64 VM_EXIT_INSTRUCTION_LEN;
    ULONG64 VMX_INSTRUCTION_INFO;
    ULONG64 GUEST_ES_LIMIT;
    ULONG64 GUEST_CS_LIMIT;
    ULONG64 GUEST_SS_LIMIT;
    ULONG64 GUEST_DS_LIMIT;
    ULONG64 GUEST_FS_LIMIT;
    ULONG64 GUEST_GS_LIMIT;
    ULONG64 GUEST_LDTR_LIMIT;
    ULONG64 GUEST_TR_LIMIT;
    ULONG64 GUEST_GDTR_LIMIT;
    ULONG64 GUEST_IDTR_LIMIT;
    ULONG64 GUEST_ES_AR_BYTES;
    ULONG64 GUEST_CS_AR_BYTES;
    ULONG64 GUEST_SS_AR_BYTES;
    ULONG64 GUEST_DS_AR_BYTES;
    ULONG64 GUEST_FS_AR_BYTES;
    ULONG64 GUEST_GS_AR_BYTES;
    ULONG64 GUEST_LDTR_AR_BYTES;
    ULONG64 GUEST_TR_AR_BYTES;
    ULONG64 GUEST_INTERRUPTIBILITY_INFO;
    ULONG64 GUEST_ACTIVITY_STATE;
    ULONG64 GUEST_SM_BASE;
    ULONG64 GUEST_SYSENTER_CS;
    ULONG64 HOST_IA32_SYSENTER_CS;
    ULONG64 CR0_GUEST_HOST_MASK;
    ULONG64 CR4_GUEST_HOST_MASK;
    ULONG64 CR0_READ_SHADOW;
    ULONG64 CR4_READ_SHADOW;
    ULONG64 CR3_TARGET_VALUE0;
    ULONG64 CR3_TARGET_VALUE1;
    ULONG64 CR3_TARGET_VALUE2;
    ULONG64 CR3_TARGET_VALUE3;
    ULONG64 EXIT_QUALIFICATION;
    ULONG64 GUEST_LINEAR_ADDRESS;
    ULONG64 GUEST_CR0;
    ULONG64 GUEST_CR3;
    ULONG64 GUEST_CR4;
    ULONG64 GUEST_ES_BASE;
    ULONG64 GUEST_CS_BASE;
    ULONG64 GUEST_SS_BASE;
    ULONG64 GUEST_DS_BASE;
    ULONG64 GUEST_FS_BASE;
    ULONG64 GUEST_GS_BASE;
    ULONG64 GUEST_LDTR_BASE;
    ULONG64 GUEST_TR_BASE;
    ULONG64 GUEST_GDTR_BASE;
    ULONG64 GUEST_IDTR_BASE;
    ULONG64 GUEST_DR7;
    ULONG64 GUEST_RSP;
    ULONG64 GUEST_RIP;
    ULONG64 GUEST_RFLAGS;
    ULONG64 GUEST_PENDING_DBG_EXCEPTIONS;
    ULONG64 GUEST_SYSENTER_ESP;
    ULONG64 GUEST_SYSENTER_EIP;
    ULONG64 HOST_CR0;
    ULONG64 HOST_CR3;
    ULONG64 HOST_CR4;
    ULONG64 HOST_FS_BASE;
    ULONG64 HOST_GS_BASE;
    ULONG64 HOST_TR_BASE;
    ULONG64 HOST_GDTR_BASE;
    ULONG64 HOST_IDTR_BASE;
    ULONG64 HOST_IA32_SYSENTER_ESP;
    ULONG64 HOST_IA32_SYSENTER_EIP;
    ULONG64 HOST_RSP;
    ULONG64 HOST_RIP;
} VMCS, *PVMCS;


/*
//eptp
*/
#define MEM_TYPE_UC                                     0
#define MEM_TYPE_WB                                     6
#define MEM_TYPE_WT                                     4
#define MEM_TYPE_WP                                     5
#define MEM_TYPE_WC                                     1

//
// EPT 页结构内存类型
//
#define EPT_MEM_WB							(MEM_TYPE_WB << 3)
#define EPT_MEM_UC							(MEM_TYPE_UC << 3)
#define EPT_MEM_WT							(MEM_TYPE_WT << 3)
#define EPT_MEM_WP							(MEM_TYPE_WP << 3)
#define EPT_MEM_WC							(MEM_TYPE_WC << 3)