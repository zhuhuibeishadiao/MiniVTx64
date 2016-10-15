#pragma once
#ifndef INTEL_VT_X64_H
#define INTEL_VT_X64_H
//#define _EPT

#define FLAGS_RF_MASK (1 << 16)

#include "def.h"
#include "ept1.h"
#include "procmon.h"
//#include "paging.h"


static KMUTEX g_mutex;
static LONG g_processors;
static ULONG32 vis_concealed = FALSE;

PVIRT_CPU *g_cpus;

LONG g_Initialized;
extern PHYSICAL_ADDRESS g_PageMapBasePhysicalAddress;

typedef union {
	struct {
		UINT8 mmm : 3, // RM
			  rrr : 3, // REG
			  oo : 2; // Mod
	};
	UINT8 value;
} modrm_t;

typedef union {
	struct {
		UINT8 base : 3,
			  index : 3,
			  scale : 2;
	};
	UINT8 value;
} sib_t;

typedef union _VMX_SECONDARY_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 VirtualizeAPICAccesses : 1;      // [0]
		ULONG32 EnableEPT : 1;                   // [1]
		ULONG32 DescriptorTableExiting : 1;      // [2]
		ULONG32 EnableRDTSCP : 1;                // [3]
		ULONG32 VirtualizeX2APICMode : 1;        // [4]
		ULONG32 EnableVPID : 1;                  // [5]
		ULONG32 WBINVDExiting : 1;               // [6]
		ULONG32 UnrestrictedGuest : 1;           // [7]
		ULONG32 APICRegisterVirtualization : 1;  // [8]
		ULONG32 VirtualInterruptDelivery : 1;    // [9]
		ULONG32 PAUSELoopExiting : 1;            // [10]
		ULONG32 RDRANDExiting : 1;               // [11]
		ULONG32 EnableINVPCID : 1;               // [12]
		ULONG32 EnableVMFunctions : 1;           // [13]
		ULONG32 VMCSShadowing : 1;               // [14]
		ULONG32 Reserved1 : 1;                   // [15]
		ULONG32 RDSEEDExiting : 1;               // [16]
		ULONG32 Reserved2 : 1;                   // [17]
		ULONG32 EPTViolation : 1;                // [18]
		ULONG32 Reserved3 : 1;                   // [19]
		ULONG32 EnableXSAVESXSTORS : 1;          // [20]
	} Fields;
} VMX_SECONDARY_CPU_BASED_CONTROLS, *PVMX_SECONDARY_CPU_BASED_CONTROLS;

typedef union _VMX_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                 // [0-1]
		ULONG32 InterruptWindowExiting : 1;    // [2]
		ULONG32 UseTSCOffseting : 1;           // [3]
		ULONG32 Reserved2 : 3;                 // [4-6]
		ULONG32 HLTExiting : 1;                // [7]
		ULONG32 Reserved3 : 1;                 // [8]
		ULONG32 INVLPGExiting : 1;             // [9]
		ULONG32 MWAITExiting : 1;              // [10]
		ULONG32 RDPMCExiting : 1;              // [11]
		ULONG32 RDTSCExiting : 1;              // [12]
		ULONG32 Reserved4 : 2;                 // [13-14]
		ULONG32 CR3LoadExiting : 1;            // [15]
		ULONG32 CR3StoreExiting : 1;           // [16]
		ULONG32 Reserved5 : 2;                 // [17-18]
		ULONG32 CR8LoadExiting : 1;            // [19]
		ULONG32 CR8StoreExiting : 1;           // [20]
		ULONG32 UseTPRShadowExiting : 1;       // [21]
		ULONG32 NMIWindowExiting : 1;          // [22]
		ULONG32 MovDRExiting : 1;              // [23]
		ULONG32 UnconditionalIOExiting : 1;    // [24]
		ULONG32 UseIOBitmaps : 1;              // [25]
		ULONG32 Reserved6 : 1;                 // [26]
		ULONG32 MonitorTrapFlag : 1;           // [27]
		ULONG32 UseMSRBitmaps : 1;             // [28]
		ULONG32 MONITORExiting : 1;            // [29]
		ULONG32 PAUSEExiting : 1;              // [30]
		ULONG32 ActivateSecondaryControl : 1;  // [31]
	} Fields;
} VMX_CPU_BASED_CONTROLS, *PVMX_CPU_BASED_CONTROLS;

typedef union _IA32_VMX_PROCBASED_CTLS2_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved0 : 32;                 // [0-31]
		ULONG64 VirtualizeAPICAccesses : 1;     // [32 + 0]
		ULONG64 EnableEPT : 1;                  // [32 + 1]
		ULONG64 DescriptorTableExiting : 1;     // [32 + 2]
		ULONG64 EnableRDTSCP : 1;               // [32 + 3]
		ULONG64 VirtualizeX2APICMode : 1;       // [32 + 4]
		ULONG64 EnableVPID : 1;                 // [32 + 5]
		ULONG64 WBINVDExiting : 1;              // [32 + 6]
		ULONG64 UnrestrictedGuest : 1;          // [32 + 7]
		ULONG64 APICRegisterVirtualization : 1; // [32 + 8]
		ULONG64 VirtualInterruptDelivery : 1;   // [32 + 9]
		ULONG64 PAUSELoopExiting : 1;           // [32 + 10]
		ULONG64 RDRANDExiting : 1;              // [32 + 11]
		ULONG64 EnableINVPCID : 1;              // [32 + 12]
		ULONG64 EnableVMFunctions : 1;          // [32 + 13]
		ULONG64 VMCSShadowing : 1;              // [32 + 14]
		ULONG64 Reserved1 : 1;                  // [32 + 15]
		ULONG64 RDSEEDExiting : 1;              // [32 + 16]
		ULONG64 Reserved2 : 1;                  // [32 + 17]
		ULONG64 EPTViolation : 1;               // [32 + 18]
		ULONG64 Reserved3 : 1;                  // [32 + 19]
		ULONG64 EnableXSAVESXSTORS : 1;         // [32 + 20]
	} Fields;
} IA32_VMX_PROCBASED_CTLS2_MSR, *PIA32_VMX_PROCBASED_CTLS2_MSR;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS NTAPI CmGetPagePTEAddress(
	PVOID Page,
	PULONG64 * pPagePTE,
	PHYSICAL_ADDRESS * pPA
	)
{
	ULONG64 Pml4e, Pdpe, Pde, Pte, PA;
	ULONG64 PageVA = (ULONG64)Page;

	if (!Page || !pPagePTE)
		return STATUS_INVALID_PARAMETER;

	*pPagePTE = NULL;

	Pml4e = *(PULONG64)(((PageVA >> 36) & 0xff8) + PML4_BASE);
	if (!(Pml4e & 1))
		// pml4e not present
		return STATUS_NO_MEMORY;

	Pdpe = *(PULONG64)(((PageVA >> 27) & 0x1ffff8) + PDP_BASE);
	if (!(Pdpe & 1))
		// pdpe not present
		return STATUS_NO_MEMORY;

	Pde = *(PULONG64)(((PageVA >> 18) & 0x3ffffff8) + PD_BASE);
	if (!(Pde & 1))
		// pde not present
		return STATUS_NO_MEMORY;

	if ((Pde & 0x81) == 0x81) {
		// 2-mbyte pde
		PA = ((((PageVA >> 12) & 0x1ff) + ((Pde >> 12) & 0xfffffff)) << 12) + (PageVA & 0xfff);

		if (pPA)
			(*pPA).QuadPart = PA;

		return STATUS_UNSUCCESSFUL;
	}

	Pte = *(PULONG64)(((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);
	if (!(Pte & 1))
		// pte not present
		return STATUS_NO_MEMORY;

	*pPagePTE = (PULONG64)(((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);

	PA = (((Pte >> 12) & 0xfffffff) << 12) + (PageVA & 0xfff);
	if (pPA)
		(*pPA).QuadPart = PA;

	return STATUS_SUCCESS;
}

BOOLEAN IsBitSet(ULONG64 v, UCHAR bitNo)
{
	ULONG64 mask = (ULONG64)1 << bitNo;
	return (BOOLEAN)((v & mask) != 0);
}


PVOID AllocateMemory(ULONG32 Size)
{
	PVOID pMem = NULL;
	pMem = ExAllocatePoolWithTag(NonPagedPool, Size, VIRTDBG_POOLTAG);
	if (pMem == NULL)
		return NULL;

	RtlZeroMemory(pMem, Size);
	return pMem;
}

VOID UnAllocateMemory(PVOID pMem)
{
	ExFreePoolWithTag(pMem, VIRTDBG_POOLTAG);
}

PVOID AllocateContiguousMemory(ULONG size)
{
	PVOID Address;
	PHYSICAL_ADDRESS l1, l2, l3;

	l1.QuadPart = 0;
	l2.QuadPart = -1;
	l3.QuadPart = 0x200000;

	Address = MmAllocateContiguousMemorySpecifyCache(size, l1, l2, l3, MmCached);
	//Address = MmAllocateContiguousMemorySpecifyCache(4*0x1000, l1, l2, l3, MmCached);

	if (Address == NULL)
	{
		return NULL;
	}

	RtlZeroMemory(Address, size);
	//RtlZeroMemory(Address, 4*0x1000);
	return Address;
}


NTSTATUS CheckForVirtualizationSupport()
{
	ULONG32 eax, ebx, ecx, edx;
	/* vmx supported by cpu ? */
	_CpuId(0, &eax, &ebx, &ecx, &edx);
	if (eax < 1)
	{
		FGP_VT_KDPRINT(("error: extended CPUID functions not implemented\n"));
		return STATUS_UNSUCCESSFUL;
	}

	/* Intel Genuine */
	if (!(ebx == 0x756e6547 && ecx == 0x6c65746e && edx == 0x49656e69))
	{
		FGP_VT_KDPRINT(("error: not an INTEL processor\n"));
		return STATUS_UNSUCCESSFUL;
	}

	_CpuId(0x1, &eax, &ebx, &ecx, &edx);
	if (!IsBitSet(ecx, 5))
	{
		FGP_VT_KDPRINT(("error: VMX not supported\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}



NTSTATUS VtStart(PVOID StartContext)
{
	NTSTATUS Status;
	CCHAR i;
	KIRQL OldIrql;
	KAFFINITY OldAffinity;

	//InitLog();

	Status = CheckForVirtualizationSupport();
	if (Status == STATUS_UNSUCCESSFUL)
	{
		FGP_VT_KDPRINT(("aborting, no virtualisation support\n"));
		return STATUS_UNSUCCESSFUL;
	}

	KeInitializeMutex(&g_mutex, 0);
	KeWaitForSingleObject(&g_mutex, Executive, KernelMode, FALSE, NULL);
	FGP_VT_KDPRINT(("virtualizing %d processors ...\n", KeNumberProcessors));

	g_cpus = ExAllocatePoolWithTag(NonPagedPool, KeNumberProcessors*sizeof(PVIRT_CPU), 0x42424242);

	if (!g_cpus)
	{
		FGP_VT_KDPRINT(("can't allocate cpus array\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	FGP_VT_KDPRINT(("Allocated g_cpus array @ 0x%llx, size=0x%x\n", g_cpus, KeNumberProcessors*sizeof(PVIRT_CPU)));
	RtlZeroMemory(g_cpus, KeNumberProcessors*sizeof(PVIRT_CPU));

	//InitControlArea();
	//InitDebugLayer();
	//InitProtocolLayer(g_SendArea, g_RecvArea);
	//
	// 遍历所有处理器
	//
	for (i = 0; i < KeNumberProcessors; i++)
	{
		OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1 << i));
		OldIrql = KeRaiseIrqlToDpcLevel();
		_StartVirtualization();
		KeLowerIrql(OldIrql);
		KeRevertToUserAffinityThreadEx(OldAffinity);
	}

	FGP_VT_KDPRINT(("all done...\n"));

	KeReleaseMutex(&g_mutex, FALSE);

	if (KeNumberProcessors != g_processors)
	{
		FGP_VT_KDPRINT(("aborting, not all processors are virtualized\n"));
		return STATUS_UNSUCCESSFUL;
	}

	InterlockedIncrement(&g_Initialized);

	/*    for (i = 0; i < KeNumberProcessors; i++)*/
	/*    {*/
	/*        DumpVirtCpu(g_cpus[i]);*/
	/*    }*/

	return STATUS_SUCCESS;

}

NTSTATUS ResumeGuest()
{
	FGP_VT_KDPRINT(("Resuming guest...\n"));
	return STATUS_SUCCESS;
}


NTSTATUS CheckIfVMXIsEnabled()
{
	ULONG64 cr4, msr;

	/* vmxon supported ? */
	_SetCr4(X86_CR4_VMXE);
	cr4 = _Cr4();

	if (!(cr4 & X86_CR4_VMXE))
	{
		FGP_VT_KDPRINT(("error: VMXON not supported\n"));
		return STATUS_UNSUCCESSFUL;
	}

	/* vmx desactived by bios ? */
	msr = _ReadMsr(MSR_IA32_FEATURE_CONTROL);
	if (!(msr & 4))
	{
		FGP_VT_KDPRINT(("vmx is disabled in bios: MSR_IA32_FEATURE_CONTROL is 0x%llx\n", msr));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


NTSTATUS SetupVMX(PVIRT_CPU pCpu)
{
	PHYSICAL_ADDRESS pa;
	ULONG64 msr;
	PVMX_BASIC_MSR pvmx;
	ULONG32 i;
	PVOID va;
	ULONG size;

	i = KeGetCurrentProcessorNumber();

	pCpu->ProcessorNumber = i;
	msr = _ReadMsr(MSR_IA32_VMX_BASIC);
	pvmx = (PVMX_BASIC_MSR)&msr;

	size = pvmx->szVmxOnRegion;

	FGP_VT_KDPRINT(("VMXON region size: 0x%x\n", size));
	FGP_VT_KDPRINT(("VMX revision ID: 0x%x\n", pvmx->RevId));

	va = AllocateContiguousMemory(/*size*/0x4000);

	if (va == NULL)
	{
		FGP_VT_KDPRINT(("error: can't allocate vmxon region\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	*(ULONG32 *)va = pvmx->RevId;
	pa = MmGetPhysicalAddress(va);

	_VmxOn(pa);
	InvVpidAllContext();
	if (_VmFailInvalid())
	{
		FGP_VT_KDPRINT(("_VmxOn failed\n"));
		return STATUS_UNSUCCESSFUL;
	}

	pCpu->VMXON_va = va;
	pCpu->VMXON_pa = pa;
	FGP_VT_KDPRINT(("VMON 内存虚拟地址 %llx\n", va));
	FGP_VT_KDPRINT(("VMON 物理地址 %llx\n", pa));

	va = AllocateContiguousMemory(/*size*/0x4000);

	if (va == NULL)
	{
		FGP_VT_KDPRINT(("error: can't allocate vmcs region\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	*(ULONG32 *)va = pvmx->RevId;
	pa = MmGetPhysicalAddress(va);

	pCpu->VMCS_va = va;
	pCpu->VMCS_pa = pa;
	FGP_VT_KDPRINT(("VMCS 内存虚拟地址 %llx\n", va));
	FGP_VT_KDPRINT(("VMCS 物理地址 %llx\n", pa));

	va = AllocateContiguousMemory(0x1000);
	pa = MmGetPhysicalAddress(va);

	if (va == NULL)
	{
		FGP_VT_KDPRINT(("error: can't allocate msr bitmap\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	pCpu->MSR_bitmap_va = va;
	pCpu->MSR_bitmap_pa = pa;

	return STATUS_SUCCESS;
}



NTSTATUS InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector,
	USHORT Selector, PUCHAR GdtBase)
{
	PSEGMENT_DESCRIPTOR SegDesc;
	ULONG64 tmp;

	if (!SegmentSelector)
		return STATUS_INVALID_PARAMETER;

	if (Selector & 0x4) {
		FGP_VT_KDPRINT(("InitializeSegmentSelector(): Given selector (0x%X) points to LDT\n", Selector));
		return STATUS_INVALID_PARAMETER;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->sel = Selector;
	SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
	SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
	SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

	if (!(SegDesc->attr0 & LA_STANDARD)) {
		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->attributes.fields.g) {
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
	}

	return STATUS_SUCCESS;
}


NTSTATUS FillGuestSelectorData(PVOID GdtBase, ULONG Segreg, USHORT
	Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG uAccessRights;

	InitializeSegmentSelector(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)& SegmentSelector.attributes)[0] + (((PUCHAR)&
		SegmentSelector.attributes)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	_WriteVMCS(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	_WriteVMCS(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.limit);
	_WriteVMCS(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);

	if ((Segreg == LDTR) || (Segreg == TR))
		// don't setup for FS/GS - their bases are stored in MSR values
		_WriteVMCS(GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);

	return STATUS_SUCCESS;
}

ULONG32 AdjustControls(ULONG32 Ctl, ULONG32 Msr)
{
	LARGE_INTEGER MsrValue;
	MsrValue.QuadPart = _ReadMsr(Msr);
	FGP_VT_KDPRINT(("Adjusting control for msr 0x%x\n", Msr));
	FGP_VT_KDPRINT(("Adjusting controls (low): 0x%08x\n", MsrValue.LowPart));
	FGP_VT_KDPRINT(("Adjusting controls (high): 0x%08x\n", MsrValue.HighPart));
	Ctl &= MsrValue.HighPart;
	Ctl |= MsrValue.LowPart;
	return Ctl;
}

ULONG VmxpAdjustMsr(IN LARGE_INTEGER ControlValue, ULONG DesiredValue)
{
	// VMX feature/capability MSRs encode the "must be 0" bits in the high word
	// of their value, and the "must be 1" bits in the low word of their value.
	// Adjust any requested capability/feature based on these requirements.
	DesiredValue &= ControlValue.HighPart;
	DesiredValue |= ControlValue.LowPart;
	return DesiredValue;
}

ULONG NTAPI VmxAdjustControls(
	ULONG64 Ctl,
	ULONG64 Msr
)
{
	LARGE_INTEGER MsrValue;

	MsrValue.QuadPart = Asm_ReadMsr(Msr);
	Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

NTSTATUS SetupVMCS(PVIRT_CPU pCpu, PVOID GuestRsp)
{
	ULONG32 ExceptionBitmap;
	ULONG64 Interceptions;
	PVOID GdtBase;
	SEGMENT_SELECTOR SegmentSelector;
	ULONG32 i;
	PHYSICAL_ADDRESS pa;
	NTSTATUS Status;
	LARGE_INTEGER Eptp = { 0 };
	LARGE_INTEGER CTLS = { 0 };
	VMX_SECONDARY_CPU_BASED_CONTROLS vmCpuCtl2Requested = { 0 };
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
	

	i = KeGetCurrentProcessorNumber();
	FGP_VT_KDPRINT(("GuestRsp=%p\n", GuestRsp));

	pa = pCpu->VMCS_pa;
	FGP_VT_KDPRINT(("VMCS PHYSICAL_ADDRESS %llx\n", pa));
	_VmClear(pa);
	_VmPtrLd(pa);

	_WriteVMCS(GUEST_CR0, _Cr0());

	_WriteVMCS(GUEST_CR3, _Cr3());

	_WriteVMCS(GUEST_CR4, _Cr4());
	_WriteVMCS(GUEST_DR7, X86_DR7_INIT_VAL);
	_WriteVMCS(GUEST_RSP, (ULONG64)GuestRsp);
	_WriteVMCS(GUEST_RIP, (ULONG64)_GuestEntryPoint);
	_WriteVMCS(GUEST_RFLAGS, _Rflags());

	GdtBase = (PVOID)_GdtBase();
	FillGuestSelectorData(GdtBase, ES, _Es());
	FillGuestSelectorData(GdtBase, CS, _Cs());
	FillGuestSelectorData(GdtBase, SS, _Ss());
	FillGuestSelectorData(GdtBase, DS, _Ds());
	FillGuestSelectorData(GdtBase, FS, _Fs());
	FillGuestSelectorData(GdtBase, GS, _Gs());
	FillGuestSelectorData(GdtBase, LDTR, _Ldtr());
	FillGuestSelectorData(GdtBase, TR, _TrSelector());
	_WriteVMCS(GUEST_ES_BASE, 0);
	_WriteVMCS(GUEST_CS_BASE, 0);
	_WriteVMCS(GUEST_SS_BASE, 0);
	_WriteVMCS(GUEST_DS_BASE, 0);
	_WriteVMCS(GUEST_FS_BASE, _ReadMsr(MSR_FS_BASE));
	_WriteVMCS(GUEST_GS_BASE, _ReadMsr(MSR_GS_BASE));
	_WriteVMCS(GUEST_GDTR_BASE, (ULONG64)GdtBase);
	_WriteVMCS(GUEST_IDTR_BASE, _IdtBase());
	_WriteVMCS(GUEST_GDTR_LIMIT, _GdtLimit());
	_WriteVMCS(GUEST_IDTR_LIMIT, _IdtLimit());

	_WriteVMCS(GUEST_IA32_DEBUGCTL_FULL, _ReadMsr(MSR_IA32_DEBUGCTL) & 0xffffffff);
	_WriteVMCS(GUEST_IA32_DEBUGCTL_HIGH, _ReadMsr(MSR_IA32_DEBUGCTL) >> 32);
	_WriteVMCS(GUEST_SYSENTER_CS, _ReadMsr(MSR_IA32_SYSENTER_CS));
	_WriteVMCS(GUEST_SYSENTER_ESP, _ReadMsr(MSR_IA32_SYSENTER_ESP));
	_WriteVMCS(GUEST_SYSENTER_EIP, _ReadMsr(MSR_IA32_SYSENTER_EIP));

	/* guest non register state */
	_WriteVMCS(GUEST_INTERRUPTIBILITY_INFO, 0);
	_WriteVMCS(GUEST_ACTIVITY_STATE, 0);
	_WriteVMCS(VMCS_LINK_PTR_FULL, 0xffffffff);
	_WriteVMCS(VMCS_LINK_PTR_HIGH, 0xffffffff);

	/* host state area */
	_WriteVMCS(HOST_CR0, _Cr0());
	_WriteVMCS(HOST_CR3, _Cr3());
	_WriteVMCS(HOST_CR4, _Cr4());
	_WriteVMCS(HOST_RSP, (ULONG64)pCpu);
	_WriteVMCS(HOST_RIP, (ULONG64)_ExitHandler);

	_WriteVMCS(HOST_ES_SELECTOR, KGDT64_R0_DATA);
	_WriteVMCS(HOST_CS_SELECTOR, KGDT64_R0_CODE);
	_WriteVMCS(HOST_SS_SELECTOR, KGDT64_R0_DATA);
	_WriteVMCS(HOST_DS_SELECTOR, KGDT64_R0_DATA);
	_WriteVMCS(HOST_FS_SELECTOR, (_Fs() & 0xf8));
	_WriteVMCS(HOST_GS_SELECTOR, (_Gs() & 0xf8));
	_WriteVMCS(HOST_TR_SELECTOR, (_TrSelector() & 0xf8));
	_WriteVMCS(HOST_FS_BASE, _ReadMsr(MSR_FS_BASE));
	_WriteVMCS(HOST_GS_BASE, _ReadMsr(MSR_GS_BASE));

	InitializeSegmentSelector(&SegmentSelector, _TrSelector(), (PVOID)
		_GdtBase());

	_WriteVMCS(HOST_TR_BASE, SegmentSelector.base);

	_WriteVMCS(HOST_GDTR_BASE, _GdtBase());
	_WriteVMCS(HOST_IDTR_BASE, _IdtBase());

	_WriteVMCS(HOST_IA32_SYSENTER_ESP, _ReadMsr(MSR_IA32_SYSENTER_ESP));
	_WriteVMCS(HOST_IA32_SYSENTER_EIP, _ReadMsr(MSR_IA32_SYSENTER_EIP));
	_WriteVMCS(HOST_IA32_SYSENTER_CS, _ReadMsr(MSR_IA32_SYSENTER_CS));

	/* VM Execution Control Fields */
	_WriteVMCS(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0,
		MSR_IA32_VMX_PINBASED_CTLS));


	//MSR_IA32_VMX_PROCBASED_CTLS
	Interceptions = 0;

	Interceptions = VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS);
	Interceptions |= CPU_BASED_RDTSC_EXITING;
	Interceptions |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	//_WriteVMCS(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(Interceptions, MSR_IA32_VMX_PROCBASED_CTLS));
	Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL, Interceptions);
	
	
	Interceptions = 0;
	Interceptions = SECONDARY_EXEC_ENABLE_RDTSCP;
	Vmx_VmWrite(SECONDARY_VM_EXEC_CONTROL, Interceptions);

#ifdef _EPT
	//vmCpuCtl2Requested.Fields.EnableEPT = TRUE;
	//vmCpuCtl2Requested.Fields.EnableRDTSCP = TRUE;
	//vmCpuCtl2Requested.Fields.EnableXSAVESXSTORS = TRUE;
	//vmCpuCtl2Requested.Fields.DescriptorTableExiting = TRUE;
	//vmCpuCtl2Requested.Fields.EnableRDTSCP = TRUE;
	//vmCpuCtl2Requested.Fields.EnableXSAVESXSTORS = TRUE;
	Interceptions = 0;
	Interceptions = SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_RDTSCP;
	Vmx_VmWrite(SECONDARY_VM_EXEC_CONTROL ,Interceptions);
	//Interceptions |= SECONDARY_EXEC_ENABLE_RDTSCP;
	/*Interceptions = AdjustControls(Interceptions,
		MSR_IA32_VMX_PROCBASED_CTLS2);
	_WriteVMCS(SECONDARY_VM_EXEC_CONTROL, Interceptions);*/
	/*Eptp.QuadPart = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	__vmx_vmwrite(
		SECONDARY_VM_EXEC_CONTROL,
		VmxpAdjustMsr(Eptp, vmCpuCtl2Requested.All));*/

#endif
	ExceptionBitmap = 0;
	ExceptionBitmap |= 1<<DEBUG_EXCEPTION;
	//ExceptionBitmap |= 1<<BREAKPOINT_EXCEPTION;
	//ExceptionBitmap |= 1<<PAGE_FAULT_EXCEPTION;

	_WriteVMCS(EXCEPTION_BITMAP, ExceptionBitmap);
	_WriteVMCS(PAGE_FAULT_ERROR_CODE_MASK, 0);
	_WriteVMCS(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	_WriteVMCS(IO_BITMAP_A, 0);
	_WriteVMCS(IO_BITMAP_A_HIGH, 0);
	_WriteVMCS(IO_BITMAP_B, 0);
	_WriteVMCS(IO_BITMAP_B_HIGH, 0);
	_WriteVMCS(TSC_OFFSET, 0);
	_WriteVMCS(TSC_OFFSET_HIGH, 0);
	_WriteVMCS(MSR_BITMAP, pCpu->MSR_bitmap_pa.LowPart);
	_WriteVMCS(MSR_BITMAP_HIGH, pCpu->MSR_bitmap_pa.HighPart);
/*
#ifdef _EPT
	Status = EPTInit(pCpu, &Eptp);
	if (Status == STATUS_UNSUCCESSFUL)
	{
		FGP_VT_KDPRINT(("ept is disable init : epte is %llx\n", Eptp.QuadPart));
		return STATUS_UNSUCCESSFUL;
	}
	_WriteVMCS(EPT_POINTER_FULL,Eptp.LowPart);
	MmInitManager(pCpu);
	_WriteVMCS(GUEST_CR3, g_PageMapBasePhysicalAddress.QuadPart);
#endif // _EPT*/
//#ifdef _EPT
//	Bit32u  j, h, map;
//	Bit64u temp64, temp32;
//	EPTInit();
//
//	/* Init Virtual PT Bases */
//	vmm_memset(VIRT_PT_BASES, 0, HOST_GB * 512 * sizeof(VM_Address));
//	/* Allocate memory for EPT paging structures */
//
//	/* We need only one entry of EPT PML4 table */
//	Pml4 = (VM_Address)GUEST_MALLOC(4096);	/* Alloc 4K to be sure of 4K alignment :-( */
//	MmuGetPhysicalAddress(_Cr3(), Pml4, &Phys_Pml4);
//	vmm_memset((void *)Pml4, 0, 4096);
//
//	/* We need only HOST_GB entries of EPT PDPT */
//	pCpu->pdpt = (VM_Address)GUEST_MALLOC(4096);	/* Alloc 4K to be sure of 4K alignment :-( */
//	MmuGetPhysicalAddress(_Cr3(), pCpu->pdpt, &pCpu->phys_pdpt);
//	vmm_memset((void *)pCpu->pdpt, 0, 4096);
//
//	/* Fill PML4E with PDPT base address and RWX permissions */
//	*(VM_Address *)Pml4 = (pCpu->phys_pdpt & 0xfffff000) | 0x7;
//
//	map = 0;
//
//	for (i = 0; i < HOST_GB; i++) {
//
//		/* Allocate memory for PD */
//		pCpu->pd = (VM_Address)GUEST_MALLOC(4096);
//		if (!pCpu->pd) {
//			return STATUS_UNSUCCESSFUL;
//		}
//		MmuGetPhysicalAddress(_Cr3(), pCpu->pd, &(pCpu->phys_pd));
//		vmm_memset((void *)pCpu->pd, 0, 4096);
//
//		/* Fill i-th PDPTE with i-th PD baseaddr and RWX permissions */
//		*(VM_Address *)(pCpu->pdpt + i * 8) = (pCpu->phys_pd & 0xfffff000) | 0x7;
//
//		for (j = 0; j < 4096; j = j + 8) {
//
//			/* Allocate memory for PT */
//			pCpu->pt = (VM_Address)GUEST_MALLOC(4096);
//			if (!pCpu->pt) {
//				return STATUS_UNSUCCESSFUL;
//			}
//			/* Store Virtual PT base in ad-hoc array */
//			VIRT_PT_BASES[(i * 512) + (j / 8)] = pCpu->pt;
//			/* Get Phys Addr */
//			MmuGetPhysicalAddress(_Cr3(), pCpu->pt, &(pCpu->phys_pt));
//			vmm_memset((void *)pCpu->pt, 0, 4096);
//
//			/* Fill j-th PDE with PT baseaddr and RWX permissions */
//			*(VM_Address *)(pCpu->pd + j) = (pCpu->phys_pt & 0xfffff000) | 0x7;
//
//			/* 1:1 physical memory mapping */
//			for (h = 0; h < 4096; h = h + 8) {
//				/* Log("Fill PDPT[%d] PD[%d] PT[%d] with 0x%08hx", i, j/8, h/8, ((map << 12) | 0x37)); */
//				*(VM_Address *)(pCpu->pt + h) = (map << 12) | ((Bit8u)EPTGetMemoryType((map << 12)) << 3) | READ | WRITE | EXEC;
//				map++;
//			}
//		}
//	}
//
//	temp32 = _ReadVMCS(CPU_BASED_VM_EXEC_CONTROL);
//	CmSetBit32(&temp32, CPU_BASED_PRIMARY_ACTIVATE_SEC); /* Activate secondary controls */
//	_WriteVMCS(CPU_BASED_VM_EXEC_CONTROL, temp32);
//
//	/* Write EPTP (Memory Type WB, Page Walk 4 ---> 3 = 0x1e) */
//	temp64 = 0;
//	temp64 = (Phys_Pml4 & 0xfffff000) | 0x1e;
//	_WriteVMCS(EPT_POINTER_FULL, temp64);
//
//	temp32 = 0;
//	CmSetBit32(&temp32, 1); /* Enable EPT */
//	_WriteVMCS(SECONDARY_VM_EXEC_CONTROL, temp32);
//
//	vmm_memset(&EPTInveptDesc, 0, sizeof(EPTInveptDesc));
//	EPTInveptDesc.Eptp = _ReadVMCS(EPT_POINTER_FULL);
//
//	FGP_VT_KDPRINT(("SUCCESS: EPT enabled."));
//#endif // _EPT

#ifdef _EPT
	//p2m_init();
// 	_WriteVMCS(EPT_POINTER_FULL, MyEpt.ept_control.eptp);
// 	MyEpt.p2m_vpid_flush();
// 	MyEpt.p2m_tlb_flush();
	if (EptPml4TablePointer)
	{
		EnableEpt((PVOID)EptPml4TablePointer);
	}
#endif
	
	/* VM Exit Control */
	_WriteVMCS(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE |
		VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));

	_WriteVMCS(VM_EXIT_MSR_STORE_COUNT, 0);
	_WriteVMCS(VM_EXIT_MSR_LOAD_COUNT, 0);
	_WriteVMCS(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE,
		MSR_IA32_VMX_ENTRY_CTLS));

	_WriteVMCS(VM_ENTRY_MSR_LOAD_COUNT, 0);
	_WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, 0);

	_WriteVMCS(CR0_GUEST_HOST_MASK, X86_CR0_PG);
	_WriteVMCS(CR0_READ_SHADOW, (_Cr0() & X86_CR0_PG) | X86_CR0_PG);

	_WriteVMCS(CR4_GUEST_HOST_MASK, X86_CR4_VMXE);
	_WriteVMCS(CR4_READ_SHADOW, 0);

	_WriteVMCS(CR3_TARGET_COUNT, 0);
	_WriteVMCS(CR3_TARGET_VALUE0, 0);      //no use
	_WriteVMCS(CR3_TARGET_VALUE1, 0);      //no use                        
	_WriteVMCS(CR3_TARGET_VALUE2, 0);      //no use
	_WriteVMCS(CR3_TARGET_VALUE3, 0);      //no use

	return STATUS_SUCCESS;
}


NTSTATUS Virtualize(PVIRT_CPU pCpu)
{
	/*    ULONG64 rsp;*/
	ULONG32 i;

	i = KeGetCurrentProcessorNumber();
	FGP_VT_KDPRINT(("CPU: 0x%p \n", pCpu));
	FGP_VT_KDPRINT(("rsp: 0x%llx \n", _Rsp()));

	_VmLaunch();
	/* never returns if successful */
	FGP_VT_KDPRINT(("rflags after _VmLaunch: 0x%x\n", _Rflags()));
	if (_VmFailInvalid())
	{
		FGP_VT_KDPRINT(("no current VMCS\n"));
		return STATUS_UNSUCCESSFUL;
	}

	if (_VmFailValid())
	{
		FGP_VT_KDPRINT(("vmlaunch failed\n"));
		FGP_VT_KDPRINT(("_ReadVMCS: 0x%llx\n", _ReadVMCS(VM_INSTRUCTION_ERROR)));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_UNSUCCESSFUL;
}


NTSTATUS StartVirtualization(PVOID GuestRsp)
{
	NTSTATUS Status;
	PVOID HostKernelStackBase;
	PVIRT_CPU pCpu;

	Status = CheckIfVMXIsEnabled();

	if (Status == STATUS_UNSUCCESSFUL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	HostKernelStackBase = ExAllocatePoolWithTag(NonPagedPool, 16 * 0x1000, 0x42424242);
	RtlZeroMemory(HostKernelStackBase, 16 * 0x1000);
	if (!HostKernelStackBase)
	{
		FGP_VT_KDPRINT(("can't allocate host kernel stack\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	pCpu = (PVIRT_CPU)((PCHAR)HostKernelStackBase + 16 * 0x1000 - 8 - sizeof(VIRT_CPU));
	pCpu->HostKernelStackBase = HostKernelStackBase;
	pCpu->Self = pCpu;
	pCpu->State = STATE_RUNNING;
	pCpu->Mailbox = IPI_RUNNING;

	Status = SetupVMX(pCpu);

	g_cpus[pCpu->ProcessorNumber] = pCpu;

	if (Status == STATUS_UNSUCCESSFUL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	Status = SetupVMCS(pCpu, GuestRsp);

	if (Status == STATUS_UNSUCCESSFUL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	InterlockedIncrement(&g_processors);

	Status = Virtualize(pCpu);

	if (Status == STATUS_UNSUCCESSFUL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

static BOOLEAN HandleUnimplemented(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 ExitCode)
{
	ULONG64 InstructionLength;

	FGP_VT_KDPRINT(("vmx: unimplemented\n"));
	FGP_VT_KDPRINT(("vmx: exitcode = 0x%llx\n", ExitCode));
	FGP_VT_KDPRINT(("vmx: guest_rip = 0x%llx\n", _ReadVMCS(GUEST_RIP)));

	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);

	return TRUE;
}

static BOOLEAN HandleException(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	ULONG32 Event, InjectEvent;
	ULONG64 ErrorCode, ExitQualification, GuestRip, uDr6;
	PINTERRUPT_INFO_FIELD pEvent;
	PINTERRUPT_INJECT_INFO_FIELD pInjectEvent;
	PDEBUG_EXIT_QUALIFICATION pDebugExitQualification;

	Event = (ULONG32)_ReadVMCS(VM_EXIT_INTR_INFO);
	pEvent = (PINTERRUPT_INFO_FIELD)&Event;

	InjectEvent = 0;
	pInjectEvent = (PINTERRUPT_INJECT_INFO_FIELD)&InjectEvent;

	GuestRip = _ReadVMCS(GUEST_RIP);

	switch (pEvent->InterruptionType)
	{
	case NMI_INTERRUPT:
		FGP_VT_KDPRINT(("vmx: HandleNmi()\n"));
		InjectEvent = 0;
		pInjectEvent->Vector = NMI_INTERRUPT;
		pInjectEvent->InterruptionType = NMI_INTERRUPT;
		pInjectEvent->DeliverErrorCode = 0;
		pInjectEvent->Valid = 1;
		_WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
		break;

	case EXTERNAL_INTERRUPT:
		FGP_VT_KDPRINT(("vmx: HandleExternalInterrupt()\n"));
		break;

	case HARDWARE_EXCEPTION:
		switch (pEvent->Vector)
		{
		case DEBUG_EXCEPTION:

			//
			// A debug exception does not update DR6, DR7.GD, or IA32_DEBUGCTL.LBR.(From Intel manual)
			//
			ExitQualification = _ReadVMCS(EXIT_QUALIFICATION);
			pDebugExitQualification = (PDEBUG_EXIT_QUALIFICATION)&ExitQualification;
			uDr6 = X86_DR6_INIT_VAL;
			uDr6 |= (ExitQualification
				& (X86_DR6_B0 | X86_DR6_B1 | X86_DR6_B2 | X86_DR6_B3 | X86_DR6_BD | X86_DR6_BS));
			/*
			FGP_VT_KDPRINT(("dr6=0x%llx\n", uDr6));

			if (pDebugExitQualification->B0
			|| pDebugExitQualification->B1
			|| pDebugExitQualification->B2
			|| pDebugExitQualification->B3
			)
			{
			FGP_VT_KDPRINT(("hw breakpoint\n"));
			}

			if (pDebugExitQualification->BD)
			{
			FGP_VT_KDPRINT(("debug register access detected\n"));
			}

			if (pDebugExitQualification->BS)
			{
			FGP_VT_KDPRINT(("single step\n"));
			}
			*/

			pGuestRegs->dr6 &= ~X86_DR6_B_MASK;
			pGuestRegs->dr6 |= uDr6;


			pGuestRegs->dr7 = _ReadVMCS(GUEST_DR7);
			pGuestRegs->dr7 &= ~X86_DR7_GD;
			pGuestRegs->dr7 &= ~X86_DR7_RAZ_MASK;
			pGuestRegs->dr7 |= X86_DR7_RA1_MASK;

			_WriteVMCS(GUEST_DR7, pGuestRegs->dr7);


			//FGP_VT_KDPRINT(("vmx: int1 guest_rip = 0x%llx\n", GuestRip));

			//ReportException(pCpu, pGuestRegs, pEvent->Vector, GuestRip);

			InjectEvent = 0;
			pInjectEvent->Vector = DEBUG_EXCEPTION;
			pInjectEvent->InterruptionType = HARDWARE_EXCEPTION;
			pInjectEvent->DeliverErrorCode = 0;
			pInjectEvent->Valid = 1;
			_WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
			_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP));

			break;

		case PAGE_FAULT_EXCEPTION:
			//InterlockedIncrement(&g_pagefaults);
			ErrorCode = _ReadVMCS(VM_EXIT_INTR_ERROR_CODE);
			ExitQualification = _ReadVMCS(EXIT_QUALIFICATION);
			/*                    if (g_pagefaults < 10)*/
			/*                    {*/
			/*                        DbgLog(("vmx: Exception(): guest_rip = 0x%llx\n", */
			/*                            GuestRip));*/

			/*                        DbgLog(("pagefault #%d\n", g_pagefaults));*/
			/*                        DbgLog(("vmx: page fault\n"));*/
			/*                        DbgLog(("vmx: error=0x%x\n", ErrorCode));*/
			/*                        DbgLog(("vmx: address=0x%llx\n", ExitQualification));*/
			/*                    }*/

			_SetCr2(ExitQualification);
			_WriteVMCS(VM_ENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
			InjectEvent = 0;
			pInjectEvent->Vector = PAGE_FAULT_EXCEPTION;
			pInjectEvent->InterruptionType = HARDWARE_EXCEPTION;
			pInjectEvent->DeliverErrorCode = 1;
			pInjectEvent->Valid = 1;
			_WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
			_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP));
			break;

		default:
			FGP_VT_KDPRINT(("vmx: Hardware Exception (vector=0x%x)\n", pEvent->Vector));
			break;
		}

		break;

	case SOFTWARE_EXCEPTION:
		/* #BP (int3) and #OF (into) */

		switch (pEvent->Vector)
		{
		case BREAKPOINT_EXCEPTION:
			FGP_VT_KDPRINT(("vmx: int3\n"));
			FGP_VT_KDPRINT(("vmx: Exception(): guest_rip = 0x%llx\n", GuestRip));

			InjectEvent = 0;
			pInjectEvent->Vector = BREAKPOINT_EXCEPTION;
			pInjectEvent->InterruptionType = SOFTWARE_INTERRUPT;
			pInjectEvent->DeliverErrorCode = 0;
			pInjectEvent->Valid = 1;
			_WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
			_WriteVMCS(VM_ENTRY_INSTRUCTION_LEN, 1);
			_WriteVMCS(GUEST_RIP, GuestRip);
			break;

		case OVERFLOW_EXCEPTION:
		default:
			FGP_VT_KDPRINT(("vmx: Software Exception (vector=0x%x)\n", pEvent->Vector));

			break;
		}
		break;

	default:
		FGP_VT_KDPRINT(("vmx: unknown interruption type\n"));
		break;
	}

	return TRUE;
}

static BOOLEAN HandleCpuid(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	ULONG32 Function, eax, ebx, ecx, edx;
	ULONG64 InstructionLength;

	Function = (ULONG32)pGuestRegs->rax;
	ecx = (ULONG32)pGuestRegs->rcx;
	//	FGP_VT_KDPRINT(("vmx: cpuid on processor #%d: Function=0x%x\n", KeGetCurrentProcessorNumber(), Function));
	//	FGP_VT_KDPRINT(("vmx: HandleCpuid(): guest_rip = 0x%llx\n", _ReadVMCS(GUEST_RIP)));
	_CpuId(Function, &eax, &ebx, &ecx, &edx);

	pGuestRegs->rax = eax;
	pGuestRegs->rbx = ebx;
	pGuestRegs->rcx = ecx;
	pGuestRegs->rdx = edx;

	if (Function == 0)
	{
		pGuestRegs->rbx = 0x11111111;
		pGuestRegs->rcx = 0x22222222;
		pGuestRegs->rdx = 0x33333333;
	}
	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);

	return TRUE;
}


static BOOLEAN HandleInvd(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	ULONG64 InstructionLength;

	FGP_VT_KDPRINT(("vmx: invd\n"));
	_Invd();

	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);
	return TRUE;
}


static BOOLEAN HandleVmCall(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	ULONG64 InstructionLength, Rip, Rsp;

	Rip = _ReadVMCS(GUEST_RIP);
	FGP_VT_KDPRINT(("VmCall: guest_rip = 0x%llx\n", Rip));

	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);

	if ((pGuestRegs->rax == 0x42424242) && (pGuestRegs->rbx == 0x43434343))
	{
		FGP_VT_KDPRINT(("got magic sequence, terminating\n"));
		Rip = (ULONG64)_GuestExit;
		Rsp = pGuestRegs->rsp;
		FGP_VT_KDPRINT(("restoring rip=0x%llx, rsp=0x%llx\n", Rip, Rsp));
		_VmxOff(Rip, Rsp);
	}
	else  if (pGuestRegs->rax == VMCALL_INIT_SPLIT)
	{
		//Log("Init EIP", GuestSTATE->GuestEIP);
		if (pGuestRegs->rbx == 0)
		{
			_Int3();
		}
		init_split((TlbTranslation *)pGuestRegs->rbx);
		_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);
	}
	else if (pGuestRegs->rax == VMCALL_END_SPLIT)
	{
		//Log("End EIP", GuestSTATE->GuestEIP);
		end_split(splitPages);
		_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);
	}
	else if (pGuestRegs->rax == VMCALL_MEASURE)
	{
		PHYSICAL_ADDRESS phys = { 0 };
		UINT8 *pePtr;
		// If we can safely measure the PE, do so
		if (KeGetCurrentIrql() == 0)
		{
			phys.QuadPart = pGuestRegs->rbx;
#ifdef SPLIT_TLB
			DbgPrint("Checksum of proc (data copy): %x\r\n",
				peChecksumExecSections(targetPePtr,
				(void *)pGuestRegs->rcx,
				targetProc,
				&apcstate,
				targetPhys));
			DbgPrint("Checksum of proc (exec copy): %x\r\n",
				peChecksumBkupExecSections(targetPePtr,
				(void *)targetPePtr,
				targetProc,
				&apcstate,
				targetPhys));
			//DbgPrint("Exec: %d Data: %d Thrash: %d\r\n", ExecExits, DataExits, Thrashes);
#endif
#ifndef SPLIT_TLB
			DbgPrint("Checksum of proc: %x\r\n",
				peChecksumExecSections(targetPePtr,
				(void *)pGuestRegs->rcx,
				targetProc,
				&apcstate,
				targetPhys));
#endif
		}
		_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);
	}
	else
	{
		_WriteVMCS(GUEST_RIP, Rip + InstructionLength);
	}


	return TRUE;
}

static BOOLEAN HandleVmInstruction(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	ULONG64 InstructionLength, Rip;

	Rip = _ReadVMCS(GUEST_RIP);
	FGP_VT_KDPRINT(("VmInstruction: guest_rip = 0x%llx\n", Rip));

	/* _VmFailInvalid */
	_WriteVMCS(GUEST_RFLAGS, _ReadVMCS(GUEST_RFLAGS) | 0x1);

	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);

	return TRUE;
}



static BOOLEAN HandleDrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	PMOV_DR_QUALIFICATION pExitQualification;
	ULONG64 Exit;
	ULONG64 Dr;
	ULONG64 Reg;
	ULONG64 InstructionLength;

	Exit = _ReadVMCS(EXIT_QUALIFICATION);
	pExitQualification = (PMOV_DR_QUALIFICATION)&Exit;

	switch (pExitQualification->DebugRegIndex)
	{

	case DR_0:
		Dr = pGuestRegs->dr0;
		break;

	case DR_1:
		Dr = pGuestRegs->dr1;
		break;

	case DR_2:
		Dr = pGuestRegs->dr2;
		break;

	case DR_3:
		Dr = pGuestRegs->dr3;
		break;

	case DR_6:
		Dr = pGuestRegs->dr6;
		break;

	case DR_7:
		Dr = _ReadVMCS(GUEST_DR7);
		break;

	default:
		Dr = 0;
		_Int3();
		break;
	}

	switch (pExitQualification->GeneralReg)
	{
	case RAX:
		Reg = pGuestRegs->rax;
		break;

	case RCX:
		Reg = pGuestRegs->rcx;
		break;

	case RDX:
		Reg = pGuestRegs->rdx;
		break;

	case RBX:
		Reg = pGuestRegs->rbx;
		break;

	case RSP:
		Reg = pGuestRegs->rsp;
		break;

	case RBP:
		Reg = pGuestRegs->rbp;
		break;

	case RSI:
		Reg = pGuestRegs->rsi;
		break;

	case RDI:
		Reg = pGuestRegs->rdi;
		break;

	case R8:
		Reg = pGuestRegs->r8;
		break;

	case R9:
		Reg = pGuestRegs->r9;
		break;

	case R10:
		Reg = pGuestRegs->r10;
		break;

	case R11:
		Reg = pGuestRegs->r11;
		break;

	case R12:
		Reg = pGuestRegs->r12;
		break;

	case R13:
		Reg = pGuestRegs->r13;
		break;

	case R14:
		Reg = pGuestRegs->r14;
		break;

	case R15:
		Reg = pGuestRegs->r15;
		break;

	default:
		Reg = 0;
		_Int3();
		break;

	}
	switch (pExitQualification->DirectionAccess)
	{
	case MOV_TO_DR:

		switch (pExitQualification->DebugRegIndex)
		{
		case DR_0:
			pGuestRegs->dr0 = Reg;
			break;
		case DR_1:
			pGuestRegs->dr1 = Reg;
			break;
		case DR_2:
			pGuestRegs->dr2 = Reg;
			break;
		case DR_3:
			pGuestRegs->dr3 = Reg;
			break;
		case DR_6:
			Reg |= X86_DR6_RA1_MASK;
			Reg &= ~X86_DR6_RAZ_MASK;
			pGuestRegs->dr6 = Reg;
			break;
		case DR_7:
			Reg |= X86_DR7_RA1_MASK;
			Reg &= ~X86_DR7_RAZ_MASK;
			_WriteVMCS(GUEST_DR7, Reg);
			//pGuestRegs->dr7 = Reg;
			break;

		default:
			_Int3();
			break;
		}
		break;

	case MOV_FROM_DR:
		switch (pExitQualification->GeneralReg)
		{
		case RAX:
			pGuestRegs->rax = Dr;
			break;

		case RCX:
			pGuestRegs->rcx = Dr;
			break;

		case RDX:
			pGuestRegs->rdx = Dr;
			break;

		case RBX:
			pGuestRegs->rbx = Dr;
			break;

		case RSP:
			pGuestRegs->rsp = Dr;
			break;

		case RBP:
			pGuestRegs->rbp = Dr;
			break;

		case RSI:
			pGuestRegs->rsi = Dr;
			break;

		case RDI:
			pGuestRegs->rdi = Dr;
			break;

		case R8:
			pGuestRegs->r8 = Dr;
			break;

		case R9:
			pGuestRegs->r9 = Dr;
			break;

		case R10:
			pGuestRegs->r10 = Dr;
			break;

		case R11:
			pGuestRegs->r11 = Dr;
			break;

		case R12:
			pGuestRegs->r12 = Dr;
			break;

		case R13:
			pGuestRegs->r13 = Dr;
			break;

		case R14:
			pGuestRegs->r14 = Dr;
			break;

		case R15:
			pGuestRegs->r15 = Dr;
			break;

		default:
			_Int3();
			break;
		}

		break;

	default:
		_Int3();
		break;
	}

	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);

	return TRUE;
}


static BOOLEAN HandleCrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	PMOV_CR_QUALIFICATION pExitQualification;
	ULONG64 Exit;
	ULONG64 Cr;
	ULONG64 Reg;
	ULONG64 InstructionLength;

	Exit = _ReadVMCS(EXIT_QUALIFICATION);
	pExitQualification = (PMOV_CR_QUALIFICATION)&Exit;

	switch (pExitQualification->ControlRegister)
	{
	case CR0:
		Cr = _ReadVMCS(GUEST_CR0);
		break;

	case CR3:
		Cr = _ReadVMCS(GUEST_CR3);
		break;

	case CR4:
		Cr = _ReadVMCS(GUEST_CR4);
		break;

	default:
		Cr = 0;
		_Int3();
		break;
	}

	switch (pExitQualification->Register)
	{
	case RAX:
		Reg = pGuestRegs->rax;
		break;

	case RCX:
		Reg = pGuestRegs->rcx;
		break;

	case RDX:
		Reg = pGuestRegs->rdx;
		break;

	case RBX:
		Reg = pGuestRegs->rbx;
		break;

	case RSP:
		Reg = pGuestRegs->rsp;
		break;

	case RBP:
		Reg = pGuestRegs->rbp;
		break;

	case RSI:
		Reg = pGuestRegs->rsi;
		break;

	case RDI:
		Reg = pGuestRegs->rdi;
		break;

	case R8:
		Reg = pGuestRegs->r8;
		break;

	case R9:
		Reg = pGuestRegs->r9;
		break;

	case R10:
		Reg = pGuestRegs->r10;
		break;

	case R11:
		Reg = pGuestRegs->r11;
		break;

	case R12:
		Reg = pGuestRegs->r12;
		break;

	case R13:
		Reg = pGuestRegs->r13;
		break;

	case R14:
		Reg = pGuestRegs->r14;
		break;

	case R15:
		Reg = pGuestRegs->r15;
		break;

	default:
		Reg = 0;
		_Int3();
		break;

	}
#ifdef SPLIT_TLB   
	if (_ReadVMCS(GUEST_CR3) == targetCR3 && splitPages != NULL)
	{
		EptPteEntry *eptpte = NULL;
		UINT32 i;
		for (i = 0; i < appsize / PAGE_SIZE; i++)
		{
			if (targetPtes[i] != NULL)
			{
				TlbTranslation *ptr = getTlbTranslation(splitPages, targetPtes[i]->PageFrameNumber << 12);
				if (ptr == NULL)
				{
					AppendTlbTranslation(splitPages, targetPtes[i]->PageFrameNumber << 12,
						(UINT8 *)targetPeVirt + (i * PAGE_SIZE));
				}
			}
		}
	}
#endif
	switch (pExitQualification->AccessType)
	{
	case MOV_TO_CR:
		switch (pExitQualification->ControlRegister)
		{
		case CR0:
			_WriteVMCS(GUEST_CR0, Reg);
			break;

		case CR3:
			//HandleClientRequest(pCpu, pGuestRegs, Reg);
			_WriteVMCS(GUEST_CR3, Reg);
			break;

		case CR4:
			_WriteVMCS(GUEST_CR4, Reg);
			break;

		default:
			_Int3();
			break;
		}
		break;

	case MOV_FROM_CR:
		switch (pExitQualification->Register)
		{
		case RAX:
			pGuestRegs->rax = Cr;
			break;

		case RCX:
			pGuestRegs->rcx = Cr;
			break;

		case RDX:
			pGuestRegs->rdx = Cr;
			break;

		case RBX:
			pGuestRegs->rbx = Cr;
			break;

		case RSP:
			pGuestRegs->rsp = Cr;
			break;

		case RBP:
			pGuestRegs->rbp = Cr;
			break;

		case RSI:
			pGuestRegs->rsi = Cr;
			break;

		case RDI:
			pGuestRegs->rdi = Cr;
			break;

		case R8:
			pGuestRegs->r8 = Cr;
			break;

		case R9:
			pGuestRegs->r9 = Cr;
			break;

		case R10:
			pGuestRegs->r10 = Cr;
			break;

		case R11:
			pGuestRegs->r11 = Cr;
			break;

		case R12:
			pGuestRegs->r12 = Cr;
			break;

		case R13:
			pGuestRegs->r13 = Cr;
			break;

		case R14:
			pGuestRegs->r14 = Cr;
			break;

		case R15:
			pGuestRegs->r15 = Cr;
			break;

		default:
			_Int3();
			break;
		}

		break;

	default:
		_Int3();
		break;
	}
	InvVpidAllContext();
	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);

	return TRUE;
}


static BOOLEAN HandleMsrRead(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	LARGE_INTEGER Msr;
	ULONG32 ecx;
	ULONG64 InstructionLength;

	ecx = (ULONG32)pGuestRegs->rcx;

	//FGP_VT_KDPRINT(("vmx: HandleMsrRead(): msr = 0x%x\n", ecx));

	switch (ecx)
	{
	case MSR_IA32_SYSENTER_CS:
		Msr.QuadPart = _ReadVMCS(GUEST_SYSENTER_CS);
		break;

	case MSR_IA32_SYSENTER_ESP:
		Msr.QuadPart = _ReadVMCS(GUEST_SYSENTER_ESP);
		break;

	case MSR_IA32_SYSENTER_EIP:
		Msr.QuadPart = _ReadVMCS(GUEST_SYSENTER_EIP);
		break;

	case MSR_GS_BASE:
		Msr.QuadPart = _ReadVMCS(GUEST_GS_BASE);
		break;

	case MSR_FS_BASE:
		Msr.QuadPart = _ReadVMCS(GUEST_FS_BASE);
		break;

	default:
		Msr.QuadPart = _ReadMsr(ecx);
		break;
	}

	pGuestRegs->rax = Msr.LowPart;
	pGuestRegs->rdx = Msr.HighPart;

	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);

	return TRUE;
}

static BOOLEAN HandleMsrWrite(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	LARGE_INTEGER Msr;
	ULONG32 ecx;
	ULONG64 InstructionLength;

	ecx = (ULONG32)pGuestRegs->rcx;

	//FGP_VT_KDPRINT(("vmx: HandleMsrWrite(): msr = 0x%x\n", ecx));
	Msr.LowPart = (ULONG32)pGuestRegs->rax;
	Msr.HighPart = (ULONG32)pGuestRegs->rdx;

	switch (ecx)
	{
	case MSR_IA32_SYSENTER_CS:
		_WriteVMCS(GUEST_SYSENTER_CS, Msr.QuadPart);
		break;

	case MSR_IA32_SYSENTER_ESP:
		_WriteVMCS(GUEST_SYSENTER_ESP, Msr.QuadPart);
		break;

	case MSR_IA32_SYSENTER_EIP:
		_WriteVMCS(GUEST_SYSENTER_EIP, Msr.QuadPart);
		break;

	case MSR_GS_BASE:
		_WriteVMCS(GUEST_GS_BASE, Msr.QuadPart);
		break;

	case MSR_FS_BASE:
		_WriteVMCS(GUEST_FS_BASE, Msr.QuadPart);
		break;

	default:
		_WriteMsr(ecx, Msr.QuadPart);
		break;
	}

	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);

	return TRUE;
}

static BOOLEAN HandleEPT(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	PHYSICAL_ADDRESS gpa, gla;
	ULONG64 q, inst_len;
	ULONG64 addr, data;
	ULONG64 *paddr;
	ULONG64 InstructionLength;

#if defined(_X86_)
	gpa.LowPart = VmxRead(GUEST_PHYSICAL_ADDRESS);
	gpa.HighPart = VmxRead(GUEST_PHYSICAL_ADDRESS_HIGH);
#elif defined(_X64_)
	gpa.QuadPart = _ReadVMCS(GUEST_PHYSICAL_ADDR_FULL);
#endif

	gla.QuadPart = _ReadVMCS(GUEST_LINEAR_ADDRESS);
	q = _ReadVMCS(EXIT_QUALIFICATION);
	//Trap->RipDelta = 0;

#ifdef EXAMPLE_MEM_DUMP
	return ept_handle_violation_ext(arch, gpa);
#else
// 	if (q & EPT_WRITE_VIOLATION) {
// 		//print("Ept handler: gpa=%08x\n", gpa.QuadPart);
// 		//__asm{ int 3 }
// 		addr = gpa.QuadPart;
// 		//if (rangecheck((i32)addr, (i32)pdesc_rv, 0, rvlen*sizeof(rv_desc))) {
// 		//__asm{ int 3 }
// 		//	handle_rv_ring_pagefault(addr, data);
// 		//write_phymem(addr, 4, &data);
// 		//}
// 		/*switch (gpa.QuadPart) {
// 		case IOADDR_BAR0 + TDT:
// 			//print("TxIndex=%08x\n", data);
// 			handle_tx_pagefault(data);
// 			break;
// 		case IOADDR_BAR0 + RDT:
// 			//print("RvIndex=%08x\n", data);
// 			handle_rv_pagefault(data);
// 			break;
// 		default:
// 			//__asm { int 3 }
// 			break;
// 		}*/
// 		/*write_guest_mem(paddr, &data);
// 		Trap->RipDelta = inst_len;*/
// 		InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
// 		_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);
// 		return TRUE;
// 	}
// 
// 	DbgPrint("ept_handle_violation():Violation @0x%llx for %c%c%c/%c%c%c\n", gpa.QuadPart,
// 		(q & EPT_READ_VIOLATION) ? 'r' : '-',
// 		(q & EPT_WRITE_VIOLATION) ? 'w' : '-',
// 		(q & EPT_EXEC_VIOLATION) ? 'x' : '-',
// 		(q & EPT_EFFECTIVE_READ) ? 'r' : '-',
// 		(q & EPT_EFFECTIVE_WRITE) ? 'w' : '-',
// 		(q & EPT_EFFECTIVE_EXEC) ? 'x' : '-');
// 	//panic(("EPT violation should not happen"));
	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);
	return FALSE;
#endif
}

//win 10 
static VOID HandleRdtsc(PGUEST_REGS pGuestRegs)
{
	//ULARGE_INTEGER tsc = { 0 };
	ULONG64 InstructionLength;
	/*tsc.QuadPart = __rdtsc();
	pGuestRegs->rdx = tsc.HighPart;
	pGuestRegs->rax = tsc.LowPart;*/

	//DbgPrint("Rdtsc!\n");

	Asm_Rdtsc(&pGuestRegs->rax, &pGuestRegs->rdx);

	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);

	//Asm_Rdtsc(&pGuestRegs->rax, &pGuestRegs->rdx);
}

//win 10
static VOID HandleRdtscp(PGUEST_REGS GuestState)
{
	/*unsigned int tscAux = 0;
	ULARGE_INTEGER tsc = { 0 };
	ULONG64 InstructionLength;
	tsc.QuadPart = __rdtscp(&tscAux);
	
	GuestState->rdx = tsc.HighPart;
	GuestState->rax = tsc.LowPart;
	GuestState->rcx = tscAux;*/
	ULONG64 InstructionLength;
	GuestState->rax = (_TSC() & 0xFFFFFFFF);
	GuestState->rdx = (_TSC() >> 32);
	//DbgPrint("Rdtscp!\n");
	InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP) + InstructionLength);


}

VOID HandleVmExit(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
	ULONG64 ExitCode;
	KIRQL OldIrql, CurrentIrql;

	OldIrql = 0;
	CurrentIrql = KeGetCurrentIrql();
	if (CurrentIrql < DISPATCH_LEVEL)
	{
		OldIrql = KeRaiseIrqlToDpcLevel();
	}

	pGuestRegs->rsp = _ReadVMCS(GUEST_RSP);
	ExitCode = _ReadVMCS(VM_EXIT_REASON);
	//HandleUnimplemented(pCpu, pGuestRegs, ExitCode);

	switch (ExitCode)
	{
	case EXIT_REASON_EXCEPTION_NMI:
		exit_reason_dispatch_handler__exec_trap(pGuestRegs);
		//HandleException(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_EXTERNAL_INTERRUPT:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_TRIPLE_FAULT:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_INIT:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_SIPI:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_IO_SMI:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_OTHER_SMI:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_PENDING_INTERRUPT:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_TASK_SWITCH:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_CPUID:
		HandleCpuid(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_HLT:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_INVD:
		HandleInvd(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_INVLPG:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_RDPMC:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_RDTSC:
		//DbgPrint("xx!\n");
		HandleRdtsc(pGuestRegs);
		//HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_RSM:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_VMCALL:
		HandleVmCall(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
		HandleVmInstruction(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_CR_ACCESS:
		HandleCrAccess(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_DR_ACCESS:
		HandleDrAccess(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_IO_INSTRUCTION:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_MSR_READ:
		HandleMsrRead(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_MSR_WRITE:
		HandleMsrWrite(pCpu, pGuestRegs);
		break;

	case EXIT_REASON_INVALID_GUEST_STATE:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_MSR_LOADING:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_MWAIT_INSTRUCTION:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_MONITOR_INSTRUCTION:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_PAUSE_INSTRUCTION:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_MACHINE_CHECK:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;

	case EXIT_REASON_TPR_BELOW_THRESHOLD:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;
#ifdef _EPT
	case EXIT_REASON_EPT_VIOLATION:
		exit_reason_dispatch_handler__exec_ept(pGuestRegs);
		break;
	case EXIT_REASON_EPT_MISCONFIG:
		_Int3();
		break;
#endif
	case EXIT_REASON_RDTSCP:
		//DbgPrint("xx!\n");
		HandleRdtscp(pGuestRegs);
		break;

	default:
		HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
		break;
	}
	_WriteVMCS(GUEST_RSP, pGuestRegs->rsp);
	if (CurrentIrql < DISPATCH_LEVEL)
	{
		KeLowerIrql(OldIrql);
	}

}

#endif
