#pragma once
#include "Def.h"





#define SPLIT_TLB 1
/** Number of EPT PDE pages to allocate, one per GB of memory */
#define NUM_PD_PAGES 4
/** Maximum number of EPT page tables */
#define NUM_TABLES 512
#define MAX_STACK_SIZE 100
#define VM_VPID 1
#define DATA_EPT 0x1
#define CODE_EPT 0x2
#define EPT_MASK_DATA_READ 0x1
extern UINT32 appsize;
/** Bitmask for data write violation */
#define EPT_MASK_DATA_WRITE (1 << 1)
/** Bitmask for data execute violation */
#define EPT_MASK_DATA_EXEC (1 << 2)
/** Bitmask for if the guest linear address is valid */
#define EPT_MASK_GUEST_LINEAR_VALID (1 << 7)
#pragma pack(push, ept, 1)
enum EPT_MEMORY_TYPE_E
{
	EPT_MEMORY_TYPE_UC = 0,
	EPT_MEMORY_TYPE_WC = 1,
	EPT_MEMORY_TYPE_WT = 4,
	EPT_MEMORY_TYPE_WP = 5,
	EPT_MEMORY_TYPE_WB = 6,
};
typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
	struct 
	{
		UINT64 ExecuteOnly : 1;		// Bit 0 defines if the EPT implementation supports execute-only translation
		UINT64 Reserved1 : 31;	// Undefined
		UINT64 Reserved2 : 8;	// Undefined
		UINT64 IndividualAddressInvVpid : 1; // Bit 40 defines if type 0 INVVPID instructions are supported
		UINT64 Reserved3 : 23;
	};
	UINT64 pvid;
} IA32_VMX_EPT_VPID_CAP_MSR;
struct EptTablePointer_s
{
	UINT64 MemoryType : 3; // EPT Paging structure memory type (0 for UC)
	UINT64 PageWalkLength : 3; // Page-walk length - 1
	UINT64 reserved1 : 6; // Reserved
	UINT64 PhysAddr : 24; // Physical address of the EPT PML4 table
	UINT64 reserved2 : 28;
};

union EptTablePointer_u
{
	UINT64 unsignedVal;
	struct EptTablePointer_s Bits;
};

typedef union EptTablePointer_u EptTablePointer;

struct EptPml4Entry_s
{
	UINT64 Present : 1; // If the 512 GB region is present (read access)
	UINT64 Write : 1; // If the 512 GB region is writable
	UINT64 Execute : 1; // If the 512 GB region is executable
	UINT64 reserved1 : 9; // Reserved
	UINT64 PhysAddr : 24; // Physical address
	UINT64 reserved2 : 28; // Reserved
};

typedef struct EptPml4Entry_s EptPml4Entry;

struct EptPdpteEntry1Gb_s
{
	UINT64 Present : 1; // If the 1 GB region is present (read access)
	UINT64 Write : 1; // If the 1 GB region is writable
	UINT64 Execute : 1; // If the 1 GB region is executable
	UINT64 MemoryType : 3; // EPT Memory type
	UINT64 IgnorePat : 1; // Flag for whether to ignore PAT
	UINT64 Size : 1; // Must be 1
	UINT64 reserved1 : 22; // Reserved
	UINT64 PhysAddr : 6; // Physical address
	UINT64 reserved2 : 28; // Reserved
};

typedef struct EptPdpteEntry1Gb_s EptPdpteEntry1Gb;

struct EptPdpteEntry_s
{
	UINT64 Present : 1; // If the 1 GB region is present (read access)
	UINT64 Write : 1; // If the 1 GB region is writable
	UINT64 Execute : 1; // If the 1 GB region is executable
	UINT64 reserved1 : 9; // Reserved
	UINT64 PhysAddr : 24; // Physical address
	UINT64 reserved2 : 28; // Reserved
};

typedef struct EptPdpteEntry_s EptPdpteEntry;

struct EptPdeEntry_s
{
	UINT64 Present : 1; // If the 2 MB region is present (read access)
	UINT64 Write : 1; // If the 2 MB region is writable
	UINT64 Execute : 1; // If the 2 MB region is executable
	UINT64 reserved1 : 9; // Reserved
	UINT64 PhysAddr : 24; // Physical address
	UINT64 reserved2 : 28; // Reserved
};

typedef struct EptPdeEntry_s EptPdeEntry;

struct EptPdeEntry2Mb_s
{
	UINT64 Present : 1; // If the 1 GB region is present (read access)
	UINT64 Write : 1; // If the 1 GB region is writable
	UINT64 Execute : 1; // If the 1 GB region is executable
	UINT64 MemoryType : 3; // EPT Memory type
	UINT64 IgnorePat : 1; // Flag for whether to ignore PAT
	UINT64 Size : 1; // Must be 1
	UINT64 reserved1 : 13; // Reserved
	UINT64 PhysAddr : 15; // Physical address
	UINT64 reserved2 : 28; // Reserved
};

typedef struct EptPdeEntry2Mb_s EptPdeEntry2Mb;

struct EptPteEntry_s
{
	UINT64 Present : 1; // If the 1 GB region is present (read access)
	UINT64 Write : 1; // If the 1 GB region is writable
	UINT64 Execute : 1; // If the 1 GB region is executable
	UINT64 MemoryType : 3; // EPT Memory type
	UINT64 IgnorePat : 1; // Flag for whether to ignore PAT
	UINT64 reserved1 : 5; // Reserved
	UINT64 PhysAddr : 24; // Physical address
	UINT64 reserved2 : 28; // Reserved
};

typedef struct EptPteEntry_s EptPteEntry;

struct InvVpidDesc_s
{
	UINT64 Vpid : 16; // VPID to effect
	UINT64 reserved : 48; // Reserved
	UINT64 LinearAddress : 64; // Linear address
};

struct uint128_s
{
	UINT32 dword1;
	UINT32 dword2;
	UINT32 dword3;
	UINT32 dword4;
};

union InvVpidDesc_u
{
	struct uint128_s dwords;
	struct InvVpidDesc_s bits;
};

typedef union InvVpidDesc_u InvVpidDesc;
#pragma pack(pop, ept)
struct TlbTranslation_s
{
	UINT64 VirtualAddress;
	UINT64 DataPhys;
	UINT64 CodePhys;
	UINT8 CodeOrData;
	UINT8 RW;
	EptPteEntry *EptPte;
};
struct PageTableEntry_s
{
#ifdef X86
	UINT32 p : 1; // Present
	UINT32 rw : 1; // Read/Write
	UINT32 us : 1; // User/Superuser
	UINT32 pwt : 1; // Page write through
	UINT32 pcd : 1; // Page level cache disable
	UINT32 a : 1; // Accessed
	UINT32 d : 1; // Dirty
	UINT32 pat : 1; // PAT must be 0
	UINT32 g : 1; // G must be 0
	UINT32 reserved1 : 3; // Must be 0
	UINT32 address : 20;	// Address of page.
#else
	union
	{
		ULONG Valid : 1;
		ULONG Write : 1;
		ULONG Owner : 1;
		ULONG WriteThrough : 1;
		ULONG CacheDisable : 1;
		ULONG Accessed : 1;
		ULONG Dirty : 1;
		ULONG LargePage : 1;
		ULONG Global : 1;
		ULONG CopyOnWrite : 1;
		ULONG Prototype : 1;
		ULONG reserved0 : 1;
		ULONG PageFrameNumber : 26;
		ULONG reserved1 : 26;
		ULONG LowPart;
	};
	ULONG HighPart;
#endif // X86

	
};

typedef struct PageTableEntry_s PageTableEntry;
struct Stack_s
{
	void *data[MAX_STACK_SIZE];
	UINT32 top;
	UINT8 empty;
};
struct PagingContext_s
{
	PageTableEntry *PageTable;
	UINT32 VirtualPrefix;
	UINT8 *PageArray;
	UINT32 NumPages;
	UINT8 *PageArrayBitmap;
	UINT64 CR3Val;
};



typedef struct PagingContext_s PagingContext;
typedef struct Stack_s Stack;
typedef struct TlbTranslation_s TlbTranslation;
/** Pointer to the 512 PDPTEs covering the first 512GB of memory */
EptPdpteEntry *BkupPdptePtr = NULL;
/** Array of pointers to free for the PDEs */
EptPdeEntry2Mb *BkupPdePtrs[NUM_PD_PAGES] = { 0 };
UINT32 EptPageTableCounter = 0, TableVirtsCounter = 0, ViolationExits = 0,
ExecExits = 0, DataExits = 0, Thrashes = 0, Thrash = 0;
EptPteEntry *EptTableArray[NUM_TABLES] = { 0 };
EptPteEntry *EptTableVirts[NUM_TABLES] = { 0 };
TlbTranslation *splitPages = NULL;
UINT8 ProcessorSupportsType0InvVpid = 0;
IA32_VMX_EPT_VPID_CAP_MSR       vmxEptMsr;
/** Stack to store faulting addresses for TLB split */
Stack pteStack = { 0 };
PagingContext memContext = { 0 };
extern PVOID AllocateContiguousMemory(ULONG size);
extern BOOLEAN IsBitSet(ULONG64 v, UCHAR bitNo);

EptPml4Entry                    *EptPml4TablePointer = NULL; // Pointer to the EPT PML4 table

void EnableEpt(PVOID Pml4Ptr);

/**
Disables EPT & VPID
*/
void DisableEpt();

/**
Allocates and initializes an identity map for EPT

@return Pointer to the EPTPML4 table
*/
EptPml4Entry * InitEptIdentityMap();

/**
Frees the EPT identity map and any mapped page tables

@param ptr Pointer to the EPT PML4 table
*/
void FreeEptIdentityMap(EptPml4Entry * ptr);

/**
Invalidates all the VPID contexts
*/
void InvVpidAllContext();

/**
Invalidates the VPID entry for a given linear address

@param vpid VPID context
@param address Linear address to flush
*/
void InvVpidIndividualAddress(UINT16 vpid, UINT64 address);

/**
Invalidates all EPT translations
*/
void InvEptAllContext();

/**
Returns the EPT PTE for a guest physical address, down-grading from PDE to PTEs if needed

@note Assumes system has less than 512 GB of memory

@param guestPhysicalAddress 32-bit address to get the PTE for
@param pml4Ptr Optional pointer to EPT PML4 table (if not provided will use EPTP from VMCS)

@return Pointer to the EPT PTE for the passed address, or NULL if error
*/
EptPteEntry * EptMapAddressToPte(UINT64 guestPhysicalAddress, EptPml4Entry * pml4Ptr);

/**
Returns the EPT PTE for a guest physical address, down-grading from PDE to PTEs if needed

@note Assumes system has less than 512 GB of memory

@param guestPhysicalAddress 32-bit address to get the PTE for
@param pml4Ptr Optional pointer to EPT PML4 table (if not provided will use EPTP from VMCS)
@param context Pointer to the paging context

@return Pointer to the EPT PTE for the passed address, or NULL if error
*/
EptPteEntry * EptMapAddressToPteDirql(UINT64 guestPhysicalAddress,
	EptPml4Entry * pml4Ptr,
	PagingContext * context);

/**
Unmaps a PTE mapped in but does not free the page table

@param ptr Pointer to the PTE
*/
void EptUnmapPte(EptPteEntry * ptr);

/**
Unmaps a PTE mapped in but does not free the page table (at DIRQL)

@param ptr Pointer to the PTE
@param context Pointer to paging context
*/
void EptUnmapPteDirql(EptPteEntry * ptr, PagingContext * context);

/**
VM Exit handler for EPT violation

@param GuestSTATE State of the guest
*/
void exit_reason_dispatch_handler__exec_ept(PGUEST_REGS GuestSTATE);

/**
VM Exit handler for the trap flag

@param GuestSTATE State of the guest
*/
void exit_reason_dispatch_handler__exec_trap(PGUEST_REGS  GuestSTATE);

/**
Sets the guest's trap flag

@param value 1 or 0 value to set the trap flag to
*/
void SetTrapFlag(UINT8 value);

/**
Sets up the environment to split the TLB

@param arrPtr Pointer to a TlbTranslation array
*/
void init_split(TlbTranslation * arrPtr);

/**
Stops splitting the TLB for a memory region

@param arrPtr Pointer to a TlbTranslation array
*/
void end_split(TlbTranslation * arrPtr);

/**
Helper function to intelligently map out memory

@param context Pointer to paging context, if NULL, then the Win32 function is used
@param ptr Pointer to region to be mapped out
@param size Number of bytes in region, if context != NULL size is PAGE_SIZE
*/
void MapOutMemory(PagingContext * context, void * ptr, UINT32 size);

/**
Helper function to intelligently map in physical addresses

@param context Pointer to paging context, if NULL, then the Win32 function is used
@param phys Physical address to map in
@param size Number of bytes (if context != NULL, size is always PAGE_SIZE)
@return Pointer to mapped-in region
*/
void * MapInMemory(PagingContext * context, PHYSICAL_ADDRESS phys, UINT32 size);

/**
Function to determine whether or not the passed guest physical is in a PT or a PD

@param guestPhysicalAddress Guest Physical
@return 1 if there is a PTE for the address, 0 if there is a PDE for it
*/
UINT8 EptPtExists(UINT64 guestPhysicalAddress);

/**
Helper function to call the INVVPID instruction with the passed type & descriptor

@param invtype INVVPID type
@param desc INVVPID descriptor
*/
static void __invVpidAllContext(UINT64 invtype, InvVpidDesc desc);

void StackInitStack(Stack * stack)
{
	stack->empty = 1;
	stack->top = 0;
}

void * StackPop(Stack * stack)
{
	void *outVal;
	if (stack->empty == 1)
		return NULL;

	outVal = stack->data[stack->top];

	if (stack->top == 0)
	{
		stack->empty = 1;
	}
	else
	{
		stack->top--;
	}

	return outVal;
}

void StackPush(Stack * stack, void * ptr)
{
	if (stack->top + 1 == MAX_STACK_SIZE)
		return;

	if (stack->empty == 1)
	{
		stack->top = 0;
		stack->empty = 0;
		stack->data[0] = ptr;
	}
	else
	{
		stack->top++;
		stack->data[stack->top] = ptr;
	}
}

UINT8 StackIsEmpty(Stack * stack)
{
	return stack->empty;
}

UINT8 StackIsFull(Stack * stack)
{
	return (stack->top + 1 == MAX_STACK_SIZE) ? 1 : 0;
}

UINT32 StackNumEntries(Stack * stack)
{
	if (stack->empty == 1)
		return 0;
	return stack->top + 1;
}

void * StackPeek(Stack * stack)
{
	if (stack->empty == 1)
		return NULL;
	return stack->data[stack->top];
}


TlbTranslation * getTlbTranslation(TlbTranslation * transArr, UINT64 guestPhysical)
{
	UINT32 i = 0;
	guestPhysical &= 0xFFFFF000;
	if (transArr == NULL)
		return NULL;
	// Look for the correct TlbTranslation
	while (transArr[i].DataPhys != 0)
	{
		if ((transArr[i].CodeOrData == DATA_EPT && guestPhysical == transArr[i].DataPhys) ||
			(transArr[i].CodeOrData == CODE_EPT && guestPhysical == transArr[i].CodePhys))
			return &transArr[i];
		i++;
	}
	return NULL;
}

void * pagingAllocPage(PagingContext *context)
{
	UINT32 i;
	for (i = 0; i < context->NumPages; i++)
	{
		if (context->PageArrayBitmap[i] == 0)
		{
			// Mark page as taken
			context->PageArrayBitmap[i] = 1;
			return context->PageArray + (i * PAGE_SIZE);
		}
	}
	// No memory left
	return NULL;
}

void EnableEpt(PVOID Pml4Ptr)
{
	UINT64 reg = _ReadVMCS(SECONDARY_VM_EXEC_CONTROL);
	PHYSICAL_ADDRESS phys = MmGetPhysicalAddress(Pml4Ptr);
	unsigned long long count = 0;
	unsigned int i, n;
	LARGE_INTEGER base;
	ULONG32 eax, ebx, ecx, edx;
	SHORT_CPU m_EAX;
	ULONG64 eptp, EptVpid;
	PHYSICAL_ADDRESS pa;

	/*Get phys address size from from CPUID.80000008 (useless on 32 bit but whatever) */
		/*31                          16 15              8 7              0 * /
		/*+------------------------------ + ---------------- - +---------------- + */
		/*| ############################## | VirtualMemoryBits | PhysMemoryBits | */
		/*+------------------------------ + ---------------- - +---------------- + */
		_CpuId(0x80000008, &eax, &ebx, &ecx, &edx);

	m_EAX.QuadPart = eax;
	pa = phys;

	base.QuadPart = _GetMaxPhyaddr(m_EAX.LowPart);
	FGP_VT_KDPRINT(("Cpu PhysMemoryBits is %llx \n", m_EAX.LowPart));
	eptp = pa.QuadPart & ~0x0fff & base.QuadPart;
	FGP_VT_KDPRINT(("MaxPhyAddrSelectMask is %llx \n", base.QuadPart));
	EptVpid = _ReadMsr(MSR_IA32_VMX_EPT_VPID_CAP);
	vmxEptMsr.pvid = EptVpid;
	ProcessorSupportsType0InvVpid = (UINT8)vmxEptMsr.IndividualAddressInvVpid;
	if (IsBitSet(EptVpid, 21))
	{
		eptp = eptp | (1 << 6);
	}
	if (IsBitSet(EptVpid, 14))
	{
		eptp = eptp | MEM_TYPE_WB;
	}
	else
	{
		eptp = eptp | MEM_TYPE_UC;
	}
	eptp = eptp | 0x18;

	// Set up the EPTP
	_WriteVMCS(EPT_POINTER_FULL, eptp);
	//_WriteVMCS(EPT_POINTER_HIGH, 0);

	// Set the guest VPID to a non-zero value
	_WriteVMCS(VIRTUAL_PROCESSOR_ID, 1);

	// Enable the secondary controls VMCS field
	_WriteVMCS(SECONDARY_VM_EXEC_CONTROL, reg | (1 << 5) | (1 << 1));
	reg = _ReadVMCS(CPU_BASED_VM_EXEC_CONTROL);
	_WriteVMCS(CPU_BASED_VM_EXEC_CONTROL, reg | (1 << 31));
	InvVpidAllContext();
}

void DisableEpt()
{
	UINT64 reg = _ReadVMCS(SECONDARY_VM_EXEC_CONTROL);
	_WriteVMCS(SECONDARY_VM_EXEC_CONTROL, reg & ~((1 << 5) | (1 << 1)));

	// Clear out the EPTP
	_WriteVMCS(EPT_POINTER_FULL, 0);
	//_WriteVMCS(EPT_POINTER_HIGH, 0);
}

EptPml4Entry * InitEptIdentityMap()
{
	EptPml4Entry *pml4Ptr = NULL;
	EptPdpteEntry *pdptePtr = NULL;
	PHYSICAL_ADDRESS phys = { 0 }, Highest = { 0 }, Lowest = { 0 };
	UINT32 i, j, pdeCounter = 0;

	Highest.LowPart = ~0;

	// Allocate contiguous, un-cached memory
	pml4Ptr = (EptPml4Entry *)MmAllocateContiguousMemorySpecifyCache(
		sizeof(EptPml4Entry)* 512,
		Lowest,
		Highest,
		Lowest,
		MmNonCached);

	if (pml4Ptr == NULL)
	{
		return NULL;
	}

	pdptePtr = (EptPdpteEntry *)MmAllocateContiguousMemorySpecifyCache(
		sizeof(EptPdpteEntry)* 512,
		Lowest,
		Highest,
		Lowest,
		MmNonCached);
	// Save a copy of the virtual address for later freeing
	BkupPdptePtr = pdptePtr;
	if (pdptePtr == NULL)
	{
		MmFreeContiguousMemory(pml4Ptr);
		return NULL;
	}

	for (i = 0; i < NUM_PD_PAGES; i++)
	{
		BkupPdePtrs[i] = (EptPdeEntry2Mb *)MmAllocateContiguousMemorySpecifyCache(
			sizeof(EptPdeEntry2Mb)* 512,
			Lowest,
			Highest,
			Lowest,
			MmNonCached);

		// Free memory if we fail to allocate the next chunk
		if (BkupPdePtrs[i] != NULL)
		{
			RtlZeroMemory((void *)BkupPdePtrs[i], sizeof(EptPdeEntry2Mb)* 512);
		}
		else
		{
			MmFreeContiguousMemory(pml4Ptr);
			MmFreeContiguousMemory(pdptePtr);
			for (j = 0; j < i; j++)
			{
				MmFreeContiguousMemory(BkupPdePtrs[j]);
			}
			return NULL;
		}
	}

	phys = MmGetPhysicalAddress((void *)pdptePtr);

	// Zero out the pages
	RtlZeroMemory((void *)pml4Ptr, sizeof(EptPml4Entry)* 512);
	RtlZeroMemory((void *)pdptePtr, sizeof(EptPdpteEntry)* 512);

	// Populate our newly created EPT tables!
	// Only need the first PML4 Entry unless we have more than 512 GB of RAM
	pml4Ptr->Present = 1;
	pml4Ptr->Write = 1;
	pml4Ptr->Execute = 1;
	pml4Ptr->PhysAddr = phys.LowPart >> 12;

	// Establish an identity map
	for (i = 0; i < NUM_PD_PAGES; i++)
	{
		phys = MmGetPhysicalAddress((void *)BkupPdePtrs[i]);
		pdptePtr[i].Present = 1;
		pdptePtr[i].Write = 1;
		pdptePtr[i].Execute = 1;
		pdptePtr[i].PhysAddr = phys.LowPart >> 12;

		// Populate our 4GBs worth of PDEs
		for (j = 0; j < 512; j++)
		{
			BkupPdePtrs[i][j].Present = 1;
			BkupPdePtrs[i][j].Write = 1;
			BkupPdePtrs[i][j].MemoryType = EPT_MEMORY_TYPE_WB;
			BkupPdePtrs[i][j].Execute = 1;
			BkupPdePtrs[i][j].Size = 1;
			BkupPdePtrs[i][j].PhysAddr = pdeCounter;
			pdeCounter++;
		}
	}

	return pml4Ptr;
}

void FreeEptIdentityMap(EptPml4Entry * ptr)
{
	UINT32 i;
	if (BkupPdptePtr != NULL) MmFreeContiguousMemory((void *)BkupPdptePtr);
	if (ptr != NULL) MmFreeContiguousMemory((void *)ptr);

	for (i = 0; i < NUM_PD_PAGES; i++)
	{
		if (NULL != BkupPdePtrs[i])
			MmFreeContiguousMemory(BkupPdePtrs[i]);
	}

	for (i = 0; i < EptPageTableCounter; i++)
	{
		if (NULL != (void *)EptTableArray[i])
			MmFreeContiguousMemory((void *)EptTableArray[i]);
	}
}

EptPteEntry * EptMapAddressToPte(UINT64 guestPhysicalAddress, EptPml4Entry * pml4Ptr)
{
	return EptMapAddressToPteDirql(guestPhysicalAddress, pml4Ptr, NULL);
}

UINT8 EptPtExists(UINT64 guestPhysicalAddress)
{
	UINT64 pdpteOff = ((guestPhysicalAddress >> 30) & 0x3),
		pdeOff = ((guestPhysicalAddress >> 21) & 0x1FF);
	EptPdeEntry2Mb *pde = NULL;

	// Map in correct PDE
	pde = BkupPdePtrs[pdpteOff];

	// Determine if this is mapping a large 2MB page or points to a page table    
	return !(pde[pdeOff].Size);
}

EptPteEntry * EptMapAddressToPteDirql(UINT64 guestPhysicalAddress,
	EptPml4Entry * pml4Ptr,
	PagingContext * context)
{
	UINT32 i;
	UINT64 pdpteOff = ((guestPhysicalAddress >> 30) & 0x3),
		pdeOff = ((guestPhysicalAddress >> 21) & 0x1FF),
		pteOff = ((guestPhysicalAddress >> 12) & 0x1FF);
	EptPdeEntry2Mb *pde = NULL;
	EptPdpteEntry *pdpte = NULL;
	EptPteEntry *retVal = NULL, *pageTable = NULL;
	PHYSICAL_ADDRESS phys = { 0 };

	// Map in correct PDE
	pde = BkupPdePtrs[pdpteOff];

	// Determine if this is mapping a large 2MB page or points to a page table    
	if (pde[pdeOff].Size == 1)
	{
		// Need to allocate a page table which replaces the 2MB PDE
		phys.LowPart = ~0;
		if (context == NULL)
			pageTable = (EptPteEntry *)MmAllocateContiguousMemory(
			sizeof(EptPteEntry)* 512, phys);
		else
			pageTable = (EptPteEntry *)pagingAllocPage(context);

		if (pageTable == NULL)
		{
			goto abort;
		}
		// Zero out the new page table
		RtlZeroMemory((void *)pageTable, sizeof(EptPteEntry)* 512);

		// Populate the page table
		for (i = 0; i < 512; i++)
		{
			pageTable[i].Present = 1;
			pageTable[i].Write = 1;
			pageTable[i].MemoryType = EPT_MEMORY_TYPE_WB;
			pageTable[i].Execute = 1;
			pageTable[i].PhysAddr = (((pde[pdeOff].PhysAddr << 21) & 0xFFFFFFFF) >> 12) + i;
		}

		pde[pdeOff].Size = 0;
		pde[pdeOff].IgnorePat = 0;
		pde[pdeOff].MemoryType = 0;

		phys = MmGetPhysicalAddress((void *)pageTable);
		((EptPdeEntry *)pde)[pdeOff].PhysAddr = phys.QuadPart >> 12;

		EptTableVirts[TableVirtsCounter] = pageTable;
		TableVirtsCounter++;

		if (context == NULL)
		{
			EptTableArray[EptPageTableCounter] = pageTable;
			EptPageTableCounter++;
		}

		return &pageTable[pteOff];
	}

	// Map in existing PTE to return
	for (i = 0; i < TableVirtsCounter; i++)
	{
		if (EptTableVirts[i][0].PhysAddr << 12 <= guestPhysicalAddress &&
			EptTableVirts[i][511].PhysAddr << 12 >= guestPhysicalAddress)
		{
			return &EptTableVirts[i][pteOff];
		}
	}


abort:
	return retVal;
}

void EptUnmapPte(EptPteEntry * ptr)
{
	EptUnmapPteDirql(ptr, NULL);
}

void EptUnmapPteDirql(EptPteEntry * ptr, PagingContext * context)
{
	if (ptr == NULL)
		return;
	MapOutMemory(context, (void *)ptr, sizeof(EptPteEntry));
}

void MapOutMemory(PagingContext * context, void * ptr, UINT32 size)
{
	if (context == NULL)
		MmUnmapIoSpace(ptr, size);
}

void * MapInMemory(PagingContext * context, PHYSICAL_ADDRESS phys, UINT32 size)
{
	return MmMapIoSpace(phys, size, MmNonCached);
}

void SetTrapFlag(UINT8 value)
{
	UINT64 eflags = _ReadVMCS(GUEST_RFLAGS);
	if (value == 1)
	{
		_WriteVMCS(GUEST_RFLAGS, eflags | (1 << 8));
	}
	else
	{
		_WriteVMCS(GUEST_RFLAGS, eflags & ~(1 << 8));
	}
}

void exit_reason_dispatch_handler__exec_trap(PGUEST_REGS  GuestSTATE)
{
	EptPteEntry *pteptr = NULL;
	TlbTranslation *translationPtr = NULL;
	// Check to see if this is a trap caused by the TLB splitting
	if (!StackIsEmpty(&pteStack))
	{
		translationPtr = (TlbTranslation *)StackPop(&pteStack);
		if (translationPtr != NULL)
			pteptr = translationPtr->EptPte;

		// Mark everything non-present
		if (pteptr != NULL)
		{
			pteptr->Present = 0;
			pteptr->Write = 0;
			pteptr->Execute = 0;
		}
		SetTrapFlag(0);
		if (Thrash)
		{
			InvVpidIndividualAddress(VM_VPID, translationPtr->VirtualAddress);
			if (StackPeek(&pteStack) == translationPtr)
			{
				StackPop(&pteStack);
			}
			else
			{
				translationPtr = (TlbTranslation *)StackPop(&pteStack);
				pteptr = translationPtr->EptPte;
				pteptr->Present = 0;
				pteptr->Write = 0;
				pteptr->Execute = 0;
				InvVpidIndividualAddress(VM_VPID, translationPtr->VirtualAddress);
			}
			Thrash = 0;
			//InvVpidAllContext();
		}
	}
	else
	{
		// @todo Re-inject this interrupt into the guest
		_Int3();
	}
	_WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP));
}

void exit_reason_dispatch_handler__exec_ept(PGUEST_REGS  GuestSTATE)
{
	UINT64 guestPhysical = (_ReadVMCS(GUEST_PHYSICAL_ADDR_FULL)),
		exitQualification = _ReadVMCS(EXIT_QUALIFICATION),
		guestLinear = _ReadVMCS(GUEST_LINEAR_ADDRESS);
	EptPteEntry *pteptr = NULL;
	TlbTranslation *translationPtr = getTlbTranslation(splitPages, guestPhysical);

	// This is a bad sign, it means that it cannot find the proper translation
	if (translationPtr == NULL)
	{
		end_split(splitPages);
		return;
	}

	// @todo Determine the root cause of the stack overflowing
	// Ensure that there is space on the stack
	if (StackIsFull(&pteStack))
		DbgPrint("Overflow!\r\n");

	// Get the faulting EPT PTE
	pteptr = translationPtr->EptPte;
	if (pteptr != NULL && pteptr->Present == 1 && pteptr->Execute == 1)
	{
		return;
	}

	if (!StackIsEmpty(&pteStack) && (void *)translationPtr != StackPeek(&pteStack))
	{
		((TlbTranslation *)StackPeek(&pteStack))->EptPte->Present = 1;
		((TlbTranslation *)StackPeek(&pteStack))->EptPte->Write = 1;
		((TlbTranslation *)StackPeek(&pteStack))->EptPte->Execute = 1;
	}
	StackPush(&pteStack, (void *)translationPtr);
	ViolationExits++;

	/*if (exitQualification & EPT_MASK_GUEST_LINEAR_VALID)
	{
	Log("Guest Linear Address", guestLinear);
	Log("Guest Physical", guestPhysical);
	Log("Guest EIP", GuestSTATE->GuestEIP);
	Log("----------------------------", 0);
	}*/

	if (StackNumEntries(&pteStack) >= 2) // Thrashing
	{
		PHYSICAL_ADDRESS phys = { 0 };
		UINT8 *dataPtr, *codePtr;

		// Check to ensure there has been no instruction corruption
		if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
		{
			phys.QuadPart = translationPtr->DataPhys;
			dataPtr = (UINT8 *)MmMapIoSpace(phys, PAGE_SIZE, MmNonCached);
			phys.QuadPart = translationPtr->CodePhys;
			codePtr = (UINT8 *)MmMapIoSpace(phys, PAGE_SIZE, MmNonCached);
			if (0 != memcmp(dataPtr + (_ReadVMCS(GUEST_RIP) & 0xFFF),
				codePtr + (_ReadVMCS(GUEST_RIP) & 0xFFF),
				_ReadVMCS(VM_EXIT_INSTRUCTION_LEN)))
			{
				memcpy(dataPtr + (_ReadVMCS(GUEST_RIP) & 0xFFF),
					codePtr + (_ReadVMCS(GUEST_RIP) & 0xFFF),
					_ReadVMCS(VM_EXIT_INSTRUCTION_LEN));
			}
			MmUnmapIoSpace(dataPtr, PAGE_SIZE);
			MmUnmapIoSpace(codePtr, PAGE_SIZE);
		}
		else
		{
			//Beep(1);
		}
		Thrash = 1;
		Thrashes++;

		pteptr->PhysAddr = translationPtr->DataPhys >> 12;
		pteptr->Execute = 1;
		pteptr->Present = 1;
		pteptr->Write = 1;
	}
	else
	{
		if (exitQualification & EPT_MASK_DATA_EXEC) // Execute access
		{
			ExecExits++;
			pteptr->PhysAddr = translationPtr->CodePhys >> 12;
			//pteptr->PhysAddr = translationPtr->DataPhys >> 12;
			pteptr->Execute = 1;
		}
		else if (exitQualification & EPT_MASK_DATA_READ ||
			exitQualification & EPT_MASK_DATA_WRITE) // Data access
		{
			DataExits++;
			pteptr->PhysAddr = translationPtr->DataPhys >> 12;
			//pteptr->PhysAddr = translationPtr->CodePhys >> 12;
			pteptr->Present = 1;
			pteptr->Write = 1;
		}
		else
		{
			// Violation that is neither data access nor instruction fetch
			//Beep(1);
			_Int3();
		}
	}
	// Set the trap flag to force another VMEXIT to the trap handler
	SetTrapFlag(1);
	//InvEptAllContext();
	//InvVpidAllContext();
}

void init_split(TlbTranslation * arrPtr)
{
	UINT32 i = 0;
	EptPteEntry *pte = NULL;

	// (Re)initialize counters and the stack
	splitPages = arrPtr;
	StackInitStack(&pteStack);

	ViolationExits = 0;
	DataExits = 0;
	ExecExits = 0;
	Thrashes = 0;
	Thrash = 0;
#ifdef SPLIT_TLB
	//Log("Initializing TLB split", 0);
	// For all the defined target pages
	while (arrPtr[i].DataPhys != 0 && i < appsize / PAGE_SIZE)
	{
		// Determine which guest physical address is the one to be marked non-present 
		if (arrPtr[i].CodeOrData == CODE_EPT)
		{
			pte = EptMapAddressToPte(arrPtr[i].CodePhys, NULL);
		}
		else
		{
			pte = EptMapAddressToPte(arrPtr[i].DataPhys, NULL);
		}
		pte->Present = 0;
		pte->Write = 0;
		pte->Execute = 0;
		arrPtr[i].EptPte = pte;
		i++;
	}
	// Clear the TLB
	InvEptAllContext();
	InvVpidAllContext();
#endif
}

void end_split(TlbTranslation * arrPtr)
{
	UINT32 i = 0;
	EptPteEntry *pte = NULL;
#ifdef SPLIT_TLB
	//Log("Tear-down TLB split", 0);
	DbgPrint("%d Total Violations: %d Data and %d Exec %d Thrashes\r\n",
		ViolationExits,
		DataExits,
		ExecExits,
		Thrashes);
	if (arrPtr != NULL)
	{
		while (arrPtr[i].DataPhys != 0 && i < appsize / PAGE_SIZE)
		{
			// Restore the identity map
			pte = arrPtr[i].EptPte;
			if (arrPtr[i].CodeOrData == CODE_EPT)
			{
				pte->PhysAddr = arrPtr[i].CodePhys >> 12;
			}
			else
			{
				pte->PhysAddr = arrPtr[i].DataPhys >> 12;
			}
			pte->Present = 1;
			pte->Write = 1;
			pte->Execute = 1;
			i++;
		}
		// Invalidate TLB
		InvEptAllContext();
		InvVpidAllContext();
	}
	else
	{
		//Beep(1);
	}
#endif
	splitPages = NULL;
	StackInitStack(&pteStack);
}

static void __invVpidAllContext(UINT64 invtype, InvVpidDesc desc)
{
	_invvpid(invtype, (ULONG64)&desc);
}

void InvVpidAllContext()
{
	InvVpidDesc desc = { 0 };
	__invVpidAllContext(2, desc);
}

void InvVpidIndividualAddress(UINT16 vpid, UINT64 address)
{
	InvVpidDesc desc = { 0 };
	if (ProcessorSupportsType0InvVpid == 1) // Ensure the process supports this type
	{
		desc.bits.LinearAddress = address;
		desc.bits.Vpid = vpid;
		__invVpidAllContext(0, desc);
	}
	else
	{
		__invVpidAllContext(2, desc);
	}
}

void InvEptAllContext()
{
	InvVpidDesc desc = { 0 };
	_invept(2, (ULONG64)&desc);
}
