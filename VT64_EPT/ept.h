#pragma once
#include "Def.h"
#define _X64_


/*
//p2m
*/
#define P2M_READABLE			0x01
#define P2M_WRITABLE			0x02
#define P2M_EXECUTABLE			0x04
#define P2M_FULL_ACCESS			(P2M_READABLE | P2M_WRITABLE | P2M_EXECUTABLE)

typedef enum
{
	P2M_UPDATE_MFN = 1,
	P2M_UPDATE_REMAININGS = 2,
	P2M_UPDATE_MT = 4,
	P2M_UPDATE_ALL = 7
} P2M_UPDATE_TYPE;

/*
//eptp
*/
#define EPT_DEFAULT_MT      	6
#define EPT_DEFAULT_GAW     	3
#define EPT_TABLE_ORDER     	9

#define EPT_EACHTABLE_ENTRIES 	512
// The <ept_entry_t> declaration is stolen from Xen 4. Shame...

/* EPT violation qualifications definitions */
#define _EPT_READ_VIOLATION         0
#define EPT_READ_VIOLATION          (1UL<<_EPT_READ_VIOLATION)
#define _EPT_WRITE_VIOLATION        1
#define EPT_WRITE_VIOLATION         (1UL<<_EPT_WRITE_VIOLATION)
#define _EPT_EXEC_VIOLATION         2
#define EPT_EXEC_VIOLATION          (1UL<<_EPT_EXEC_VIOLATION)
#define _EPT_EFFECTIVE_READ         3
#define EPT_EFFECTIVE_READ          (1UL<<_EPT_EFFECTIVE_READ)
#define _EPT_EFFECTIVE_WRITE        4
#define EPT_EFFECTIVE_WRITE         (1UL<<_EPT_EFFECTIVE_WRITE)
#define _EPT_EFFECTIVE_EXEC         5
#define EPT_EFFECTIVE_EXEC          (1UL<<_EPT_EFFECTIVE_EXEC)
#define _EPT_GAW_VIOLATION          6
#define EPT_GAW_VIOLATION           (1UL<<_EPT_GAW_VIOLATION)
#define _EPT_GLA_VALID              7
#define EPT_GLA_VALID               (1UL<<_EPT_GLA_VALID)
#define _EPT_GLA_FAULT              8
#define EPT_GLA_FAULT               (1UL<<_EPT_GLA_FAULT)

typedef union {
	struct {
		ULONG64 r : 1,
		w : 1,
		x : 1,
		emt : 3, /* EPT Memory type */
		ipat : 1, /* Ignore PAT memory type */
		sp_avail : 1, /* Is this a superpage? */
		avail1 : 4,
		mfn : 40,
		avail2 : 12;
	};
	ULONG64 epte;
} ept_entry_t;

typedef union{
	struct {
		ULONG64 etmt : 3,
		gaw : 3,
		rsvd : 6,
		asr : 52;
	};
	ULONG64 eptp;
}ept_control;

/*
//mtrr
*/
#define MTRR_TYPE_UNCACHABLE 0
#define MTRR_TYPE_WRCOMB     1
#define MTRR_TYPE_WRTHROUGH  4
#define MTRR_TYPE_WRPROT     5
#define MTRR_TYPE_WRBACK     6
#define MTRR_NUM_TYPES       7


/*
//page
*/

#define BITS_PER_LONG 64
#define BYTES_PER_LONG 8
#define LONG_BYTEORDER 3
#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39
#define ROOT_PAGETABLE_SHIFT    L4_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L4_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define ROOT_PAGETABLE_ENTRIES  L4_PAGETABLE_ENTRIES

/* Convert between frame number and address formats.  */
#define gfn_to_gpaddr(gfn)	((ULONG64)(gfn) << PAGE_SHIFT)
#define gpaddr_to_gfn(addr)	((ULONG64)((addr & 0x000ffffffffff000) >> PAGE_SHIFT))

#define gvfn_to_gvaddr(gvfn)	((ULONG64)(gvfn) << PAGE_SHIFT)
#define gvaddr_to_gvfn(addr)	((ULONG64)((addr & 0xfffffffffffff000) >> PAGE_SHIFT))

#define mfn_to_mpaddr(mfn)	((ULONG64)(mfn) << PAGE_SHIFT)
#define mpaddr_to_mfn(addr)	((ULONG64)((addr & 0xfffffffffffff000) >> PAGE_SHIFT))

#define pagetable_get_fn(x)    ((ULONG64)(x))

#define PG_shift(idx)       (BITS_PER_LONG - (idx))
#define PG_mask(x, idx)     ((ULONG64)x ## UL << PG_shift(idx))

#define PGT_PAT_dont_free       PG_mask(1, 6) 
#define PGT_PAT_pool            PG_mask(2, 6)
#define PGT_PAT_contiguous      PG_mask(3, 6) 
#define PGT_PAT_mask     		PG_mask(3, 6) 



typedef struct ept
{
	union {
		struct {
			UINT64 ept_mt : 3,
			ept_wl : 3,
				 rsvd : 6,
					asr : 52;
		};
		UINT64 eptp;
	} ept_control;
	UINT64 lock;
	UINT64 holder;  /* processor which holds the lock */
	BOOLEAN need_flush;
	//BOOLEAN can_remap; //[TODO] Ugly design, Currently I enable it when all the cores have Vis installed. 

	/* Shadow translated domain: P2M mapping */
	UINT64 p2m_table;

	UINT64 spare_page_gpaddr;
	UINT64 spare_page_gvaddr;

	NTSTATUS(NTAPI *p2m_create_mapping)(UINT64 gfn, UINT64 mfn, ULONG32 p2m_type,
		BOOLEAN bLargePage);
	VOID(NTAPI *p2m_tlb_flush)(void);
	VOID(NTAPI *p2m_vpid_flush)(void);
	NTSTATUS(NTAPI *p2m_create_identity_map)(void);

	NTSTATUS(NTAPI *p2m_update_mapping)(UINT64 gfn, UINT64 mfn, ULONG32 p2m_type,
		BOOLEAN bLargePage, P2M_UPDATE_TYPE op_type);

	NTSTATUS(NTAPI *p2m_update_all_mapping)(ULONG32 p2m_type);
	ULONG   mm_lowest_gfn;
	ULONG   mm_highest_gfn;
	ULONG   mm_num_gfn;
}EPT, *LPEPT;

EPT MyEpt = { 0 };
/*
//memory
*/
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,                 //  0 Y N  
	SystemProcessorInformation,             //  1 Y N  
	SystemPerformanceInformation,           //  2 Y N  
	SystemTimeOfDayInformation,             //  3 Y N  
	SystemNotImplemented1,                  //  4 Y N  
	SystemProcessesAndThreadsInformation,   //  5 Y N  
	SystemCallCounts,                       //  6 Y N  
	SystemConfigurationInformation,         //  7 Y N  
	SystemProcessorTimes,                   //  8 Y N  
	SystemGlobalFlag,                       //  9 Y Y  
	SystemNotImplemented2,                  // 10 Y N  
	SystemModuleInformation,                // 11 Y N  
	SystemLockInformation,                  // 12 Y N  
	SystemNotImplemented3,                  // 13 Y N  
	SystemNotImplemented4,                  // 14 Y N  
	SystemNotImplemented5,                  // 15 Y N  
	SystemHandleInformation,                // 16 Y N  
	SystemObjectInformation,                // 17 Y N  
	SystemPagefileInformation,              // 18 Y N  
	SystemInstructionEmulationCounts,       // 19 Y N  
	SystemInvalidInfoClass1,                // 20  
	SystemCacheInformation,                 // 21 Y Y  
	SystemPoolTagInformation,               // 22 Y N  
	SystemProcessorStatistics,              // 23 Y N  
	SystemDpcInformation,                   // 24 Y Y  
	SystemNotImplemented6,                  // 25 Y N  
	SystemLoadImage,                        // 26 N Y  
	SystemUnloadImage,                      // 27 N Y  
	SystemTimeAdjustment,                   // 28 Y Y  
	SystemNotImplemented7,                  // 29 Y N  
	SystemNotImplemented8,                  // 30 Y N  
	SystemNotImplemented9,                  // 31 Y N  
	SystemCrashDumpInformation,             // 32 Y N  
	SystemExceptionInformation,             // 33 Y N  
	SystemCrashDumpStateInformation,        // 34 Y Y/N  
	SystemKernelDebuggerInformation,        // 35 Y N  
	SystemContextSwitchInformation,         // 36 Y N  
	SystemRegistryQuotaInformation,         // 37 Y Y  
	SystemLoadAndCallImage,                 // 38 N Y  
	SystemPrioritySeparation,               // 39 N Y  
	SystemNotImplemented10,                 // 40 Y N  
	SystemNotImplemented11,                 // 41 Y N  
	SystemInvalidInfoClass2,                // 42  
	SystemInvalidInfoClass3,                // 43  
	SystemTimeZoneInformation,              // 44 Y N  
	SystemLookasideInformation,             // 45 Y N  
	SystemSetTimeSlipEvent,                 // 46 N Y  
	SystemCreateSession,                    // 47 N Y  
	SystemDeleteSession,                    // 48 N Y  
	SystemInvalidInfoClass4,                // 49  
	SystemRangeStartInformation,            // 50 Y N  
	SystemVerifierInformation,              // 51 Y Y  
	SystemAddVerifier,                      // 52 N Y  
	SystemSessionProcessesInformation       // 53 Y N  

} SYSTEM_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
	);
ULONG64 NTAPI MmAllocateContiguousPagesSpecifyCache(
	ULONG uNumberOfPages,
	ULONG64 *pFirstPagePA,
	ULONG CacheType,
	BOOLEAN hide_this_page
	);
struct page_info
{
	LIST_ENTRY le;

	/* Reference count  */
	ULONG32 count_ref;

	/* and various PGT_xxx flags and fields */
	// Must use ULONG type, since it takes 32bit in X86 and 64bit in X64
	// PGT_xxx macros has compatibility with different platforms.
	ULONG64 type_info;

	//for PGT_PAT_contiguous only
	ULONG32 uNumberOfPages;

	ULONG64 gvaddr;
	ULONG64 gfn;
	ULONG64 mfn;

	// for concealing page usage, avoid seal the same page on multi-core platform 
	BOOLEAN remapped;

};
#define NO_HOLDER	~0;
typedef ULONG_PTR spinlock_t;
static LIST_ENTRY list_alloc_pages;
static KSPIN_LOCK list_alloc_pages_lock;
static ULONG lock_holder = NO_HOLDER;

static LIST_ENTRY* list_last_checkpoint = &list_alloc_pages;
static LIST_ENTRY* list_cur_checkpoint;

//static gpaddr_t spare_page_gpaddr = 0;
//static gvaddr_t spare_page_gvaddr = 0;

PDRIVER_OBJECT DriverObject;

//SystemBasicInfo
typedef struct _SYSTEM_BASIC_INFORMATION
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

LIST_ENTRY* DDKExInterlockedRemoveHeadList(LIST_ENTRY* list, spinlock_t* lock)
{
	LIST_ENTRY* result = NULL;
	LIST_ENTRY* next_element;

	_spin_lock_acquire(lock);
	result = list->Flink;
	next_element = result->Flink;

	if (result == list)
	{
		_spin_lock_release(lock);
		return NULL;
	}

	list->Flink = next_element;
	next_element->Blink = list;
	_spin_lock_release(lock);

	return result;
}


VOID DDKExInterlockedInsertTailList(LIST_ENTRY* list, LIST_ENTRY* entry, KSPIN_LOCK* lock)
{
	LIST_ENTRY* last_ele;

	_spin_lock_acquire(lock);
	last_ele = list->Blink;
	last_ele->Flink = entry;
	entry->Blink = last_ele;
	entry->Flink = list;
	list->Blink = entry;
	_spin_lock_release(lock);
}

static struct page_info* NTAPI mm_save_page(
	ULONG64 gvaddr,
	ULONG64 gpaddr,
	ULONG64 mpaddr,
	ULONG64 pg_type,
	ULONG uNumberOfPages
	)
{
	ULONG64 gfn;
	ULONG64 mfn;
	struct page_info *new_pginfo;

	//assert(gvaddr, ("mm_save_page(): gvaddr is a null pointer"));
	if (!gvaddr)
	{
		_Int3();
	}

	new_pginfo = ExAllocatePoolWithTag(NonPagedPool,
		sizeof (struct page_info), ITL_TAG);

	//assert(new_pginfo, ("mm_save_page(): Insufficient Memory Resources"));
	if (!new_pginfo)
	{
		_Int3();
	}

	RtlZeroMemory(new_pginfo, sizeof (struct page_info));

	gfn = gpaddr_to_gfn(gpaddr);
	mfn = mpaddr_to_mfn(mpaddr);

	new_pginfo->count_ref = 0;
	new_pginfo->type_info = pg_type;
	new_pginfo->mfn = mfn;
	new_pginfo->gfn = gfn;
	new_pginfo->gvaddr = gvaddr;
	new_pginfo->uNumberOfPages = uNumberOfPages;

	DDKExInterlockedInsertTailList(&list_alloc_pages, &new_pginfo->le,
		&list_alloc_pages_lock);

	list_cur_checkpoint = &new_pginfo->le;
	//dprint(PRINT_INFO, ("gva: 0x%llx, gvfn: 0x%llx, gfn: 0x%llx, mfn: 0x%llx",gvaddr, gvaddr_to_gvfn(gvaddr), gfn, mfn));

	return new_pginfo;
}

NTSTATUS NTAPI mm_map_machine_pfns(EPT* arch)
{
	/* [TODO] Currently I choose to map all the pfns on the x86 platform.
	* A more precise solution is to query the os available pfns and mapping them
	* However, this is OS version specied and seems not very good.
	*/
	NTSTATUS status;
	ULONG64 gfn;

	if (!arch->p2m_create_identity_map)
		return STATUS_UNSUCCESSFUL;

	arch->p2m_create_identity_map();

	return STATUS_SUCCESS;
}

VOID NTAPI mm_hide_vis_code(void)
{
	/*
	* We don't need to really *HIDE* the Vis code segment now. Instead, we register them in the <list_alloc_pages>
	* The reason is that, all pages appeared as entries in the <list_alloc_pages> struct will be concealed.
	*/
	ULONG mapped_sizes;
	ULONG64 gpaddr;
	ULONG64 gvaddr;
	ULONG upages;

	upages = BYTES_TO_PAGES(DriverObject->DriverSize);

	for (mapped_sizes = 0; mapped_sizes < DriverObject->DriverSize - PAGE_SIZE;
		mapped_sizes += PAGE_SIZE)
	{
		gvaddr = (ULONG64)DriverObject->DriverStart + mapped_sizes;

#if defined (_X86_)
		gpaddr = MmGetPhysicalAddress((PVOID)gvaddr).LowPart;
#elif defined (_X64_)
		gpaddr = MmGetPhysicalAddress((PVOID)gvaddr).QuadPart;
#endif

		mm_save_page(gvaddr, gpaddr, MyEpt.spare_page_gpaddr, PGT_PAT_dont_free, upages);
	}
}

/*VOID NTAPI mm_reveal_vis_code (void)
{
/*
* We don't need to really *HIDE* the Vis code segment now. Instead, we register them in the <list_alloc_pages>
* The reason is that, all pages appeared as entries in the <list_alloc_pages> struct will be concealed.
*/
/*ULONG mapped_sizes;
gpaddr_t gpaddr;
gvaddr_t gvaddr;
struct page_info* pginfo;
ULONG upages = BYTES_TO_PAGES (DriverObject->DriverSize);

for (mapped_sizes = 0; mapped_sizes < DriverObject->DriverSize;
mapped_sizes += PAGE_SIZE)
{
gvaddr = (gvaddr_t)DriverObject->DriverStart + mapped_sizes;

#if defined (_X86_)
gpaddr = MmGetPhysicalAddress ((PVOID)gvaddr).LowPart;
#elif defined (_X64_)
gpaddr = MmGetPhysicalAddress ((PVOID)gvaddr).QuadPart;
#endif
MmFindPageByGPA(gpaddr, &pginfo);
assert(pginfo, "mm_reveal_vis_code(): pginfo is a null pointer");
pginfo->remapped = FALSE;

arch->p2m.p2m_create_mapping(gpaddr_to_gfn(gpaddr), gpaddr_to_gfn(gpaddr),
(P2M_READABLE | P2M_WRITABLE | P2M_EXECUTABLE), FALSE);
}
}*/


NTSTATUS NTAPI mm_hide_vis_pages(void)
{
	struct page_info *pg_info, *start_pginfo;
	ULONG64 gfn;
	KIRQL old_irql;

	if (!MyEpt.p2m_update_mapping)
		return STATUS_UNSUCCESSFUL;

	start_pginfo = (struct page_info*)list_cur_checkpoint->Flink;
	pg_info = (struct page_info*)list_last_checkpoint->Flink;

	if (list_cur_checkpoint->Blink == list_last_checkpoint)
	{
		// No new mapping saved in P2m table
		return STATUS_SUCCESS;
	}

	if (lock_holder != KeGetCurrentProcessorNumber())
	{
		KeAcquireSpinLock(&list_alloc_pages_lock, &old_irql);
		lock_holder = KeGetCurrentProcessorNumber();
	}

	do
	{
		pg_info = CONTAINING_RECORD(pg_info, struct page_info, le);

		if (!pg_info->remapped)
		{
			MyEpt.p2m_update_mapping(pg_info->gfn, pg_info->mfn,
				P2M_FULL_ACCESS, FALSE, P2M_UPDATE_MFN);
			pg_info->remapped = TRUE;
		}
		pg_info = (struct page_info *) pg_info->le.Flink;
	} while (start_pginfo != pg_info);

	list_last_checkpoint = list_cur_checkpoint;
	if (lock_holder == KeGetCurrentProcessorNumber())
	{
		KeReleaseSpinLock(&list_alloc_pages_lock, old_irql);
		lock_holder = NO_HOLDER;
	}
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmFindPageByGPA(
	ULONG64 gpaddr,
struct page_info **ppg_info
	)
{
	struct page_info *pg_info, *last_pg_info;
	ULONG64 gfn;
	KIRQL old_irql;

	//assert(ppg_info, ("MmFindPageByGPA(): ppg_info is a null pointer"));
	if (!ppg_info)
	{
		_Int3();
	}

	if (lock_holder != KeGetCurrentProcessorNumber())
	{
		KeAcquireSpinLock(&list_alloc_pages_lock, &old_irql);
		lock_holder = KeGetCurrentProcessorNumber();
	}

	gfn = gpaddr_to_gfn(gpaddr);
	pg_info = (struct page_info*)list_alloc_pages.Flink;

	while (pg_info != (struct page_info*) &list_alloc_pages) {
		pg_info = CONTAINING_RECORD(pg_info, struct page_info, le);

		if (pg_info->gfn == gfn) {
			*ppg_info = pg_info;
			pg_info->count_ref++;

			if (lock_holder == KeGetCurrentProcessorNumber())
			{
				KeReleaseSpinLock(&list_alloc_pages_lock, old_irql);
				lock_holder = NO_HOLDER;
			}
			return STATUS_SUCCESS;
		}
		// [Superymk] Debug here
		if (!pg_info->le.Flink)
			return STATUS_UNSUCCESSFUL; //__asm {int 3}

		last_pg_info = pg_info;
		pg_info = (struct page_info *) pg_info->le.Flink;
	}

	if (lock_holder == KeGetCurrentProcessorNumber())
	{
		KeReleaseSpinLock(&list_alloc_pages_lock, old_irql);
		lock_holder = NO_HOLDER;
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI MmFindPageByGVA(
	ULONG64 gvaddr,
struct page_info **ppg_info
	)
{
	struct page_info *pg_info;
	ULONG64 gvfn, pg_gvfn;
	KIRQL old_irql;

	//assert(ppg_info, ("MmFindPageByGVA(): ppg_info is a null pointer"));

	if (!ppg_info)
	{
		_Int3();
	}
	if (lock_holder != KeGetCurrentProcessorNumber())
	{
		KeAcquireSpinLock(&list_alloc_pages_lock, &old_irql);
		lock_holder = KeGetCurrentProcessorNumber();
	}

	gvfn = gvaddr_to_gvfn(gvaddr);
	pg_info = (struct page_info*)list_alloc_pages.Flink;
	while (pg_info != (struct page_info*) &list_alloc_pages) {
		pg_info = CONTAINING_RECORD(pg_info, struct page_info, le);

		if (gvaddr_to_gvfn(pg_info->gvaddr) == gvfn) {
			*ppg_info = pg_info;
			pg_info->count_ref++;

			if (lock_holder == KeGetCurrentProcessorNumber())
			{
				KeReleaseSpinLock(&list_alloc_pages_lock, old_irql);
				lock_holder = NO_HOLDER;
			}
			return STATUS_SUCCESS;
		}
		pg_info = (struct page_info *) pg_info->le.Flink;
	}

	if (lock_holder == KeGetCurrentProcessorNumber())
	{
		KeReleaseSpinLock(&list_alloc_pages_lock, old_irql);
		lock_holder = NO_HOLDER;
	}
	return STATUS_UNSUCCESSFUL;
}

/**
* effects: Allocate <uNumberOfPages> pages from memory.
*/
ULONG64 NTAPI MmAllocatePages(
	ULONG uNumberOfPages,
	ULONG64 *pFirstPagePA,
	BOOLEAN hide_this_page
	)
{
	ULONG64 PageVA, FirstPage;
	ULONG64 PagePA;
	NTSTATUS Status;
	struct page_info* pginfo;

	ULONG i;

	if (!uNumberOfPages)
		return 0;

	FirstPage = PageVA = (ULONG64)ExAllocatePoolWithTag(NonPagedPool,
		uNumberOfPages * PAGE_SIZE, ITL_TAG);
	//assert(PageVA, ("MmAllocatePages(): Memory allocation error"));
	if (!PageVA)
	{
		_Int3();
	}
	RtlZeroMemory((PVOID)PageVA, uNumberOfPages * PAGE_SIZE);

	if (pFirstPagePA)
#if defined (_X86_)
		*pFirstPagePA = MmGetPhysicalAddress((PVOID)PageVA).LowPart;
#elif defined (_X64_)
		*pFirstPagePA = MmGetPhysicalAddress((PVOID)PageVA).QuadPart;
#endif

	if (hide_this_page)
	{
		for (i = 0; i < uNumberOfPages; i++) {
			// map to the same addresses in the host pagetables as they are in guest's
#if defined (_X86_)
			PagePA = MmGetPhysicalAddress((PVOID)PageVA).LowPart;
#elif defined (_X64_)
			PagePA = MmGetPhysicalAddress((PVOID)PageVA).QuadPart;
#endif

			pginfo = mm_save_page(PageVA, PagePA, MyEpt.spare_page_gpaddr,
				!i ? PGT_PAT_pool : PGT_PAT_dont_free, uNumberOfPages);

			PageVA = PageVA + PAGE_SIZE;
		}
	}

	return FirstPage;
}
/**
* effects: Allocate Contiguous Pages from memory.
*/
ULONG64 NTAPI MmAllocateContiguousPages(
	ULONG uNumberOfPages,
	ULONG64 *pFirstPagePA,
	BOOLEAN hide_this_page
	)
{
	return MmAllocateContiguousPagesSpecifyCache(
		uNumberOfPages,
		pFirstPagePA,
		MmCached,
		hide_this_page);
}
/**
* effects: Allocate Contiguous Pages from memory with the indicated cache strategy.
*/
ULONG64 NTAPI MmAllocateContiguousPagesSpecifyCache(
	ULONG uNumberOfPages,
	ULONG64 *pFirstPagePA,
	ULONG CacheType,
	BOOLEAN hide_this_page
	)
{
	ULONG64 PageVA, FirstPage;
	ULONG64 PagePA;
	PHYSICAL_ADDRESS l1, l2, l3;
	NTSTATUS Status;
	struct page_info* pginfo;
	ULONG i;

	if (!uNumberOfPages)
		return 0;

	l1.QuadPart = 0;
	l2.QuadPart = -1;
	l3.QuadPart = 0x200000;    // 0x10000 ?

	FirstPage = PageVA = (ULONG64)MmAllocateContiguousMemorySpecifyCache(
		uNumberOfPages * PAGE_SIZE,
		l1,
		l2,
		l3,
		CacheType);
	if (!PageVA)
		return 0;

	RtlZeroMemory((PVOID)PageVA, uNumberOfPages * PAGE_SIZE);

#if defined (_X86_)
	PagePA = MmGetPhysicalAddress((PVOID)PageVA).LowPart;
#elif defined (_X64_)
	PagePA = MmGetPhysicalAddress((PVOID)PageVA).QuadPart;
#endif

	if (pFirstPagePA)
		*pFirstPagePA = PagePA;

	if (hide_this_page)
	{
		for (i = 0; i < uNumberOfPages; i++) {
			// map to the same addresses in the host pagetables as they are in guest's
			pginfo = mm_save_page(PageVA, PagePA, MyEpt.spare_page_gpaddr,
				!i ? PGT_PAT_contiguous : PGT_PAT_dont_free, uNumberOfPages);

			PageVA = PageVA + PAGE_SIZE;
			PagePA += PAGE_SIZE;
		}
	}

	return FirstPage;
}

static VOID NTAPI mm_init_globals(void)
{

	SYSTEM_BASIC_INFORMATION BasicSystemInfo;
	NTSTATUS rc;
	ULONG rlench = 0;

	//memset(&BasicSystemInfo, 0, sizeof(BASICSYSTEMINFO));
	rc = ZwQuerySystemInformation(SystemBasicInformation,
		&BasicSystemInfo,
		sizeof(SYSTEM_BASIC_INFORMATION),
		&rlench);

	//assert((rc == STATUS_SUCCESS), ("mm_init_globals():Error in querying physical memory info."));

	if (!(NT_SUCCESS(rc)))
	{
		_Int3();
		rc = ZwQuerySystemInformation(SystemBasicInformation,
			&BasicSystemInfo,
			rlench,
			&rlench);
	}
	MyEpt.mm_highest_gfn = (BasicSystemInfo.HighestPhysicalPageNumber);
	MyEpt.mm_lowest_gfn = (BasicSystemInfo.LowestPhysicalPageNumber);
	MyEpt.mm_num_gfn = BasicSystemInfo.NumberOfPhysicalPages;
}

static VOID NTAPI mm_init_spare_page(void)
{
	// [TODO] We need to add a spinlock to this function in order to make it thread-safe.
	PHYSICAL_ADDRESS l1, l2, l3;
	ULONG64 *spare_page_gpaddr = &MyEpt.spare_page_gpaddr;
	ULONG64 *spare_page_gvaddr = &MyEpt.spare_page_gvaddr;

	InitializeListHead(&list_alloc_pages);
	KeInitializeSpinLock(&list_alloc_pages_lock);

	l1.QuadPart = 0;
	l2.QuadPart = -1;
	l3.QuadPart = 0x200000;
	*spare_page_gvaddr = (ULONG64)MmAllocateContiguousMemorySpecifyCache(
		PAGE_SIZE,
		l1,
		l2,
		l3,
		MmCached);
	//assert(*spare_page_gvaddr, ("mm_init_spare_page(): spare_page_gvaddr is a null pointer"));
	if (!(*spare_page_gvaddr))
	{
		_Int3();
	}
	RtlZeroMemory((PVOID)*spare_page_gvaddr, PAGE_SIZE);

#if defined (_X86_)
	*spare_page_gpaddr = MmGetPhysicalAddress((PVOID)*spare_page_gvaddr).LowPart;
#elif defined (_X64_)
	*spare_page_gpaddr = MmGetPhysicalAddress((PVOID)*spare_page_gvaddr).QuadPart;
#endif

	//assert(spare_page_gpaddr, ("mm_init_spare_page(): spare_page_gpaddr has an invalid value"));
	if (!spare_page_gpaddr)
	{
		_Int3();
	}

}

/*
* Allocate a page for spare page. Its gva will be used again when finalizing the MM module.
* Its gpa will be used in remapping procedure in p2m module to achieve transparency.
*/
VOID NTAPI mm_init( PDRIVER_OBJECT pDriverObject)
{
	DriverObject = pDriverObject;

	mm_init_globals();
	mm_init_spare_page();
}

VOID NTAPI mm_finalize(
	)
{
	struct page_info *pg_info;
	ULONG i;
	PULONG64 Entry;

	while (pg_info =
		(struct page_info *) DDKExInterlockedRemoveHeadList(
		&list_alloc_pages,
		&list_alloc_pages_lock))
	{

		pg_info = CONTAINING_RECORD(pg_info, struct page_info, le);

		/*switch (pg_info->type_info & PGT_PAT_mask) {
		case PGT_PAT_pool:
			ExFreePool((PVOID)pg_info->gvaddr);
			break;
		case PGT_PAT_contiguous:
			MmFreeContiguousMemorySpecifyCache((PVOID)pg_info->gvaddr,
				pg_info->uNumberOfPages * PAGE_SIZE, MmCached);
			break;
		case PGT_PAT_dont_free:
			// this is not the first page in the allocation
			break;
		}*/
		ExFreePool((PVOID)pg_info);
	}

	//Free SparePage
	MmFreeContiguousMemorySpecifyCache((PVOID)MyEpt.spare_page_gvaddr, PAGE_SIZE,
		MmCached);

	MyEpt.spare_page_gpaddr = 0;
	MyEpt.spare_page_gvaddr = 0;
}

/*NTSTATUS NTAPI mm_hide_vis_data(struct arch_phy* arch)
{
NTSTATUS status;
status = mm_map_machine_pfns(arch);
if(!NT_SUCCESS (status))
return status;

/*status = mm_hide_vis_pages(arch);
if(!NT_SUCCESS (status))
return status; */

/*return STATUS_SUCCESS;
}*/

NTSTATUS NTAPI mm_reveal_all_pages(void)
{
	struct page_info *pg_info;
	KIRQL old_irql;

	if (!MyEpt.p2m_update_mapping)
		return STATUS_UNSUCCESSFUL;

	if (lock_holder != KeGetCurrentProcessorNumber())
	{
		KeAcquireSpinLock(&list_alloc_pages_lock, &old_irql);
		lock_holder = KeGetCurrentProcessorNumber();
	}

	pg_info = (struct page_info*)list_alloc_pages.Flink;
	while (pg_info != (struct page_info*) &list_alloc_pages) {
		pg_info = CONTAINING_RECORD(pg_info, struct page_info, le);
		//assert((pg_info), ("mm_reveal_all_pages(): invalid pg_info"));

		if (!pg_info)
		{
			_Int3();
		}
		pg_info->remapped = FALSE;

		MyEpt.p2m_update_mapping(pg_info->gfn, pg_info->gfn,
			P2M_FULL_ACCESS, FALSE, P2M_UPDATE_MFN);
		pg_info = (struct page_info *) pg_info->le.Flink;
	}

	if (lock_holder == KeGetCurrentProcessorNumber())
	{
		KeReleaseSpinLock(&list_alloc_pages_lock, old_irql);
		lock_holder = NO_HOLDER;
	}
	return STATUS_SUCCESS;
}

/**

/*
// ept
*/
#define VIS_EXIT_FN		200
#define HOST_STACK_SIZE_IN_PAGES	16

#define BP_GDT_LIMIT	        0x6f
#define BP_IDT_LIMIT	        0xfff

/* Since we record Intel/AMD's VT feature in a condensed
manner, it is required to use (ARCH_VMX | ARCH_EPT) to check the EPT support, instead of using ARCH_EPT flag only. */
/* <hvm_arch.archtecture> field layout */
/*      Bit 31(63): Vmx/SVM
Bit 30: NoHAP/EPT(NPT)
Bit 29: NoVPID/VPID(ASID)*/
#define ARCH_shift(idx)       (BITS_PER_LONG - (idx))
#define ARCH_mask(x, idx)     (x ## UL << ARCH_shift(idx))

/* HVM Technology: AMD or Intel? */
#define ARCH_VMX        PG_mask(0, 1) 
#define ARCH_SVM        PG_mask(1, 1)

/* HAP support (EPT/NPT) */
#define ARCH_NO_HAP     PG_mask(0, 2) 
#define ARCH_EPT        PG_mask(1, 2)
#define ARCH_NPT        PG_mask(1, 2)

/* VPID support (VPID/ASID) */
#define ARCH_NO_VPID     PG_mask(0, 3) 
#define ARCH_VPID        PG_mask(1, 3)
#define ARCH_ASID        PG_mask(1, 3)
#define paging_mode_ept(_MyEpt) ((_MyEpt).architecture & (ARCH_VMX | ARCH_EPT))
struct page_info* ept_pml4_page;



static NTSTATUS NTAPI ept_update_table(
	PULONG64 PageTable,
	UCHAR PageTableLevel,
	ULONG64 gfn,
	ULONG64 mfn,
	ULONG32 p2m_type,
	BOOLEAN bLargePage,
	P2M_UPDATE_TYPE op_type
	)
{
	ULONG64 PageTableOffset, GlobalOffset;
	ULONG64 GlobalOffset1, GlobalOffset2, GlobalOffset3, GlobalOffset4;
	ULONG64 LowerPageTableGuestVA;
	struct page_info *LowerPageTable;
	PHYSICAL_ADDRESS LowerPageTablePA;
	ULONG64 LowerPageTableGfn;
	NTSTATUS Status;
	PHYSICAL_ADDRESS PagePA, l1, l2, l3;
	ept_entry_t ept_entry = { 0 };

	// get the offset in the specified page table level
	PageTableOffset = (((ULONG64)gfn & (((ULONG64)1) << (PageTableLevel * EPT_TABLE_ORDER))
		- 1) >> (((ULONG64)PageTableLevel - 1) * EPT_TABLE_ORDER));

	if ((PageTableLevel == 1) || (bLargePage && (PageTableLevel == 2))) {
		// last level page table
		ept_entry.epte = ((PULONG64)PageTable)[PageTableOffset];

		if (op_type & P2M_UPDATE_MT)
		{
			ept_entry.r = (p2m_type & P2M_READABLE) ? 1 : 0;
			ept_entry.w = (p2m_type & P2M_WRITABLE) ? 1 : 0;
			ept_entry.x = (p2m_type & P2M_EXECUTABLE) ? 1 : 0;
		}

		if (op_type & P2M_UPDATE_REMAININGS)
		{
			ept_entry.emt = MTRR_TYPE_WRBACK;
			ept_entry.ipat = 0;
			ept_entry.sp_avail = 0;
		}

		if (op_type & P2M_UPDATE_MFN)
			ept_entry.mfn = mfn;

		if (bLargePage)
		{
			////assert((PageTableLevel == 2), ("LargePage at the 4th ept page table?"));
			if (PageTableLevel!=2)
			{
				_Int3();
			}
			if (op_type & P2M_UPDATE_REMAININGS)
				ept_entry.sp_avail = 1;
		}
		((PULONG64)PageTable)[PageTableOffset] = ept_entry.epte;
		return STATUS_SUCCESS;
	}
	ept_entry.epte = ((PULONG64)PageTable)[PageTableOffset];
	LowerPageTableGfn = (ULONG64)ept_entry.mfn;

	if (!LowerPageTableGfn) {
		/* we have not allocated this mid level page table before */

		Status = MmFindPageByGPA(gfn_to_gpaddr(LowerPageTableGfn), &LowerPageTable);
		if (!NT_SUCCESS(Status)) {
			LowerPageTableGuestVA = MmAllocatePages(1, (ULONG64*)&LowerPageTablePA.QuadPart, TRUE);
			if (!LowerPageTableGuestVA)
			{
				//panic(("ept_update_table(): no memory"));
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			RtlZeroMemory((PVOID)LowerPageTableGuestVA, PAGE_SIZE);
#if defined(_X86_)
			LowerPageTableGfn = gpaddr_to_gfn(LowerPageTablePA.LowPart);
#elif defined(_X64_)
			LowerPageTableGfn = gpaddr_to_gfn(LowerPageTablePA.QuadPart);
#endif
		}
		else {
			LowerPageTableGfn = LowerPageTable->gfn;
			LowerPageTableGuestVA = LowerPageTable->gvaddr;
		}
		//assert((LowerPageTableGfn), ("LowerPageTableGfn has an invalid value"));

		if (LowerPageTableGfn)
		{
			_Int3();
		}
		ept_entry.r = ept_entry.w = ept_entry.x = 1;
		ept_entry.emt = 0;
		ept_entry.ipat = 0;
		ept_entry.sp_avail = 0;
		ept_entry.mfn = LowerPageTableGfn;
		((PULONG64)PageTable)[PageTableOffset] = ept_entry.epte;

	}
	else {
		/* we have allocated this mid level page table before */
		//Status = MmFindPageByGPA (LowerPageTablePA, &LowerPageTable);
		Status = MmFindPageByGPA(gfn_to_gpaddr(LowerPageTableGfn), &LowerPageTable);

		if (!NT_SUCCESS(Status)) {
			LowerPageTablePA.QuadPart = ((PULONG64)PageTable)[PageTableOffset];
			if ((PageTableLevel == 2) && (LowerPageTablePA.QuadPart & P_LARGE)) {
				//dprint(PRINT_ERROR,("ept_update_table(): Found large PDE, data 0x%p\n", LowerPageTablePA.QuadPart));
				return STATUS_SUCCESS;

			}
			else {
				//dprint(PRINT_ERROR,("ept_update_table(): Failed to find lower page table (pl%d) guest VA, data 0x%p, status 0x%08X\n",PageTableLevel - 1, LowerPageTablePA.QuadPart, Status));
				_Int3();
				return Status;
			}
		}

		LowerPageTableGuestVA = LowerPageTable->gvaddr;
	}

	return ept_update_table((PVOID)LowerPageTableGuestVA, PageTableLevel - 1, gfn, mfn,
		p2m_type, bLargePage, op_type);
}

static NTSTATUS NTAPI ept_update_identity_table(
	PVOID PageTable,
	UCHAR PageTableLevel,
	ULONG gfn,
	ULONG32 p2m_type,
	BOOLEAN bLargePage,
	P2M_UPDATE_TYPE op_type
	)
{
	ULONG64 PageTableOffset, GlobalOffset;
	ULONG64 GlobalOffset1, GlobalOffset2, GlobalOffset3, GlobalOffset4;
	ULONG64 LowerPageTableGuestVA;
	struct page_info *LowerPageTable;
	PHYSICAL_ADDRESS LowerPageTablePA;
	ULONG64 LowerPageTableGfn;
	NTSTATUS Status;
	PHYSICAL_ADDRESS PagePA, l1, l2, l3;
	ept_entry_t ept_entry = { 0 };

	//assert(((gfn & (EPT_EACHTABLE_ENTRIES - 1)) == 0),("ept_update_identity_table(): gfn is not the integer times of PTE, \can't map gfn in the batched way."));
	if (((gfn & (EPT_EACHTABLE_ENTRIES - 1)) != 0))
	{
		_Int3();
	}
	// get the offset in the specified page table level
	PageTableOffset = (((ULONG64)gfn & (((ULONG64)1) << (PageTableLevel * EPT_TABLE_ORDER))
		- 1) >> (((ULONG64)PageTableLevel - 1) * EPT_TABLE_ORDER));

	if ((PageTableLevel == 1) || (bLargePage && (PageTableLevel == 2))) {
		// last level page table
		ULONG i = 0;

		for (i = 0; i < EPT_EACHTABLE_ENTRIES; i++)
		{
			ept_entry.epte = ((PULONG64)PageTable)[PageTableOffset + i];

			if (op_type & P2M_UPDATE_MT)
			{
				ept_entry.r = (p2m_type & P2M_READABLE) ? 1 : 0;
				ept_entry.w = (p2m_type & P2M_WRITABLE) ? 1 : 0;
				ept_entry.x = (p2m_type & P2M_EXECUTABLE) ? 1 : 0;
			}
			//ept_entry.r = ept_entry.w = ept_entry.x = 1;
			if (op_type & P2M_UPDATE_REMAININGS)
			{
				ept_entry.emt = MTRR_TYPE_WRBACK;
				ept_entry.ipat = 0;
				ept_entry.sp_avail = 0;
			}

			if (op_type & P2M_UPDATE_MFN)
				ept_entry.mfn = gfn + i;

			if (bLargePage)
			{
				//assert((PageTableLevel == 2), ("LargePage at the 4th ept page table?"));
				if ((PageTableLevel != 2))
				{
					_Int3();
				}
				if (op_type & P2M_UPDATE_REMAININGS)
					ept_entry.sp_avail = 1;
			}
			((PULONG64)PageTable)[PageTableOffset + i] = ept_entry.epte;
		}
		return STATUS_SUCCESS;
	}
	ept_entry.epte = ((PULONG64)PageTable)[PageTableOffset];
	LowerPageTableGfn = (ULONG)ept_entry.mfn;

	if (!LowerPageTableGfn) {
		/* we have not allocated this mid level page table before */

		Status = MmFindPageByGPA(gfn_to_gpaddr(LowerPageTableGfn), &LowerPageTable);
		if (!NT_SUCCESS(Status)) {
			//LowerPageTableGuestVA = ExAllocatePoolWithTag (NonPagedPool, PAGE_SIZE, ITL_TAG);
			LowerPageTableGuestVA = MmAllocatePages(1, (ULONG64*)&LowerPageTablePA.QuadPart, TRUE);
			if (!LowerPageTableGuestVA)
			{
				//panic(("ept_update_table(): no memory"));
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			RtlZeroMemory((PVOID)LowerPageTableGuestVA, PAGE_SIZE);
#if defined(_X86_)
			LowerPageTableGfn = gpaddr_to_gfn(LowerPageTablePA.LowPart);
#elif defined(_X64_)
			LowerPageTableGfn = gpaddr_to_gfn(LowerPageTablePA.QuadPart);
#endif
		}
		else {
			LowerPageTableGfn = LowerPageTable->gfn;
			LowerPageTableGuestVA = LowerPageTable->gvaddr;
		}

		//assert((LowerPageTableGfn), ("LowerPageTableGfn has an invalid value"));

		if (!LowerPageTableGfn)
		{
			_Int3();
		}
		
		ept_entry.r = ept_entry.w = ept_entry.x = 1;
		ept_entry.emt = 0;
		ept_entry.ipat = 0;
		ept_entry.sp_avail = 0;
		ept_entry.mfn = LowerPageTableGfn;
		((PULONG64)PageTable)[PageTableOffset] = ept_entry.epte;
	}
	else {
		/* we have allocated this mid level page table before */
		Status = MmFindPageByGPA(gfn_to_gpaddr(LowerPageTableGfn), &LowerPageTable);

		if (!NT_SUCCESS(Status)) {
			LowerPageTablePA.QuadPart = ((PULONG64)PageTable)[PageTableOffset];
			if ((PageTableLevel == 2) && (LowerPageTablePA.QuadPart & P_LARGE)) {
				//dprint(PRINT_ERROR,("ept_update_table(): Found large PDE, data 0x%p\n", LowerPageTablePA.QuadPart));
				return STATUS_SUCCESS;

			}
			else {
				/*dprint(PRINT_ERROR,
					("ept_update_table(): Failed to find lower page table (pl%d) guest VA, data 0x%p, status 0x%08X\n",
					PageTableLevel - 1, LowerPageTablePA.QuadPart, Status));*/
				_Int3();
				return Status;
			}
		}

		LowerPageTableGuestVA = LowerPageTable->gvaddr;
	}

	return ept_update_identity_table((PVOID)LowerPageTableGuestVA, PageTableLevel - 1, gfn, p2m_type,
		bLargePage, op_type);
}

static VOID NTAPI ept_tlb_flush(void)
{
	ULONG64 eptp = MyEpt.ept_control.eptp;
	struct {
		ULONG64 eptp, gpa;
	} operand = { eptp, 0 };

	////assert((eptp), ("ept_tlb_flush():EPTP error"));
	//DbgPrint("eptp value:0x%llx\n", eptp);
	_invept(1,(ULONG64)&operand);
}

static VOID NTAPI ept_vpid_flush(void)
{
	struct {
		ULONG64 vpid : 16;
		ULONG64 rsvd : 48;
		ULONG64 gva;
	}  operand = { 0, 0, 0 };

	_invvpid(2, (ULONG64)&operand);
}

static NTSTATUS NTAPI ept_create_mapping(
	ULONG64 gfn,
	ULONG64 mfn,
	ULONG32 p2m_type,
	BOOLEAN bLargePage
	)
{
	NTSTATUS status;

	if (MyEpt.holder != KeGetCurrentProcessorNumber())
	{
		_spin_lock_acquire(&MyEpt.lock);
		MyEpt.holder = KeGetCurrentProcessorNumber();
	}

	status = ept_update_table((PVOID)ept_pml4_page->gvaddr, 4, gfn, mfn, p2m_type,
		bLargePage, P2M_UPDATE_ALL);

	if (MyEpt.holder == KeGetCurrentProcessorNumber())
	{
		_spin_lock_release(&MyEpt.lock);
		MyEpt.holder = NO_HOLDER;
	}

	MyEpt.need_flush = TRUE;
	return status;
}

static NTSTATUS NTAPI ept_update_mapping(
	ULONG64 gfn,
	ULONG64 mfn,
	ULONG32 p2m_type,
	BOOLEAN bLargePage,
	P2M_UPDATE_TYPE op_type
	)
{
	NTSTATUS status;

	if (MyEpt.holder != KeGetCurrentProcessorNumber())
	{
		_spin_lock_acquire(&MyEpt.lock);
		MyEpt.holder = KeGetCurrentProcessorNumber();
	}

	status = ept_update_table((PVOID)ept_pml4_page->gvaddr, 4, gfn, mfn, p2m_type,
		bLargePage, op_type);

	if (MyEpt.holder == KeGetCurrentProcessorNumber())
	{
		_spin_lock_release(&MyEpt.lock);
		MyEpt.holder = NO_HOLDER;
	}

	MyEpt.need_flush = TRUE;
	return status;
}

static NTSTATUS NTAPI ept_update_all_mapping(ULONG32 p2m_type)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG gfn;

	if (MyEpt.holder != KeGetCurrentProcessorNumber())
	{
		_spin_lock_acquire(&MyEpt.lock);
		MyEpt.holder = KeGetCurrentProcessorNumber();
	}

//#ifdef _X86_
	//for(gfn = 0x0; gfn<=0xfffff; gfn += EPT_EACHTABLE_ENTRIES)
	for (gfn = 0x0; gfn < (MyEpt.mm_highest_gfn / EPT_EACHTABLE_ENTRIES + 1) * EPT_EACHTABLE_ENTRIES
		; gfn += EPT_EACHTABLE_ENTRIES)
	{
		/* All large pages are split into 4K pages. */
		status = ept_update_identity_table((PVOID)ept_pml4_page->gvaddr, 4, gfn, p2m_type,
			FALSE, P2M_UPDATE_MT);

		//assert((NT_SUCCESS(status)), ("Vis: mm_map_machine_pfns() failed with status 0x%08hX\n", status));
		if (!(NT_SUCCESS(status)))
		{
			_Int3();
		}
	}
//#endif

	if (MyEpt.holder == KeGetCurrentProcessorNumber())
	{
		_spin_lock_release(&MyEpt.lock);
		MyEpt.holder = NO_HOLDER;
	}

	MyEpt.need_flush = TRUE;
	return status;
}


/* This is used to map all the available pfns on the current platform */
static NTSTATUS NTAPI ept_create_identity_map(void)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG gfn;

	if (MyEpt.holder != KeGetCurrentProcessorNumber())
	{
		_spin_lock_acquire(&MyEpt.lock);
		MyEpt.holder = KeGetCurrentProcessorNumber();
	}

//#ifdef _X86_
	//for (gfn = 0x0; gfn <= 0xfffff; gfn += EPT_EACHTABLE_ENTRIES)
	for (gfn = 0x0; gfn < (MyEpt.mm_highest_gfn / EPT_EACHTABLE_ENTRIES + 1) * EPT_EACHTABLE_ENTRIES
		; gfn += EPT_EACHTABLE_ENTRIES)
	{
		/* All large pages are split into 4K pages. */
		status = ept_update_identity_table((PVOID)ept_pml4_page->gvaddr, 4, gfn, P2M_FULL_ACCESS,
			FALSE, P2M_UPDATE_ALL);
		if (!NT_SUCCESS(status))
		{
			_Int3();
			//dprint(PRINT_ERROR, ("Vis: mm_map_machine_pfns() failed with status 0x%08hX\n", status));
		}
	}
//#endif

	if (MyEpt.holder == KeGetCurrentProcessorNumber())
	{
		_spin_lock_release(&MyEpt.lock);
		MyEpt.holder = NO_HOLDER;
	}

	MyEpt.need_flush = TRUE;
	return status;
}

VOID NTAPI ept_init(VOID)
{
	ULONG64 ept_pml4_page_paddr = 0;
	ULONG64 ept_pml4_page_vaddr = 0;
	NTSTATUS status;

	_spin_lock_init(&MyEpt.lock);

	_spin_lock_acquire(&MyEpt.lock);
	MyEpt.holder = KeGetCurrentProcessorNumber();

	/* set ept callbacks in p2m */
	MyEpt.p2m_create_mapping = &ept_create_mapping;
	MyEpt.p2m_tlb_flush = &ept_tlb_flush;
	MyEpt.p2m_vpid_flush = &ept_vpid_flush;
	MyEpt.p2m_create_identity_map = &ept_create_identity_map;
	MyEpt.p2m_update_mapping = &ept_update_mapping;
	MyEpt.p2m_update_all_mapping = &ept_update_all_mapping;
	/* allocate ept PML4 page */
	ept_pml4_page_vaddr = MmAllocateContiguousPages(1, &ept_pml4_page_paddr, TRUE);
	status = MmFindPageByGPA(ept_pml4_page_paddr, &ept_pml4_page);
	//assert((NT_SUCCESS(status)), ("ept_init() failed!"));
	if (!(NT_SUCCESS(status)))
	{
		_Int3();
	}
	MyEpt.p2m_table = gpaddr_to_gfn(ept_pml4_page_paddr);

	/* set epte */
	MyEpt.ept_control.ept_mt = EPT_DEFAULT_MT;
	MyEpt.ept_control.ept_wl = EPT_DEFAULT_GAW;
	MyEpt.ept_control.asr = pagetable_get_fn(MyEpt.p2m_table);

	_spin_lock_release(&MyEpt.lock);
	MyEpt.holder = NO_HOLDER;

	//print("P2M:EPT is enabled\n");
}

ept_control g_ept_ctl;



VOID NTAPI p2m_init()
{
		//Obviously, the current architecture supports EPT
		//ept_init();
	ept_init();
}
