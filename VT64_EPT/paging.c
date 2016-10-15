/* 
 * Copyright holder: Invisible Things Lab
 * 
 * This software is protected by domestic and International
 * copyright laws. Any use (including publishing and
 * distribution) of this software requires a valid license
 * from the copyright holder.
 *
 * This software is provided for the educational use only
 * during the Black Hat training. This software should not
 * be used on production systems.
 *
 */

#include "paging.h"

#define DbgPrint(...) {}

static LIST_ENTRY g_PageTableList;
static KSPIN_LOCK g_PageTableListLock;

PHYSICAL_ADDRESS g_PageMapBasePhysicalAddress;
PHYSICAL_ADDRESS g_IdentityPageTableBasePhysicalAddress, g_IdentityPageTableBasePhysicalAddress_Legacy;

static PUCHAR g_PageTableBases[4] = {
  (PUCHAR) PT_BASE,
  (PUCHAR) PD_BASE,
  (PUCHAR) PDP_BASE,
  (PUCHAR) PML4_BASE
};

static NTSTATUS NTAPI MmSavePage (
  PHYSICAL_ADDRESS PhysicalAddress,
  PVOID HostAddress,
  PVOID GuestAddress,
  PAGE_ALLOCATION_TYPE AllocationType,
  ULONG uNumberOfPages,
  ULONG Flags
)
{
  PALLOCATED_PAGE AllocatedPage;

  if (!GuestAddress)
    return STATUS_INVALID_PARAMETER;

  AllocatedPage = ExAllocatePoolWithTag (NonPagedPool, sizeof (ALLOCATED_PAGE), ITL_TAG);
  if (!AllocatedPage)
    return STATUS_INSUFFICIENT_RESOURCES;
  RtlZeroMemory (AllocatedPage, sizeof (ALLOCATED_PAGE));

  PhysicalAddress.QuadPart = PhysicalAddress.QuadPart & 0x000ffffffffff000;
  HostAddress = (PVOID) ((ULONG64) HostAddress & 0xfffffffffffff000);

  AllocatedPage->AllocationType = AllocationType;
  AllocatedPage->PhysicalAddress = PhysicalAddress;
  AllocatedPage->HostAddress = HostAddress;
  AllocatedPage->GuestAddress = GuestAddress;
  AllocatedPage->uNumberOfPages = uNumberOfPages;
  AllocatedPage->Flags = Flags;

  ExInterlockedInsertTailList (&g_PageTableList, &AllocatedPage->le, &g_PageTableListLock);

  /*
     DbgPrint("MmSavePage(): PA 0x%X, HostVA 0x%p, GuestVA 0x%p, AT %d, FL 0x%X\n",
     PhysicalAddress.QuadPart,
     HostAddress,
     GuestAddress,
     AllocationType,
     Flags);
   */
  return STATUS_SUCCESS;
}

static NTSTATUS NTAPI MmFindPageByPA (
  PHYSICAL_ADDRESS PhysicalAddress,
  PALLOCATED_PAGE * pAllocatedPage
)
{
  PALLOCATED_PAGE AllocatedPage;
  KIRQL OldIrql;

  if (!pAllocatedPage)
    return STATUS_INVALID_PARAMETER;

  KeAcquireSpinLock (&g_PageTableListLock, &OldIrql);

  PhysicalAddress.QuadPart = PhysicalAddress.QuadPart & 0x000ffffffffff000;

  AllocatedPage = (PALLOCATED_PAGE) g_PageTableList.Flink;
  while (AllocatedPage != (PALLOCATED_PAGE) & g_PageTableList) {
    AllocatedPage = CONTAINING_RECORD (AllocatedPage, ALLOCATED_PAGE, le);

    if (AllocatedPage->PhysicalAddress.QuadPart == PhysicalAddress.QuadPart) {
      *pAllocatedPage = AllocatedPage;
      KeReleaseSpinLock (&g_PageTableListLock, OldIrql);
      return STATUS_SUCCESS;
    }

    AllocatedPage = (PALLOCATED_PAGE) AllocatedPage->le.Flink;
  }

  KeReleaseSpinLock (&g_PageTableListLock, OldIrql);
  return STATUS_UNSUCCESSFUL;
}

static NTSTATUS NTAPI MmFindPageByHostVA (
  PVOID HostAddress,
  PALLOCATED_PAGE * pAllocatedPage
)
{
  PALLOCATED_PAGE AllocatedPage;
  KIRQL OldIrql;

  if (!pAllocatedPage)
    return STATUS_INVALID_PARAMETER;

  KeAcquireSpinLock (&g_PageTableListLock, &OldIrql);

  HostAddress = (PVOID) ((ULONG64) HostAddress & 0xfffffffffffff000);

  AllocatedPage = (PALLOCATED_PAGE) g_PageTableList.Flink;
  while (AllocatedPage != (PALLOCATED_PAGE) & g_PageTableList) {
    AllocatedPage = CONTAINING_RECORD (AllocatedPage, ALLOCATED_PAGE, le);

    if (AllocatedPage->HostAddress == HostAddress) {
      *pAllocatedPage = AllocatedPage;
      KeReleaseSpinLock (&g_PageTableListLock, OldIrql);
      return STATUS_SUCCESS;
    }

    AllocatedPage = (PALLOCATED_PAGE) AllocatedPage->le.Flink;
  }

  KeReleaseSpinLock (&g_PageTableListLock, OldIrql);
  return STATUS_UNSUCCESSFUL;
}

static NTSTATUS NTAPI MmUpdatePageTable (
  PVOID PageTable,
  UCHAR PageTableLevel,
  PVOID VirtualAddress,
  PHYSICAL_ADDRESS PhysicalAddress,
  BOOLEAN bLargePage
)
{
  ULONG64 PageTableOffset, GlobalOffset;
  ULONG64 GlobalOffset1, GlobalOffset2, GlobalOffset3, GlobalOffset4;
  PVOID LowerPageTableHostVA, LowerPageTableGuestVA;
  PALLOCATED_PAGE LowerPageTable;
  PHYSICAL_ADDRESS LowerPageTablePA;
  NTSTATUS Status;
  PHYSICAL_ADDRESS PagePA, l1, l2, l3;

  PALLOCATED_PAGE Pml4e, Pdpe, Pde, Pte;

  // get the offset in the specified page table level
  PageTableOffset = (((ULONG64) VirtualAddress & (((ULONG64) 1) << (12 + PageTableLevel * 9))
                      - 1) >> (12 + ((ULONG64) PageTableLevel - 1) * 9));

  if ((PageTableLevel == 1) || (bLargePage && (PageTableLevel == 2))) {
    // patch PTE/PDE
/*
		GlobalOffset=(((ULONG64)VirtualAddress & (((ULONG64)1)<<(12+4*9))-1)>>12);

		GlobalOffset4=(((ULONG64)VirtualAddress & (((ULONG64)1)<<(12+4*9))-1)>>(12+(3)*9));
		GlobalOffset3=(((ULONG64)VirtualAddress & (((ULONG64)1)<<(12+4*9))-1)>>(12+(2)*9));
		GlobalOffset2=(((ULONG64)VirtualAddress & (((ULONG64)1)<<(12+4*9))-1)>>(12+(1)*9));
		GlobalOffset1=(((ULONG64)VirtualAddress & (((ULONG64)1)<<(12+4*9))-1)>>(12+(0)*9));

		MmFindPageByHostVA(GlobalOffset4*8+g_PageTableBases[3],&Pml4e);
		MmFindPageByHostVA(GlobalOffset3*8+g_PageTableBases[2],&Pdpe);
		MmFindPageByHostVA(GlobalOffset2*8+g_PageTableBases[1],&Pde);
		MmFindPageByHostVA(GlobalOffset1*8+g_PageTableBases[0],&Pte);

		DbgPrint("MmUpdatePageTable(): VA 0x%p: PML4E 0x%p, PDPE 0x%p, PDE 0x%p, PTE 0x%p\n",
			VirtualAddress,
			GlobalOffset4*8+g_PageTableBases[3],
			GlobalOffset3*8+g_PageTableBases[2],
			GlobalOffset2*8+g_PageTableBases[1],
			GlobalOffset1*8+g_PageTableBases[0]);
		DbgPrint("MmUpdatePageTable(): Guest: PML4E 0x%p, PDPE 0x%p, PDE 0x%p, PTE 0x%p\n",
			(GlobalOffset4*8 & 0xfff) + (PUCHAR)Pml4e->GuestAddress,
			(GlobalOffset3*8 & 0xfff) + (PUCHAR)Pdpe->GuestAddress,
			(GlobalOffset2*8 & 0xfff) + (PUCHAR)Pde->GuestAddress,
			(GlobalOffset1*8 & 0xfff) + (PUCHAR)Pte->GuestAddress);

		DbgPrint("MmUpdatePageTable(): VA 0x%p, HPTE 0x%p, GPTE 0x%p, PA 0x%p\n",
			VirtualAddress,
			GlobalOffset*8+g_PageTableBases[0],
			(PUCHAR)PageTable+8*PageTableOffset,
			PhysicalAddress.QuadPart);
*/

#ifdef SET_PCD_BIT
    ((PULONG64) PageTable)[PageTableOffset] = PhysicalAddress.QuadPart |        /*P_GLOBAL | */
      P_WRITABLE | P_PRESENT | P_CACHE_DISABLED;
#else
    ((PULONG64) PageTable)[PageTableOffset] = PhysicalAddress.QuadPart | /*P_GLOBAL | */ P_WRITABLE | P_PRESENT;
#endif
    if (bLargePage)
      ((PULONG64) PageTable)[PageTableOffset] |= P_LARGE;
    return STATUS_SUCCESS;
  }

  GlobalOffset =
    (((ULONG64) VirtualAddress & (((ULONG64) 1) << (12 + 4 * 9)) - 1) >> (12 + ((ULONG64) PageTableLevel - 2) * 9));
  LowerPageTablePA.QuadPart = ((PULONG64) PageTable)[PageTableOffset] & 0x000ffffffffff000;
  LowerPageTableHostVA = GlobalOffset * 8 + g_PageTableBases[PageTableLevel - 2];

  if (!LowerPageTablePA.QuadPart) {

    Status = MmFindPageByHostVA (LowerPageTableHostVA, &LowerPageTable);
    if (!NT_SUCCESS (Status)) {

      LowerPageTableGuestVA = ExAllocatePoolWithTag (NonPagedPool, PAGE_SIZE, ITL_TAG);
      if (!LowerPageTableGuestVA)
        return STATUS_INSUFFICIENT_RESOURCES;
      RtlZeroMemory (LowerPageTableGuestVA, PAGE_SIZE);

      LowerPageTablePA = MmGetPhysicalAddress (LowerPageTableGuestVA);

      Status =
        MmSavePage (LowerPageTablePA, LowerPageTableHostVA,
                    LowerPageTableGuestVA, PAT_POOL, 1, AP_PAGETABLE | (1 << (PageTableLevel - 1)));
      if (!NT_SUCCESS (Status)) {
        DbgPrint
          ("MmUpdatePageTable(): Failed to store page table level %d, MmSavePage() returned status 0x%08X\n",
           PageTableLevel - 1, Status);
        return Status;
      }
    } else {
      LowerPageTablePA.QuadPart = LowerPageTable->PhysicalAddress.QuadPart;
      LowerPageTableGuestVA = LowerPageTable->GuestAddress;
    }

#ifdef SET_PCD_BIT
    ((PULONG64) PageTable)[PageTableOffset] = LowerPageTablePA.QuadPart |       /*P_GLOBAL | */
      P_WRITABLE | P_PRESENT | P_CACHE_DISABLED;
#else
    ((PULONG64) PageTable)[PageTableOffset] = LowerPageTablePA.QuadPart | /*P_GLOBAL | */ P_WRITABLE | P_PRESENT;
#endif

    Status = MmCreateMapping (LowerPageTablePA, LowerPageTableHostVA, FALSE);
    if (!NT_SUCCESS (Status)) {
      DbgPrint
        ("MmUpdatePageTable(): MmCreateMapping() failed to map PA 0x%p with status 0x%08X\n",
         LowerPageTablePA.QuadPart, Status);
      return Status;
    }

  } else {

    Status = MmFindPageByPA (LowerPageTablePA, &LowerPageTable);
    if (!NT_SUCCESS (Status)) {
      LowerPageTablePA.QuadPart = ((PULONG64) PageTable)[PageTableOffset];
      if ((PageTableLevel == 2) && (LowerPageTablePA.QuadPart & P_LARGE)) {

        DbgPrint ("MmUpdatePageTable(): Found large PDE, data 0x%p\n", LowerPageTablePA.QuadPart);
        return STATUS_SUCCESS;

      } else {
        DbgPrint
          ("MmUpdatePageTable(): Failed to find lower page table (pl%d) guest VA, data 0x%p, status 0x%08X\n",
           PageTableLevel - 1, LowerPageTablePA.QuadPart, Status);
        return Status;
      }
    }

    LowerPageTableGuestVA = LowerPageTable->GuestAddress;
  }

  return MmUpdatePageTable (LowerPageTableGuestVA, PageTableLevel - 1, VirtualAddress, PhysicalAddress, bLargePage);
}

PVOID NTAPI MmAllocatePages (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA
)
{
  PVOID PageVA, FirstPage;
  PHYSICAL_ADDRESS PagePA;
  NTSTATUS Status;
  ULONG i;

  if (!uNumberOfPages)
    return NULL;

  FirstPage = PageVA = ExAllocatePoolWithTag (NonPagedPool, uNumberOfPages * PAGE_SIZE, ITL_TAG);
  if (!PageVA)
    return NULL;
  RtlZeroMemory (PageVA, uNumberOfPages * PAGE_SIZE);

  if (pFirstPagePA)
    *pFirstPagePA = MmGetPhysicalAddress (PageVA);

  for (i = 0; i < uNumberOfPages; i++) {

    // map to the same addresses in the host pagetables as they are in guest's
    PagePA = MmGetPhysicalAddress (PageVA);
    Status = MmSavePage (PagePA, PageVA, PageVA, !i ? PAT_POOL : PAT_DONT_FREE, uNumberOfPages, 0);
    if (!NT_SUCCESS (Status)) {
      DbgPrint ("MmAllocatePages(): MmSavePage() failed with status 0x%08X\n", Status);
      return NULL;
    }

    Status = MmCreateMapping (PagePA, PageVA, FALSE);
    if (!NT_SUCCESS (Status)) {
      DbgPrint
        ("MmAllocatePages(): MmCreateMapping() failed to map PA 0x%p with status 0x%08X\n", PagePA.QuadPart, Status);
      return NULL;
    }

    PageVA = (PUCHAR) PageVA + PAGE_SIZE;
  }

  return FirstPage;
}

PVOID NTAPI MmAllocateContiguousPages (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA
)
{
  PVOID PageVA, FirstPage;
  PHYSICAL_ADDRESS PagePA, l1, l2, l3;
  NTSTATUS Status;
  ULONG i;

  if (!uNumberOfPages)
    return NULL;

  l1.QuadPart = 0;
  l2.QuadPart = -1;
  l3.QuadPart = 0x200000;

  FirstPage = PageVA = MmAllocateContiguousMemorySpecifyCache (uNumberOfPages * PAGE_SIZE, l1, l2, l3, MmCached);
  if (!PageVA)
    return NULL;

  RtlZeroMemory (PageVA, uNumberOfPages * PAGE_SIZE);

  PagePA = MmGetPhysicalAddress (PageVA);
  if (pFirstPagePA)
    *pFirstPagePA = PagePA;

  for (i = 0; i < uNumberOfPages; i++) {

    // map to the same addresses in the host pagetables as they are in guest's

    Status = MmSavePage (PagePA, PageVA, PageVA, !i ? PAT_CONTIGUOUS : PAT_DONT_FREE, uNumberOfPages, 0);
    if (!NT_SUCCESS (Status)) {
      DbgPrint ("MmAllocateContiguousPages(): MmSavePage() failed with status 0x%08X\n", Status);
      return NULL;
    }

    Status = MmCreateMapping (PagePA, PageVA, FALSE);
    if (!NT_SUCCESS (Status)) {
      DbgPrint
        ("MmAllocateContiguousPages(): MmCreateMapping() failed to map PA 0x%p with status 0x%08X\n",
         PagePA.QuadPart, Status);
      return NULL;
    }

    PageVA = (PUCHAR) PageVA + PAGE_SIZE;
    PagePA.QuadPart += PAGE_SIZE;
  }

  return FirstPage;
}

PVOID NTAPI MmAllocateContiguousPagesSpecifyCache (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA,
  ULONG CacheType
)
{
  PVOID PageVA, FirstPage;
  PHYSICAL_ADDRESS PagePA, l1, l2, l3;
  NTSTATUS Status;
  ULONG i;

  if (!uNumberOfPages)
    return NULL;

  l1.QuadPart = 0;
  l2.QuadPart = -1;
  l3.QuadPart = 0x10000;

  FirstPage = PageVA = MmAllocateContiguousMemorySpecifyCache (uNumberOfPages * PAGE_SIZE, l1, l2, l3, CacheType);
  if (!PageVA)
    return NULL;

  RtlZeroMemory (PageVA, uNumberOfPages * PAGE_SIZE);

  PagePA = MmGetPhysicalAddress (PageVA);
  if (pFirstPagePA)
    *pFirstPagePA = PagePA;

  for (i = 0; i < uNumberOfPages; i++) {

    // map to the same addresses in the host pagetables as they are in guest's

    Status = MmSavePage (PagePA, PageVA, PageVA, !i ? PAT_CONTIGUOUS : PAT_DONT_FREE, uNumberOfPages, 0);
    if (!NT_SUCCESS (Status)) {
      DbgPrint ("MmAllocateContiguousPages(): MmSavePage() failed with status 0x%08X\n", Status);
      return NULL;
    }

    Status = MmCreateMapping (PagePA, PageVA, FALSE);
    if (!NT_SUCCESS (Status)) {
      DbgPrint
        ("MmAllocateContiguousPages(): MmCreateMapping() failed to map PA 0x%p with status 0x%08X\n",
         PagePA.QuadPart, Status);
      return NULL;
    }

    PageVA = (PUCHAR) PageVA + PAGE_SIZE;
    PagePA.QuadPart += PAGE_SIZE;
  }

  return FirstPage;
}

NTSTATUS NTAPI MmCreateMapping (
  PHYSICAL_ADDRESS PhysicalAddress,
  PVOID VirtualAddress,
  BOOLEAN bLargePage
)
{
  PALLOCATED_PAGE Pml4Page;
  NTSTATUS Status;

  Status = MmFindPageByPA (g_PageMapBasePhysicalAddress, &Pml4Page);
  if (!NT_SUCCESS (Status)) {
    return STATUS_UNSUCCESSFUL;
  }

  PhysicalAddress.QuadPart = PhysicalAddress.QuadPart & 0x000ffffffffff000;
  VirtualAddress = (PVOID) ((ULONG64) VirtualAddress & 0xfffffffffffff000);

  return MmUpdatePageTable (Pml4Page->GuestAddress, 4, VirtualAddress, PhysicalAddress, bLargePage);
}

NTSTATUS NTAPI MmMapGuestPages (
  PVOID FirstPage,
  ULONG uNumberOfPages
)
{
  PHYSICAL_ADDRESS PhysicalAddress;
  NTSTATUS Status;

  FirstPage = (PVOID) ((ULONG64) FirstPage & 0xfffffffffffff000);

  // Everything is made present, writable, executable, 4kb and cpl0 only.
  // Mapping is done to the same virtual addresses in the host.
  while (uNumberOfPages--) {

    // Guest memory may not be contiguous   
    PhysicalAddress = MmGetPhysicalAddress (FirstPage);

    if (!NT_SUCCESS (Status = MmCreateMapping (PhysicalAddress, FirstPage, FALSE))) {
      DbgPrint ("MmMapGuestPages(): MmCreateMapping() failed with status 0x%08X\n", Status);
      return Status;
    }

    FirstPage = (PVOID) ((PUCHAR) FirstPage + PAGE_SIZE);
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmWalkGuestPageTable (
  PULONG64 PageTable,
  UCHAR bLevel
)
{
  ULONG64 i;
  PVOID VirtualAddress;
  PUCHAR ShortPageVA;
  PHYSICAL_ADDRESS PhysicalAddress;
  PULONG64 LowerPageTable;

  if (!MmIsAddressValid (PageTable))
    return STATUS_SUCCESS;

  for (i = 0; i < 0x200; i++)

    if (PageTable[i] & P_PRESENT) {

      if (((bLevel == 2) && (PageTable[i] & P_LARGE)) || (bLevel == 1)) {

        if (bLevel == 1)
          VirtualAddress = (PVOID) (((LONGLONG) (&PageTable[i]) - PT_BASE) << 9);
        else
          VirtualAddress = (PVOID) (((LONGLONG) (&PageTable[i]) - PD_BASE) << 18);

        if ((LONGLONG) VirtualAddress & 0x0000800000000000)
          VirtualAddress = (PVOID) ((LONGLONG) VirtualAddress | 0xffff000000000000);

        PhysicalAddress.QuadPart = PageTable[i] & 0x000ffffffffff000;

        if ((ULONGLONG) VirtualAddress >= PT_BASE && (ULONGLONG) VirtualAddress < PML4_BASE + 0x1000)
          // guest pagetable stuff here - so don't map it
          continue;

        DbgPrint
          ("MmWalkGuestPageTable(): %sValid pl%d at 0x%p, index 0x%x, VA 0x%p, PA 0x%p %s\n",
           bLevel == 3 ? "   " : bLevel == 2 ? "      " : bLevel ==
           1 ? "         " : "", bLevel, &PageTable[i], i, VirtualAddress, PhysicalAddress.QuadPart, ((bLevel == 2)
                                                                                                      && (PageTable[i] &
                                                                                                          P_LARGE)) ?
           "LARGE" : "");

        if (bLevel == 2) {
          for (ShortPageVA = (PUCHAR) VirtualAddress + 0x0 * PAGE_SIZE;
               ShortPageVA < (PUCHAR) VirtualAddress + 0x200 * PAGE_SIZE;
               ShortPageVA += PAGE_SIZE, PhysicalAddress.QuadPart += PAGE_SIZE)
            MmCreateMapping (PhysicalAddress, ShortPageVA, FALSE);
        } else
          MmCreateMapping (PhysicalAddress, VirtualAddress, FALSE);
      }

      if ((bLevel > 1) && !((bLevel == 2) && (PageTable[i] & P_LARGE))) {
        LowerPageTable = (PULONG64) (g_PageTableBases[bLevel - 2] + 8 * (i << (9 * (5 - bLevel))));
        MmWalkGuestPageTable (LowerPageTable, bLevel - 1);
      }
    }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmMapGuestKernelPages (
)
{
  PULONG64 Pml4e = (PULONG64) PML4_BASE;
  PULONG64 Pdpe;
  PULONG64 Pde;
  ULONG uPml4eIndex, uPdpeIndex, uPdeIndex;

  for (uPml4eIndex = 0x100; uPml4eIndex < 0x200; uPml4eIndex++)
    if (Pml4e[uPml4eIndex] & P_PRESENT) {

      Pdpe = (PULONG64) PDP_BASE + (uPml4eIndex << 9);
      MmWalkGuestPageTable (Pdpe, 3);
    }

  return STATUS_SUCCESS;
}

NTSTATUS MmMapGuestTSS64 (
  PTSS64 Tss64,
  USHORT Tss64Limit
)
{
  if (!Tss64)
    return STATUS_INVALID_PARAMETER;

  DbgPrint ("MmMapGuestTSS64(): Mapping TSS64 at 0x%p, limit %d\n", Tss64, Tss64Limit);
  MmMapGuestPages (Tss64, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64, Tss64Limit));

  if (Tss64->RSP0) {
    DbgPrint ("MmMapGuestTSS64(): Mapping RSP0 at 0x%p\n", Tss64->RSP0);
    MmMapGuestPages (Tss64->RSP0, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->RSP0, PAGE_SIZE));
  }
  if (Tss64->RSP1) {
    DbgPrint ("MmMapGuestTSS64(): Mapping RSP1 at 0x%p\n", Tss64->RSP1);
    MmMapGuestPages (Tss64->RSP1, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->RSP1, PAGE_SIZE));
  }
  if (Tss64->RSP2) {
    DbgPrint ("MmMapGuestTSS64(): Mapping RSP2 at 0x%p\n", Tss64->RSP2);
    MmMapGuestPages (Tss64->RSP2, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->RSP2, PAGE_SIZE));
  }

  if (Tss64->IST1) {
    DbgPrint ("MmMapGuestTSS64(): Mapping IST1 at 0x%p\n", Tss64->IST1);
    MmMapGuestPages (Tss64->IST1, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->IST1, PAGE_SIZE));
  }
  if (Tss64->IST2) {
    DbgPrint ("MmMapGuestTSS64(): Mapping IST2 at 0x%p\n", Tss64->IST2);
    MmMapGuestPages (Tss64->IST2, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->IST2, PAGE_SIZE));
  }
  if (Tss64->IST3) {
    DbgPrint ("MmMapGuestTSS64(): Mapping IST3 at 0x%p\n", Tss64->IST3);
    MmMapGuestPages (Tss64->IST3, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->IST3, PAGE_SIZE));
  }
  if (Tss64->IST4) {
    DbgPrint ("MmMapGuestTSS64(): Mapping IST4 at 0x%p\n", Tss64->IST4);
    MmMapGuestPages (Tss64->IST4, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->IST4, PAGE_SIZE));
  }
  if (Tss64->IST5) {
    DbgPrint ("MmMapGuestTSS64(): Mapping IST5 at 0x%p\n", Tss64->IST5);
    MmMapGuestPages (Tss64->IST5, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->IST5, PAGE_SIZE));
  }
  if (Tss64->IST6) {
    DbgPrint ("MmMapGuestTSS64(): Mapping IST6 at 0x%p\n", Tss64->IST6);
    MmMapGuestPages (Tss64->IST6, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->IST6, PAGE_SIZE));
  }
  if (Tss64->IST7) {
    DbgPrint ("MmMapGuestTSS64(): Mapping IST7 at 0x%p\n", Tss64->IST7);
    MmMapGuestPages (Tss64->IST7, ADDRESS_AND_SIZE_TO_SPAN_PAGES (Tss64->IST7, PAGE_SIZE));
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmInitManager (
)
{
  PVOID Pml4Page;
  NTSTATUS Status;
  PHYSICAL_ADDRESS l1, l2, l3;

  InitializeListHead (&g_PageTableList);
  KeInitializeSpinLock (&g_PageTableListLock);

  Pml4Page = ExAllocatePoolWithTag (NonPagedPool, PAGE_SIZE, ITL_TAG);
  if (!Pml4Page)
    return STATUS_INSUFFICIENT_RESOURCES;
  RtlZeroMemory (Pml4Page, PAGE_SIZE);

  g_PageMapBasePhysicalAddress = MmGetPhysicalAddress (Pml4Page);

  if (!NT_SUCCESS
      (Status =
       MmSavePage (g_PageMapBasePhysicalAddress, (PVOID) PML4_BASE, Pml4Page, PAT_POOL, 1, AP_PAGETABLE | AP_PML4))) {
    DbgPrint ("MmInitManager(): MmSavePage() failed to save PML4 page, status 0x%08X\n", Status);
    return Status;
  }

  if (!NT_SUCCESS (Status = MmCreateMapping (g_PageMapBasePhysicalAddress, (PVOID) PML4_BASE, FALSE))) {
    DbgPrint ("MmInitManager(): MmCreateMapping() failed to map PML4 page, status 0x%08X\n", Status);
    return Status;
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmShutdownManager (
)
{
  PALLOCATED_PAGE AllocatedPage;
  ULONG i;
  PULONG64 Entry;

  while (AllocatedPage = (PALLOCATED_PAGE) ExInterlockedRemoveHeadList (&g_PageTableList, &g_PageTableListLock)) {

    AllocatedPage = CONTAINING_RECORD (AllocatedPage, ALLOCATED_PAGE, le);

    if (AllocatedPage->Flags & AP_PAGETABLE) {
      for (i = 0, Entry = AllocatedPage->GuestAddress; i < 0x200; i++) {
        if (Entry[i] & P_ACCESSED)
          DbgPrint
            ("MmShutdownManager(): HPT 0x%p: index %d accessed, entry 0x%p, FL 0x%X\n",
             AllocatedPage->HostAddress, i, Entry[i], AllocatedPage->Flags);
      }
    }

    switch (AllocatedPage->AllocationType) {
    case PAT_POOL:
      ExFreePool (AllocatedPage->GuestAddress);
      break;
    case PAT_CONTIGUOUS:
      MmFreeContiguousMemorySpecifyCache (AllocatedPage->GuestAddress,
                                          AllocatedPage->uNumberOfPages * PAGE_SIZE, MmCached);
      break;
    case PAT_DONT_FREE:
      // this is not the first page in the allocation
      break;
    }

    ExFreePool (AllocatedPage);
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmInitIdentityPageTable (
)
{
  PHYSICAL_ADDRESS FirstPdePA, FirstPdptePA, l1, l2, l3;
  PULONG64 FirstPdeVA, FirstPdpteVA, FirstPml4eVA;
  PULONG64 FirstPdeVa_Legacy;
  ULONG64 i, j;
  l1.QuadPart = 0;
  l2.QuadPart = -1;
  l3.QuadPart = 0x200000;

  //Long Mode

  //64*512 Pde
  FirstPdeVA = (PULONG64) MmAllocateContiguousMemorySpecifyCache (64 * PAGE_SIZE, l1, l2, l3, MmCached);
  if (!FirstPdeVA)
    return STATUS_INSUFFICIENT_RESOURCES;

  RtlZeroMemory (FirstPdeVA, 64 * PAGE_SIZE);

  FirstPdePA = MmGetPhysicalAddress (FirstPdeVA);

  _KdPrint (("MmInitIdentityPageTable: FirstPdeVA 0x%p FirstPdePA 0x%llX\n", FirstPdeVA, FirstPdePA.QuadPart));
  for (i = 0; i < 64; i++) {
    for (j = 0; j < 512; j++) {
      *FirstPdeVA = ((i * 0x40000000) + j * 0x200000) | P_WRITABLE | P_PRESENT | P_CACHE_DISABLED | P_LARGE;
      FirstPdeVA++;
    }
  }

  //64 Pdpte
  FirstPdpteVA = (PULONG64) MmAllocateContiguousMemorySpecifyCache (PAGE_SIZE, l1, l2, l3, MmCached);

  if (!FirstPdpteVA)
    return STATUS_INSUFFICIENT_RESOURCES;

  RtlZeroMemory (FirstPdpteVA, PAGE_SIZE);

  FirstPdptePA = MmGetPhysicalAddress (FirstPdpteVA);

  _KdPrint (("MmInitIdentityPageTable: FirstPdpteVA 0x%p FirstPdptePA 0x%llX\n", FirstPdpteVA, FirstPdptePA.QuadPart));
  for (i = 0; i < 64; i++) {
    {
      *FirstPdpteVA = (i * 0x1000 + FirstPdePA.QuadPart) | P_WRITABLE | P_PRESENT | P_CACHE_DISABLED;
      FirstPdpteVA++;
    }
  }

  //Pml4e
  FirstPml4eVA = (PULONG64) MmAllocateContiguousMemorySpecifyCache (PAGE_SIZE, l1, l2, l3, MmCached);

  if (!FirstPml4eVA)
    return STATUS_INSUFFICIENT_RESOURCES;

  RtlZeroMemory (FirstPml4eVA, PAGE_SIZE);

  g_IdentityPageTableBasePhysicalAddress = MmGetPhysicalAddress (FirstPml4eVA);

  _KdPrint (("MmInitIdentityPageTable: FirstPml4eVA 0x%p g_IdentityPageTableBasePhysicalAddress 0x%llX\n", FirstPdeVA,
             g_IdentityPageTableBasePhysicalAddress.QuadPart));
  *FirstPml4eVA = (FirstPdptePA.QuadPart) | P_WRITABLE | P_PRESENT | P_CACHE_DISABLED;

  //Legacy Mode
  FirstPdeVa_Legacy = (PULONG64) MmAllocateContiguousMemorySpecifyCache (PAGE_SIZE, l1, l2, l3, MmCached);

  if (!FirstPml4eVA)
    return STATUS_INSUFFICIENT_RESOURCES;

  RtlZeroMemory (FirstPdeVa_Legacy, PAGE_SIZE);

  g_IdentityPageTableBasePhysicalAddress_Legacy = MmGetPhysicalAddress (FirstPdeVa_Legacy);
  for (j = 0; j < 4; j++) {
    *FirstPdeVa_Legacy = (j * 0x1000 + FirstPdePA.QuadPart) | P_PRESENT | P_CACHE_DISABLED;
    FirstPdeVa_Legacy++;
  }
  _KdPrint (("MmInitIdentityPageTable: FirstPdeVa_Legacy 0x%p g_IdentityPageTableBasePhysicalAddress_Legacy 0x%llX\n",
             FirstPdeVa_Legacy, g_IdentityPageTableBasePhysicalAddress_Legacy.QuadPart));

  return STATUS_SUCCESS;
}
