#pragma once
#include "Def.h"
//mmc
typedef struct _PTE
{
	Bit64u Present : 1;
	Bit64u Writable : 1;
	Bit64u Owner : 1;
	Bit64u WriteThrough : 1;
	Bit64u CacheDisable : 1;
	Bit64u Accessed : 1;
	Bit64u Dirty : 1;
	Bit64u LargePage : 1;
	Bit64u Global : 1;
	Bit64u ForUse1 : 1;
	Bit64u ForUse2 : 1;
	Bit64u ForUse3 : 1;
	Bit64u PageBaseAddr : 36;
	Bit64u Reserved : 16;
} PTE, *PPTE;

#define VIRTUAL_PD_BASE     0xC0600000
#define MMU_PAGE_SIZE        0x1000
#define VIRTUAL_PT_BASE     0xC0000000 
#define LARGEPAGE_SIZE 0x200000
#define CR3_ALIGN(v) ((v) & 0xffffffe0)

#define VA_TO_PDPTE(a) (((a) & 0xc0000000) >> 30)
#define VA_TO_PDE(a)   (((a) & 0x3fe00000) >> 21)
#define VA_TO_PTE(a)   (((a) & 0x001ff000) >> 12)

#define PDE_TO_VA(a)   (((a) << 21) & 0x3fe00000)
#define PTE_TO_VA(a)   (((a) << 12) & 0x001ff000)

#define PHY_TO_FRAME(a)      ((Bit64u) (((a) >> 12) & 0xfffffffffffff))
#define PHY_TO_LARGEFRAME(a) ((a) >> 21)

#define FRAME_TO_PHY(a)      ((a) << 12)
#define LARGEFRAME_TO_PHY(a) (((a)>>9) << 21)

#define PDE_TO_VALID(a)  ((VM_Address) (a) & 0x1)

#define LARGEPAGE_ALIGN(a) ((a) & ~((LARGEPAGE_SIZE)-1))
#define LARGEPAGE_OFFSET(a) ((VM_Address) (a) - (VM_Address) LARGEPAGE_ALIGN(a))
#define MMU_PAGE_ALIGN(addr) (((Bit64u) (addr)) & ~(MMU_PAGE_SIZE - 1))
#define MMU_PAGE_OFFSET(a) ((VM_Address) (a) - (VM_Address) MMU_PAGE_ALIGN(a))

#define READ_PTE(a) *(Bit64u*) (a)

//ept
#undef PTE_DATA_FIELD

#define HOST_GB 16								/* Amount of GB in system (use 4 on 32 bit to get a full mapping) */

#define READ  0x1
#define WRITE 0x2
#define EXEC  0x4

#define MEM_TYPE_UNCACHEABLE  0
#define MEM_TYPE_WRITECOMBINE 1
#define MEM_TYPE_WRITETHROUGH 4
#define MEM_TYPE_WRITEPROTECT 5
#define MEM_TYPE_WRITEBACK    6

#define IA32_MTRRCAP_VCNT		0x000000ff
#define IA32_MTRRCAP_FIX		0x00000100
#define IA32_MTRRCAP_WC			0x00000400

#define PHYS_BITS_TO_MASK(bits) \
	((((1ULL << (bits-1)) - 1) << 1) | 1)

static unsigned long long int mtrr_phys_mask;

#define USESTACK
#define GUEST_MALLOC(size) MmAllocateNonCachedMemory(size)
#define GUEST_FREE(p,size) MmFreeNonCachedMemory((p), (size))

#define GET32L(val64) ((Bit32u)(((Bit64u)(val64)) & 0xFFFFFFFF))
#define GET32H(val64) ((Bit32u)(((Bit64u)(val64)) >> 32))

#define IA32_MTRR_PHYMASK_VALID		0x00000800
#define IA32_MTRR_PHYSBASE_MASK		(mtrr_phys_mask & ~0x0000000000000FFFULL)
#define IA32_MTRR_PHYSBASE_TYPE		0xFF

VM_PHY_Address VIRT_PT_BASES[HOST_GB * 512];

#define MASK_TO_LEN(mask) \
	((~((mask) & IA32_MTRR_PHYSBASE_MASK) & mtrr_phys_mask) + 1)

typedef struct _MTRR_FIXED_RANGE {
	VM_PHY_Address types;
} MTRR_FIXED_RANGE, *PMTRR_FIXED_RANGE;

typedef struct _MTRR_RANGE {
	VM_PHY_Address base;
	Bit64u size;
	Bit8u type;

} MTRR_RANGE, *PMTRR_RANGE;

#define MAX_SUPPORTED_MTRR_RANGE 32
#define MAX_SUPPORTED_MTRR_FIXED_RANGE 12

#define EPTRemovePTperms(guest_phy, permsToRemove) EPTAlterPT(guest_phy, permsToRemove, TRUE);
#define EPTMapPhysicalAddress(guest_phy, perms) EPTAlterPT(guest_phy, perms, FALSE);
#define    MmuReadPhysicalRegion(phy, buffer, size)  MmuReadWritePhysicalRegion(phy, buffer, size, FALSE)

MTRR_RANGE ranges[MAX_SUPPORTED_MTRR_RANGE];
MTRR_FIXED_RANGE fixed_ranges[MAX_SUPPORTED_MTRR_FIXED_RANGE];
#pragma pack (push, 1)
/*
struct kvm_shadow_walk_iterator {
	Bit64u addr; //寻找的GuestOS的物理页帧，即(u64)gfn << PAGE_SHIFT  
	PHYSICAL_ADDRESS shadow_addr;//当前EPT页表项的物理基地址  
	int level; //当前所处的页表级别  
	Bit64u *sptep; //指向下一级EPT页表的指针  
	unsigned index;//当前页表的索引  
};
static void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator)
{
	iterator->shadow_addr = *iterator->sptep & PT64_BASE_ADDR_MASK;
	--iterator->level;
}
static int shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator)
{
	//若页表级数小于1，直接退出  
	if (iterator->level < PT_PAGE_TABLE_LEVEL)
		return 0;

	//最后一级页表  
	if (iterator->level == PT_PAGE_TABLE_LEVEL)
		if (is_large_pte(*iterator->sptep))
			return 1;

	//获得在当前页表的索引  
	iterator->index = SHADOW_PT_INDEX(iterator->addr, iterator->level);

	//取得下一级EPT页表的基地址，或最终的物理内存单元地址  
	iterator->sptep = ((Bit64u *)__va(iterator->shadow_addr)) + iterator->index;
	return 1;
}
static void shadow_walk_init(struct kvm_shadow_walk_iterator *iterator, struct kvm_vcpu *vcpu, Bit64u addr)
{
	//把要索引的地址赋给addr  
	iterator->addr = addr;

	//初始化时，要查找的页表基址就是当前VCPU的根页表目录的物理地址  
	iterator->shadow_addr = vcpu->arch.mmu.root_hpa;

	//说明EPT页表是几级页表  
	iterator->level = vcpu->arch.mmu.shadow_root_level;

	if (iterator->level == PT32E_ROOT_LEVEL) {
		iterator->shadow_addr
			= vcpu->arch.mmu.pae_root[(addr >> 30) & 3];
		iterator->shadow_addr &= PT64_BASE_ADDR_MASK;
		--iterator->level;
		if (!iterator->shadow_addr)
			iterator->level = 0;
	}
}
#define for_each_shadow_entry(_vcpu, _addr, _walker)\
	for(shadow_walk_init(&(_walker), _vcpu, _addr); \
	shadow_walk_okay(&(_walker)); \
	shadow_walk_next(&(_walker)))

static int __direct_map(struct kvm_vcpu *vcpu, gpa_t v, int write,
	int level, gfn_t gfn, pfn_t pfn)
{
	struct kvm_shadow_walk_iterator iterator;
	struct kvm_mmu_page *sp;
	int pt_write = 0;
	gfn_t pseudo_gfn;

	for_each_shadow_entry(vcpu, (Bit64u)gfn << PAGE_SHIFT, iterator) {
		if (iterator.level == level) {
			mmu_set_spte(vcpu, iterator.sptep, ACC_ALL, ACC_ALL,
				0, write, 1, &pt_write,
				level, gfn, pfn, false, true);
			++vcpu->stat.pf_fixed;
			break;
		}

		if (*iterator.sptep == shadow_trap_nonpresent_pte) {
			pseudo_gfn = (iterator.addr & PT64_DIR_BASE_ADDR_MASK) >> PAGE_SHIFT;
			sp = kvm_mmu_get_page(vcpu, pseudo_gfn, iterator.addr,
				iterator.level - 1,
				1, ACC_ALL, iterator.sptep);
			if (!sp) {
				pgprintk("nonpaging_map: ENOMEM\n");
				kvm_release_pfn_clean(pfn);
				return -ENOMEM;
			}

			__set_spte(iterator.sptep,
				__pa(sp->spt)
				| PT_PRESENT_MASK | PT_WRITABLE_MASK
				| shadow_user_mask | shadow_x_mask);
		}
	}
	return pt_write;
}*/

typedef struct
{
	VM_PHY_Address Eptp;
	VM_PHY_Address Rsvd;

} INVEPT_DESCRIPTOR, *PINVEPT_DESCRIPTOR;

#pragma pack (pop)

INVEPT_DESCRIPTOR EPTInveptDesc;

VM_PHY_Address     Pml4;
VM_PHY_Address	Phys_Pml4;

typedef struct _EVENT_CONDITION_EPT_VIOLATION {
	VM_BOOL read;
	VM_BOOL write;
	VM_BOOL exec;
	VM_BOOL is_linear_valid;
	VM_BOOL in_page_walk;
	VM_BOOL fill_an_entry;

} EVENT_CONDITION_EPT_VIOLATION, *PEVENT_CONDITION_EPT_VIOLATION;
void *vmm_memcpy(void *dst, void *src, Bit32u n)
{
	Bit32u i = 0;
	unsigned char *p1 = (unsigned char*)dst;
	unsigned char *p2 = (unsigned char*)src;

	while (i < n) {
		p1[i] = p2[i];
		i++;
	}
	return p1;

}

extern PVOID AllocateContiguousMemory(ULONG size);
extern BOOLEAN IsBitSet(ULONG64 v, UCHAR bitNo);

void vmm_memset(void *s, int c, Bit32u n)
{
	unsigned char *p;
	Bit32u i;

	p = (unsigned char*)s;
	for (i = 0; i < n; i++) {
		p[i] = (unsigned char)c;
	}
}
void CmSetBit32(Bit64u* dword, Bit32u bit)
{
	Bit64u mask = (1 << bit);
	*dword = *dword | mask;
}

NTSTATUS EPTInit()
{
	unsigned long long count = 0;
	unsigned int i, n;
	MSR base, mask;
	ULONG32 eax, ebx, ecx, edx;
	SHORT_CPU m_EAX;
	/* Get phys address size from from CPUID.80000008 (useless on 32 bit but whatever) */
	/*  31                          16 15              8 7              0  */
	/* +------------------------------+-----------------+----------------+ */
	/* |##############################|VirtualMemoryBits| PhysMemoryBits | */
	/* +------------------------------+-----------------+----------------+ */
	_CpuId(0x80000008, &eax, &ebx, &ecx, &edx);



	n = eax;

	n &= 0xff;
	mtrr_phys_mask = PHYS_BITS_TO_MASK(n);

	vmm_memset(ranges, 0, MAX_SUPPORTED_MTRR_RANGE*sizeof(MTRR_RANGE));
	vmm_memset(fixed_ranges, 0, MAX_SUPPORTED_MTRR_RANGE*sizeof(MTRR_FIXED_RANGE));

	_ReadMsr(MSR_IA32_MTRRCAP, &base);
	count = ((((unsigned long long) base.Hi) << 32) | base.Lo) & IA32_MTRRCAP_VCNT;
	for (i = 0; i < count; i++) {
		_ReadMsr(MSR_IA32_MTRR_PHYSBASE(i), &base);
		_ReadMsr(MSR_IA32_MTRR_PHYSMASK(i), &mask);
		if (i >= MAX_SUPPORTED_MTRR_RANGE) {
			FGP_VT_KDPRINT(("PANIC! Not enough space for mtrr ranges!!!\n"));

			return STATUS_INSUFFICIENT_RESOURCES;

		}
		if (mask.Lo & IA32_MTRR_PHYMASK_VALID) {
			ranges[i].base = base.Lo & IA32_MTRR_PHYSBASE_MASK;
			ranges[i].size = MASK_TO_LEN((((unsigned long long) mask.Hi) << 32) | mask.Lo);
			ranges[i].type = (Bit8u)(base.Lo & IA32_MTRR_PHYSBASE_TYPE);
		}
	}

	i = 0;
	_ReadMsr(MSR_IA32_MTRR_FIX64K_00000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX16K_80000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX16K_A0000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX4K_C0000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX4K_C8000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX4K_D0000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX4K_D8000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX4K_E0000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX4K_E8000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX4K_F0000, &base);
	fixed_ranges[i++].types = base.Lo;
	_ReadMsr(MSR_IA32_MTRR_FIX4K_F8000, &base);
	fixed_ranges[i++].types = base.Lo;
	return STATUS_SUCCESS;
}

Bit8u EPTGetMemoryType(VM_Address address)
{
	Bit8u type = 0, index;
	if (address < 0x100000) { /* Check in fixed ranges */
		if (address < 0x80000) { /* 00000000:00080000 */
			type = (fixed_ranges[0].types & (0xff << ((address >> 16) * 8))) >> ((address >> 16) * 8);
		}
		else if (address < 0xa0000){
			address -= 0x80000;
			type = (fixed_ranges[1].types & (0xff << ((address >> 14) * 8))) >> ((address >> 14) * 8);
		}
		else if (address < 0xc0000) {
			address -= 0xa0000;
			type = (fixed_ranges[2].types & (0xff << ((address >> 14) * 8))) >> ((address >> 14) * 8);
		}
		else {
			index = ((address - 0xc0000) >> 15) + 3;
			address &= 0x7fff;
			type = (fixed_ranges[index].types & (0xff << ((address >> 12) * 8))) >> ((address >> 12) * 8);
		}
	}
	else {
		index = 0;
		while (index < MAX_SUPPORTED_MTRR_RANGE) {
			if (ranges[index].base <= address && (ranges[index].base + ranges[index].size) > address) {
				return ranges[index].type;
			}
			index++;
		}
		type = MEM_TYPE_WRITEBACK;
	}
	return type;
}

void EPTAlterPT(VM_Address guest_phy, Bit8u perms, VM_Address isRemove)
{
	VM_Address entryNum, offset;
	Bit32u pte_low, pte_high = 0;
	VM_Address pdpte_num, pde_num, pte_num;
	VM_Address  va_of_pte;

	/* First level */
	entryNum = guest_phy & 0xc0000000;
	entryNum = entryNum >> 30;
	pdpte_num = entryNum;

	/* Second level */
	entryNum = guest_phy & 0x3fe00000;
	entryNum = entryNum >> 21;
	pde_num = entryNum;

	/* Third level */
	entryNum = guest_phy & 0x001ff000;
	entryNum = entryNum >> 12;
	pte_num = entryNum;
	offset = entryNum * 8;

	/* Fourth level */
	va_of_pte = VIRT_PT_BASES[(pdpte_num * 512) + pde_num] + (pte_num * 8);

	if (isRemove) {
		pte_low = *((VM_Address *)va_of_pte);
		pte_low = (pte_low | (EPTGetMemoryType(pte_low & 0xfffff000) << 3)) & ~perms;
	}
	else {
		pte_low = (guest_phy & 0xfffff000) | (EPTGetMemoryType(guest_phy & 0xfffff000) << 3) | perms;
	}

	/* Write new entry, two 4 byte writes */
	*((VM_Address *)va_of_pte) = pte_low;
	//*((VM_Address *)(va_of_pte + 4)) = pte_high;

	/* Invalidate EPT cache */
	struct {
		Bit64u eptp, gpa;
	} operand = { EPTInveptDesc.Eptp, EPTInveptDesc.Rsvd };
	_EptInvept(SINGLE_CONTEXT_INVALIDATION, &operand);
}

VM_Address EPTGetEntry(VM_Address guest_phy)
{
	VM_Address entryNum, offset;
	VM_Address pdpte_num, pde_num, pte_num;
	VM_Address va_of_pte;

	/* First level */
	entryNum = guest_phy & 0xc0000000;
	entryNum = entryNum >> 30;
	pdpte_num = entryNum;

	/* Second level */
	entryNum = guest_phy & 0x3fe00000;
	entryNum = entryNum >> 21;
	pde_num = entryNum;

	/* Third level */
	entryNum = guest_phy & 0x001ff000;
	entryNum = entryNum >> 12;
	pte_num = entryNum;
	offset = entryNum * 8;

	/* Fourth level */
	va_of_pte = VIRT_PT_BASES[(pdpte_num * 512) + pde_num] + (pte_num * 8);

	return va_of_pte;
}

NTSTATUS MmuUnmapPhysicalPage(VM_Address va, PTE entryOriginal)
{
	PPTE pentry;

	/* Restore original PTE */
	pentry = (PPTE)(VIRTUAL_PT_BASE + (((VA_TO_PDE(va)) << 12) | (VA_TO_PTE(va) * sizeof(PTE))));
	// pentry = (PPTE) (VIRTUAL_PT_BASE + (VA_TO_PTE(va) * sizeof(PTE)));
	*pentry = entryOriginal;

	_RushTLB();

	return STATUS_SUCCESS;
}

NTSTATUS MmuFindUnusedPTE(VM_Address* pdwLogical)
{
	VM_Address dwCurrentAddress, dwPTEAddr;

	VM_Address dwPDEAddr;

	for (dwCurrentAddress = MMU_PAGE_SIZE; dwCurrentAddress < 0x80000000; dwCurrentAddress += MMU_PAGE_SIZE) {
		/* Check if memory page at logical address 'dwCurrentAddress' is free */
		Bit64u dwPDE, dwPTE;
		dwPDEAddr = VIRTUAL_PD_BASE + \
			((VA_TO_PDE(dwCurrentAddress) | (VA_TO_PDPTE(dwCurrentAddress) << 9)) * sizeof(PTE));

		dwPDE = READ_PTE(dwPDEAddr);
		if (!PDE_TO_VALID(dwPDE))
			continue;

		//    dwPTEAddr = VIRTUAL_PT_BASE + (VA_TO_PTE(dwCurrentAddress) * sizeof(PTE));
		dwPTEAddr = (VIRTUAL_PT_BASE + (((VA_TO_PDE(dwCurrentAddress)) << 12) | (VA_TO_PTE(dwCurrentAddress) * sizeof(PTE))));
		dwPTE = READ_PTE(dwPTEAddr);

		if (PDE_TO_VALID(dwPTE)) {
			/* Skip *valid* PTEs */
			continue;
		}

		/* All done!*/
		*pdwLogical = dwCurrentAddress;
		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;

}

NTSTATUS MmuMapPhysicalPage(VM_PHY_Address phy, VM_PHY_Address* pva, PPTE pentryOriginal)
{
	NTSTATUS r;
	VM_Address dwEntryAddress, dwLogicalAddress;
	PTE *pentry;

	/* Get unused PTE address in the current process */
	FGP_VT_KDPRINT(("[vt_64] MmuMapPhysicalPage() Searching for unused PTE...\n"));
	r = MmuFindUnusedPTE(&dwLogicalAddress);
	FGP_VT_KDPRINT(("[vt_64] MmuMapPhysicalPage() Unused PTE found at %.8x\n", dwLogicalAddress));

	if (r != STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	dwEntryAddress = VIRTUAL_PT_BASE + (((VA_TO_PDE(dwLogicalAddress)) << 12) | (VA_TO_PTE(dwLogicalAddress) * sizeof(PTE)));
	//  dwEntryAddress = VIRTUAL_PT_BASE + (VA_TO_PTE(dwLogicalAddress) * sizeof(PTE));

	pentry = (PPTE)dwEntryAddress;

	/* Save original PT entry */
	*pentryOriginal = *pentry;

	/* Replace PT entry */
	pentry->Present = 1;
	pentry->Writable = 1;
	pentry->Owner = 1;
	pentry->WriteThrough = 0;
	pentry->CacheDisable = 0;
	pentry->Accessed = 0;
	pentry->Dirty = 0;
	pentry->LargePage = 0;
	pentry->Global = 0;
	pentry->ForUse1 = 0;
	pentry->ForUse2 = 0;
	pentry->ForUse3 = 0;
	pentry->PageBaseAddr = PHY_TO_FRAME(phy);

	_RushTLB();

	*pva = dwLogicalAddress;

	return STATUS_SUCCESS;
}

NTSTATUS MmuReadWritePhysicalRegion(VM_PHY_Address phy, void* buffer, Bit32u size, int isWrite)
{
	NTSTATUS r;
	VM_Address dwLogicalAddress;
	PTE entryOriginal;

	/* Check that the memory region to read does not cross multiple frames */
	if (PHY_TO_FRAME(phy) != PHY_TO_FRAME(phy + size - 1)) {
		FGP_VT_KDPRINT(("[vt_64] Error: physical region %.8x-%.8x crosses multiple frames\n", phy, phy + size - 1));
		return STATUS_UNSUCCESSFUL;
	}

	r = MmuMapPhysicalPage(phy, &dwLogicalAddress, &entryOriginal);
	if (r != STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	dwLogicalAddress += MMU_PAGE_OFFSET(phy);

	if (!isWrite) {
		/* Read memory page */
		FGP_VT_KDPRINT(("[vt_64] MmuReadWritePhysicalRegion() Going to read %d from va: %.8x\n", size, dwLogicalAddress));
		vmm_memcpy(buffer, (Bit8u*)dwLogicalAddress, size);

	}
	else {
		/* Write to memory page */
		vmm_memcpy((Bit8u*)dwLogicalAddress, buffer, size);
	}

	FGP_VT_KDPRINT(("[vt_64] MmuReadWritePhysicalRegion() All done!\n"));

	MmuUnmapPhysicalPage(dwLogicalAddress, entryOriginal);

	return STATUS_SUCCESS;
}


NTSTATUS MmuGetPageEntry(VM_Address cr3, VM_Address va, PPTE ppte, int* pisLargePage)
{
	NTSTATUS r;
	VM_PHY_Address addr;
	PTE p;

	FGP_VT_KDPRINT(("[vt_64] MmuGetPageEntry() cr3: %.8x va: %.8x\n", CR3_ALIGN(cr3), va));

	/* Read PDPTE */
	addr = CR3_ALIGN(cr3) + (VA_TO_PDPTE(va)*sizeof(PTE));
	r = MmuReadPhysicalRegion(addr, &p, sizeof(PTE));
	if (r != STATUS_SUCCESS) {
		FGP_VT_KDPRINT(("[vt_64] MmuGetPageEntry() cannot read PDPTE from %.8x\n", addr));
		return STATUS_UNSUCCESSFUL;
	}

	if (!p.Present)
		return STATUS_UNSUCCESSFUL;

	/* Read PDE */
	addr = FRAME_TO_PHY(p.PageBaseAddr) + (VA_TO_PDE(va)*sizeof(PTE));

	FGP_VT_KDPRINT(("[vt_64] MmuGetPageEntry() Reading phy %.8x%.8x (NOT large)\n", GET32H(addr), GET32L(addr)));
	r = MmuReadPhysicalRegion(addr, &p, sizeof(PTE));

	if (r != STATUS_SUCCESS) {
		FGP_VT_KDPRINT(("[vt_64] MmuGetPageEntry() cannot read PDE from %.8x\n", addr));
		return STATUS_UNSUCCESSFUL;
	}

	FGP_VT_KDPRINT(("[vt_64] MmuGetPageEntry() PDE read. Present? %d Large? %d\n", p.Present, p.LargePage));

	if (!p.Present)
		return STATUS_UNSUCCESSFUL;

	/* If it's present and it's a 4MB page, then this is a hit */
	if (p.LargePage) {
		if (ppte) *ppte = p;
		*pisLargePage = TRUE;
		return STATUS_SUCCESS;
	}

	/* Read PTE */
	addr = FRAME_TO_PHY(p.PageBaseAddr) + (VA_TO_PTE(va)*sizeof(PTE));
	r = MmuReadPhysicalRegion(addr, &p, sizeof(PTE));

	if (r != STATUS_SUCCESS) {
		FGP_VT_KDPRINT(("[vt_64] MmuGetPageEntry() cannot read PTE from %.8x\n", addr));
		return STATUS_UNSUCCESSFUL;
	}

	FGP_VT_KDPRINT(("[vt_64] MmuGetPageEntry() PTE read. Present? %d\n", p.Present));

	if (!p.Present)
		return STATUS_UNSUCCESSFUL;

	if (ppte) *ppte = p;
	*pisLargePage = FALSE;

	return STATUS_SUCCESS;
}

NTSTATUS MmuGetPhysicalAddress(VM_Address cr3, VM_Address va, VM_Address* pphy)
{
	NTSTATUS r;
	PTE pte;
	int isLarge;

	r = MmuGetPageEntry(CR3_ALIGN(cr3), va, &pte, &isLarge);

	if (r != STATUS_SUCCESS) {
		return STATUS_UNSUCCESSFUL;
	}

	if (isLarge) {
		*pphy = LARGEFRAME_TO_PHY(pte.PageBaseAddr) + LARGEPAGE_OFFSET(va);
		FGP_VT_KDPRINT(("[vt_64]MmuGetPhysicalAddress(LARGE) cr3: %.8x frame: %.8x va: %.8x phy: %.8x\n",
			CR3_ALIGN(cr3), pte.PageBaseAddr, va, *pphy));
		return STATUS_SUCCESS;
	}

	*pphy = FRAME_TO_PHY(pte.PageBaseAddr) + MMU_PAGE_OFFSET(va);

	return STATUS_SUCCESS;
}


void EPTProtectPhysicalRange(VM_Address base, Bit32u size, Bit8u permsToRemove) {

	VM_PHY_Address phyaddr;
	VM_Address i;

	for (i = base; i < base + size; i = i + 4096) {
		MmuGetPhysicalAddress(_Cr3(), i, &phyaddr);
		EPTRemovePTperms(phyaddr, permsToRemove);
	}
}

/*
NTSTATUS EPTInit(PVIRT_CPU pCpu , PLARGE_INTEGER lpEpte)
{
	unsigned long long count = 0;
	unsigned int i, n;
	LARGE_INTEGER base ;
	ULONG32 eax, ebx, ecx, edx;
	SHORT_CPU m_EAX;
	ULONG64 eptp,EptVpid;
	PHYSICAL_ADDRESS pa;
	PVOID va;

	/ * Get phys address size from from CPUID.80000008 (useless on 32 bit but whatever) * /
	/ *  31                          16 15              8 7              0  * /
	/ * +------------------------------+-----------------+----------------+ * /
	/ * |##############################|VirtualMemoryBits| PhysMemoryBits | * /
	/ * +------------------------------+-----------------+----------------+ * /
	_CpuId(0x80000008, &eax, &ebx, &ecx, &edx);

	m_EAX.QuadPart = eax;
	va = AllocateContiguousMemory(64 * PAGE_SIZE);
	pa = MmGetPhysicalAddress(va);

	if (va == NULL)
	{
		FGP_VT_KDPRINT(("error: can't allocate ep4ta map\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	pCpu->Ep4ta_Base_va = va;
	pCpu->Ep4ta_Base_pa = pa;
	base.QuadPart =_GetMaxPhyaddr(m_EAX.LowPart);
	FGP_VT_KDPRINT(("Cpu PhysMemoryBits is %llx \n", m_EAX.LowPart));
	eptp = pa.QuadPart & ~0x0fff & base.QuadPart;
	FGP_VT_KDPRINT(("MaxPhyAddrSelectMask is %llx \n", base.QuadPart));
	EptVpid = _ReadMsr(MSR_IA32_VMX_EPT_VPID_CAP);
	if (IsBitSet(EptVpid, 21))
	{
		eptp = eptp | (1<<6);
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
	lpEpte->QuadPart = eptp;
	FGP_VT_KDPRINT(("Epte is %llx \n", eptp));
	
	return STATUS_SUCCESS;

	/ *eax &= 0xff;
	mtrr_phys_mask = PHYS_BITS_TO_MASK(eax);

	vmm_memset(ranges, 0, MAX_SUPPORTED_MTRR_RANGE*sizeof(MTRR_RANGE));
	vmm_memset(fixed_ranges, 0, MAX_SUPPORTED_MTRR_RANGE*sizeof(MTRR_FIXED_RANGE));

	base.QuadPart = _ReadMsr(MSR_IA32_MTRRCAP);
	count = ((((unsigned long long) base.HighPart) << 32) | base.QuadPart) & IA32_MTRRCAP_VCNT;
	for (i = 0; i < count; i++) {
		base.QuadPart = _ReadMsr(MSR_IA32_MTRR_PHYSBASE(i));
		mask.QuadPart = _ReadMsr(MSR_IA32_MTRR_PHYSMASK(i));
		if (i >= MAX_SUPPORTED_MTRR_RANGE) {
			FGP_VT_KDPRINT(("PANIC! Not enough space for mtrr ranges!!!"));
		}
		if (mask.LowPart & IA32_MTRR_PHYMASK_VALID) {
			ranges[i].base = base.LowPart & IA32_MTRR_PHYSBASE_MASK;
			ranges[i].size = MASK_TO_LEN((((unsigned long long) mask.HighPart) << 32) | mask.LowPart);
			ranges[i].type = (Bit8u)(base.LowPart & IA32_MTRR_PHYSBASE_TYPE);
		}
	}

	i = 0;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX64K_00000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX16K_80000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX16K_A0000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX4K_C0000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX4K_C8000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX4K_D0000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX4K_D8000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX4K_E0000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX4K_E8000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX4K_F0000);
	fixed_ranges[i++].types = base.LowPart;
	base.QuadPart = _ReadMsr(MSR_IA32_MTRR_FIX4K_F8000);
	fixed_ranges[i++].types = base.LowPart;* /
}*/
/*
void EPTAlterPT(hvm_address guest_phy, Bit8u perms, hvm_bool isRemove)
{
	Bit32u entryNum, offset;
	Bit32u pdpte_num, pde_num, pte_num;
	hvm_address pte_low, pte_high = 0, va_of_pte;

	/ * First level * /
	entryNum = guest_phy & 0xc0000000;
	entryNum = entryNum >> 30;
	pdpte_num = entryNum;

	/ * Second level * /
	entryNum = guest_phy & 0x3fe00000;
	entryNum = entryNum >> 21;
	pde_num = entryNum;

	/ * Third level * /
	entryNum = guest_phy & 0x001ff000;
	entryNum = entryNum >> 12;
	pte_num = entryNum;
	offset = entryNum * 8;

	/ * Fourth level * /
	va_of_pte = VIRT_PT_BASES[(pdpte_num * 512) + pde_num] + (pte_num * 8);

	if (isRemove) {
		pte_low = *((hvm_address *)va_of_pte);
		pte_low = (pte_low | (EPTGetMemoryType(pte_low & 0xfffff000) << 3)) & ~perms;
	}
	else {
		pte_low = (guest_phy & 0xfffff000) | (EPTGetMemoryType(guest_phy & 0xfffff000) << 3) | perms;
	}

	/ * Write new entry, two 4 byte writes * /
	*((hvm_address *)va_of_pte) = pte_low;
	*((hvm_address *)(va_of_pte + 4)) = pte_high;

	/ * Invalidate EPT cache * /
	EptInvept(GET32H(EPTInveptDesc.Eptp), GET32L(EPTInveptDesc.Eptp), GET32H(EPTInveptDesc.Rsvd), GET32L(EPTInveptDesc.Rsvd));
}*/