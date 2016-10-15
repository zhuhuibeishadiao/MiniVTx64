#pragma once
//#include "Def.h"
#include <Ntifs.h>
//#include "Wdm.h"
//#include "ntddk.h"
#include "ept1.h"


#pragma pack(push, pe, 1)
struct ImageDosHeader_s
{
	UINT16 e_magic;
	UINT16 e_cblp;
	UINT16 e_cp;
	UINT16 e_crlc;
	UINT16 e_cparhdr;
	UINT16 e_minalloc;
	UINT16 e_maxalloc;
	UINT16 e_ss;
	UINT16 e_sp;
	UINT16 e_csum;
	UINT16 e_ip;
	UINT16 e_cs;
	UINT16 e_lfarlc;
	UINT16 e_ovno;
	UINT16 e_res[4];
	UINT16 e_oemid;
	UINT16 e_oeminfo;
	UINT16 e_res2[10];
	UINT32 e_lfanew;
};

typedef struct ImageDosHeader_s ImageDosHeader;

struct ImageFileHeader_s
{
	UINT16 Machine;
	UINT16 NumberOfSections;
	UINT32 TimeDateStamp;
	UINT32 PointerToSymbolTable;
	UINT32 NumberOfSymbols;
	UINT16 SizeOfOptionalHeader;
	UINT16 Characteristics;
};

typedef struct ImageFileHeader_s ImageFileHeader;

struct ImageDataDirectory_s
{
	UINT32 VirtualAddress;
	UINT32 Size;
};

typedef struct ImageDataDirectory_s ImageDataDirectory;

struct ImageOptionalHeader_s
{
	UINT16 Magic;
	UINT8 MajorLinkerVersion;
	UINT8 MinorLinkerVersion;
	UINT32 SizeOfCode;
	UINT32 SizeOfInitializedData;
	UINT32 SizeOfUninitializedData;
	UINT32 AddressOfEntryPoint;
	UINT32 BaseOfCode;
	UINT32 BaseOfData;
	UINT32 ImageBase;
	UINT32 SectionAlignment;
	UINT32 FileAlignment;
	UINT16 MajorOperatingSystemVersion;
	UINT16 MinorOperatingSystemVersion;
	UINT16 MajorImageVersion;
	UINT16 MinorImageVersion;
	UINT16 MajorSubsystemVersion;
	UINT16 MinorSubsystemVersion;
	UINT32 Win32VersionValue;
	UINT32 SizeOfImage;
	UINT32 SizeOfHeaders;
	UINT32 CheckSum;
	UINT16 Subsystem;
	UINT16 DllCharacteristics;
	UINT32 SizeOfStackReserve;
	UINT32 SizeOfStackCommit;
	UINT32 SizeOfHeapReserve;
	UINT32 SizeOfHeapCommit;
	UINT32 LoaderFlags;
	UINT32 NumberOfRvaAndSizes;
	ImageDataDirectory DataDirectory[16];
};

typedef struct ImageOptionalHeader_s ImageOptionalHeader;

struct ImageSectionHeader_s
{
	UINT8 Name[8];
	union
	{
		UINT32 PhysicalAddress;
		UINT32 VirtualSize;
	} Misc;
	UINT32 VirtualAddress;
	UINT32 SizeOfRawData;
	UINT32 PointerToRawData;
	UINT32 PointerToRelocations;
	UINT32 PointerToLinenumbers;
	UINT16 NumberOfRelocations;
	UINT16 NumberOfLinenumbers;
	UINT32 Characteristics; /**< Bitmask of section characteristics */
};

typedef struct ImageSectionHeader_s ImageSectionHeader;

struct ImageBaseRelocation_s
{
	UINT32 VirtualAddress;
	UINT32 SizeOfBlock;
};

typedef struct ImageBaseRelocation_s ImageBaseRelocation;

struct ImageNtHeaders_s
{
	UINT32 Signature;
	ImageFileHeader FileHeader;
	ImageOptionalHeader OptionalHeader;
};

typedef struct ImageNtHeaders_s ImageNtHeaders;

typedef ImageDataDirectory SectionData;

struct PageDirectoryEntrySmallPage_s
{
#ifdef X86
	UINT32 p : 1; // Present
	UINT32 rw : 1; // Read/Write
	UINT32 us : 1; // User/Superuser
	UINT32 pwt : 1; // Page write through
	UINT32 pcd : 1; // Page level cache disable
	UINT32 a : 1; // Accessed
	UINT32 ignored : 1; // Ignored
	UINT32 ps : 1; // Page Size
	UINT32 reserved1 : 4; // Must be 0
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

typedef struct PageDirectoryEntrySmallPage_s PageDirectoryEntrySmallPage;

struct PageDirectoryEntry_s
{
#ifdef X86
	UINT32 p : 1; // Present
	UINT32 rw : 1; // Read/Write
	UINT32 us : 1; // User/Superuser
	UINT32 pwt : 1; // Page write through
	UINT32 pcd : 1; // Page level cache disable
	UINT32 a : 1; // Accessed
	UINT32 d : 1; // Dirty
	UINT32 ps : 1; // Large page
	UINT32 g : 1; // Global
	UINT32 reserved1 : 3; // Must be 0
	UINT32 pat : 1;	// PAT must be 0
	UINT32 reserved2 : 9; // Must be 0
	UINT32 address : 10;	// Address of page.
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
#endif // X

	
};

typedef struct PageDirectoryEntry_s PageDirectoryEntry;
#pragma pack(pop, pe)
char TargetAppName[] = "cpuid.exe";
#define MONITOR_PROCS 1
/** Boolean for whether or not to periodically measure the binary */
//#define PERIODIC_MEASURE 1
#define MONITOR_PROCS 1
/** Boolean for whether or not to periodically measure the binary */
#define PERIODIC_MEASURE 1
/** VMCALL code to initialize the TLB split */
#define VMCALL_INIT_SPLIT 0x100F
/** VMCALL code to end the TLB split */
#define VMCALL_END_SPLIT 0x200F
/** VMCALL code to measure the PE */
#define VMCALL_MEASURE 0x300F

#define IMAGE_SCN_CNT_CODE 0x00000020
/** The section contains initialized data */
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
/** The section contains un-initialized data */
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
/** The section is executable */
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
/** The section is readable */
#define IMAGE_SCN_MEM_READ 0x40000000
/** The section is writable */
#define IMAGE_SCN_MEM_WRITE 0x80000000

#define DATA_EPT 0x1
#define CODE_EPT 0x2
#define VDEBUG 1
/** Stack storage for the APC state */
KAPC_STATE apcstate;
UINT8 *appCopy = NULL;
/** MDL for probe and locking physical pages into memory */
PMDLX LockedMdl = NULL;
/** PHYSICAL_ADDRESS used to allow allocation anywhere in the 4GB range */
PHYSICAL_ADDRESS highestMemoryAddress = { 0 };
/** Pointer to the TlbTranslation array used by the EPT violation handler to split the TLB */
TlbTranslation *translationArr = NULL;

PHYSICAL_ADDRESS *targetPhys;

UINT32 appsize = 0;
UINT64 targetCR3 = 0;

PHYSICAL_ADDRESS targetPePhys = { 0 };
void *targetPeVirt = NULL;
UINT8 *targetPePtr = NULL;
PEPROCESS targetProc = NULL;
PageTableEntry **targetPtes;

/* Periodic Measurement Thread control (Created in entry, used in thread and unload) */
/** Thread object */
static VOID * periodicMeasureThread = NULL;
/** Thread body loop control variable */
static UCHAR periodicMeasureThreadExecute = 0;
/** Raise this event to abort the loop delay */
static KEVENT periodicMeasureThreadWakeUp = { 0 };
extern PVOID PsGetProcessSectionBaseAddress(PEPROCESS);
extern char * PsGetProcessImageFileName(PEPROCESS);

static KSTART_ROUTINE periodicMeasurePe;

/**
@brief Callback for when a new process is created

Detects if the new process is a target for TLB splitting
@param ParentID ID of parent process
@param ProcessId ID of newly created process
@param Create True if the process is being created, false if it's being destroyed
*/
void processCreationMonitor(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);

/**
Function to make a copy of a PE image

@param proc PEPROCESS of the target PE
@param apc Pointer to an APC state structure
@param srcPtr Source VA
@param targetPtr Memory buffer to copy to
@param len Number of bytes to copy
*/
void copyPe(PEPROCESS proc, PKAPC_STATE apc, UINT8 *srcPtr, UINT8 *targetPtr, UINT32 len);

/**
Allocates and fills in an array (null terminated) of VA -> Physical mappings and PTEs

@param srcPtr Pointer to image base
@param targetPtr Pointer to copy
@param len Number of bytes to copy
@param cr3Reg CR3 register of target application
@return Pointer to TlbTranslation array
*/
TlbTranslation * allocateAndFillTranslationArray(UINT8 *codePtr,
	UINT8 *dataPtr,
	UINT32 len,
	PEPROCESS proc,
	PKAPC_STATE apc);

/**
Frees and safely de-allocates a TLB translation array allocated with
allocateAndFillTranslationArry

@param arr Pointer to TlbTranslation array
*/
void freeTranslationArray(TlbTranslation *arr);

/**
Returns the relevant TlbTranslation for the passed guest physial address

@param transArr Pointer to array of all known translations
@param guestPhysical Physical address

@return Pointer to TlbTranslation pointing to the guest physical
*/
//TlbTranslation * getTlbTranslation(TlbTranslation * transArr, UINT64 guestPhysical);

#if 0
/**
Function to 'lock' a process' memory into physical memory and prevent paging

@param startAddr Starting virtual address to lock
@param len Number of bytes to lock
@param proc PEPROCESS pointer to the process
@param apcstate Pointer to an APC state memory location
@return MDL to be used later to unlock the memory or NULL if lock failed
*/
PMDLX pagingLockProcessMemory(PVOID startAddr, UINT32 len, PEPROCESS proc, PKAPC_STATE apcstate);

/**
Function to 'lock' a process' memory into physical memory and prevent paging

@param proc PEPROCESS pointer to the process
@param apcstate Pointer to an APC state memory location
@param mdl Pointer to previously locked process MDL
*/
void pagingUnlockProcessMemory(PEPROCESS proc, PKAPC_STATE apcstate, PMDLX mdl);
#endif

/**
Tests the TLB splitting for a single page instance
This function emulates the functionality of MoRE drop 1
*/
void splitPage();

/**
Measures the PE and displays the checksum

@param phys Physical address of the image header
@param PeHeaderVirt Process's virtual address
*/
void measurePe(PHYSICAL_ADDRESS phys, void * peHeaderVirt);

PageTableEntry * pagingMapInPte(UINT64 _CR3, void *virtualAddress);

void pagingMapOutEntry(void *ptr);

void AppendTlbTranslation(TlbTranslation * transArr, UINT64 phys, UINT8 * virt);

UINT32 checksumBuffer(UINT8 * ptr, UINT32 len);

UINT32 peGetNumberOfRelocs(UINT8 *peBaseAddr, void *realBase, PEPROCESS proc, PKAPC_STATE apc);


UINT8 * peMapInImageHeader(PHYSICAL_ADDRESS physAddr)
{
	UINT8 *pePtr = NULL;
	UINT32 imageSize = 0;

	pePtr = (UINT8*)MmMapIoSpace(physAddr, PAGE_SIZE, MmNonCached);
	if (pePtr == NULL || *pePtr != 'M' || *(pePtr + 1) != 'Z')
	{
		DbgPrint("Invalid physical address!");
		if (pePtr != NULL)
			MmUnmapIoSpace(pePtr, PAGE_SIZE);
		return NULL;
	}

	return pePtr;
}

UINT32 peGetImageSize(UINT8 *peBaseAddr)
{
	ImageDosHeader *dosHeader = NULL;
	ImageNtHeaders *ntHeaders = NULL;
	UINT16 *ptr = (UINT16 *)peBaseAddr;

	dosHeader = (ImageDosHeader *)peBaseAddr;
	ntHeaders = (ImageNtHeaders *)((UINT8 *)peBaseAddr + dosHeader->e_lfanew);

	return ntHeaders->OptionalHeader.SizeOfImage;
}
void peMapOutImageHeader(UINT8 *peBaseAddr)
{
	MmUnmapIoSpace(peBaseAddr, PAGE_SIZE);
}
void pagingMapOutEntryDirql(void *ptr, PagingContext * context)
{
	if (ptr != NULL)
		MapOutMemory(context, ptr, sizeof(PageTableEntry));
}
void pagingMapOutEntry(void *ptr)
{
	pagingMapOutEntryDirql(ptr, NULL);
}
PageDirectoryEntry * pagingMapInPdeDirql(UINT64 _CR3,
	void *virtualAddress,
	PagingContext * context)
{
	PHYSICAL_ADDRESS pageDirPhys = { 0 };
	UINT64 pdeOff = ((UINT64)virtualAddress & 0xFFC00000) >> 22;
	pageDirPhys.QuadPart = (_CR3 & 0xFFFFF000) |
		(pdeOff * sizeof(PageDirectoryEntry));

	return (PageDirectoryEntry *)MapInMemory(context, pageDirPhys,
		sizeof(PageDirectoryEntry));
}
PageTableEntry * pagingMapInPteDirql(UINT64 _CR3,
	void *virtualAddress,
	PagingContext * context)
{
	PHYSICAL_ADDRESS pageTablePhys = { 0 };
	PageDirectoryEntrySmallPage *pageDirectory = (PageDirectoryEntrySmallPage *)
		pagingMapInPdeDirql(_CR3, virtualAddress, context);
	PageTableEntry *outPte = NULL;
	UINT64 pdeOff, pteOff, pageOff = 0;

	if (pageDirectory == NULL)
	{
		return NULL;
	}

	// Determine if we're dealing with large or small pages
	if (pageDirectory->LargePage == 1 || pageDirectory->Valid == 0)
	{
		// We are a PDE, not PTE   
		outPte = NULL;
	}
	else
	{
		pteOff = ((UINT64)virtualAddress & 0x003FF000) >> 12;
		pageTablePhys.QuadPart = (pageDirectory->PageFrameNumber << 12) |
			(pteOff * sizeof(PageTableEntry));

		outPte = (PageTableEntry*)MapInMemory(context, pageTablePhys, sizeof(*outPte));
	}

	pagingMapOutEntryDirql((void *)pageDirectory, context);
	return outPte;
}
PageTableEntry * pagingMapInPte(UINT64 _CR3, void *virtualAddress)
{
	return pagingMapInPteDirql(_CR3, virtualAddress, NULL);
}

UINT32 peGetNumberOfRelocs(UINT8 *peBaseAddr, void *realBase, PEPROCESS proc, PKAPC_STATE apc)
{
	ImageDosHeader *dosHeader = NULL;
	ImageNtHeaders *ntHeaders = NULL;
	ImageSectionHeader *sectionHeader = NULL;
	ImageBaseRelocation *relocationPtr = NULL, *bkupRPtr = NULL;
	UINT32 numRelocs = 0;
	PageTableEntry *pte = NULL;
	PHYSICAL_ADDRESS phys = { 0 };

	UINT16 i, j = 0, execSectionCount = 0, numSections = 0;

	dosHeader = (ImageDosHeader *)peBaseAddr;
	ntHeaders = (ImageNtHeaders *)((UINT8 *)peBaseAddr + dosHeader->e_lfanew);
	numSections = ntHeaders->FileHeader.NumberOfSections;
	sectionHeader = (ImageSectionHeader *)&ntHeaders[1];

	for (i = 0; i < numSections; i++)
	{
		if (strncmp(sectionHeader[i].Name, ".reloc", 8) == 0)
			break;
	}
	if (strncmp(sectionHeader[i].Name, ".reloc", 8) != 0)
		return 0;
	/*DbgPrint("Found %.08s RVA: %x Characteristics: %x", sectionHeader[i].Name,
	sectionHeader[i].VirtualAddress,
	sectionHeader[i].Characteristics);*/

	//KeStackAttachProcess(proc, apc);
	pte = pagingMapInPte(targetCR3, (UINT8 *)(((UINT32)realBase) +
		sectionHeader[i].VirtualAddress));
	if (pte == NULL)
		return 0;
	phys.QuadPart = pte->PageFrameNumber << 12;
	pagingMapOutEntry(pte);

	relocationPtr = (ImageBaseRelocation *)MmMapIoSpace(phys,
		PAGE_SIZE,
		0);
	bkupRPtr = relocationPtr;
	/*DbgPrint("%p + %x = %x", realBase, sectionHeader[i].VirtualAddress, (((UINT32) realBase) +
	sectionHeader[i].VirtualAddress));*/
	i = 0;
	do
	{
		//DbgPrint("RP: %x %x\r\n", relocationPtr->VirtualAddress, relocationPtr->SizeOfBlock); 
		numRelocs += (relocationPtr->SizeOfBlock - sizeof(*relocationPtr)) / sizeof(UINT16);
		relocationPtr = (ImageBaseRelocation *)((UINT8 *)relocationPtr + relocationPtr->SizeOfBlock);
		i++;
	} while (relocationPtr->SizeOfBlock != 0);
	MmUnmapIoSpace(bkupRPtr, PAGE_SIZE);
	//KeUnstackDetachProcess(apc);
	//DbgPrint("I %d\r\n", i);

	// Size of the table (minus the header) divided by the size of each entry
	// FIXME Figure out why this is the case
	return numRelocs - (i);
}
UINT16 peGetNumExecSections(UINT8 *peBaseAddr)
{
	ImageDosHeader *dosHeader = NULL;
	ImageNtHeaders *ntHeaders = NULL;
	ImageSectionHeader *sectionHeader = NULL;

	UINT16 i, execSectionCount = 0, numSections = 0;

	dosHeader = (ImageDosHeader *)peBaseAddr;
	ntHeaders = (ImageNtHeaders *)((UINT8 *)peBaseAddr + dosHeader->e_lfanew);
	numSections = ntHeaders->FileHeader.NumberOfSections;

	sectionHeader = (ImageSectionHeader *)(&ntHeaders[1]);

	for (i = 0; i < numSections; i++)
	{
		if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(strcmp("INIT", sectionHeader[i].Name) == 0)) execSectionCount++;
	}

	return execSectionCount;
}
static UINT32 peCalculateRelocDiff(UINT8 *peBaseAddr, void *realBase)
{
	ImageDosHeader *dosHeader = NULL;
	ImageNtHeaders *ntHeaders = NULL;
	UINT16 *ptr = (UINT16 *)peBaseAddr;
	UINT32 imageBase = 0x01000000;

	dosHeader = (ImageDosHeader *)peBaseAddr;
	ntHeaders = (ImageNtHeaders *)((UINT8 *)peBaseAddr + dosHeader->e_lfanew);
	// Uncomment for a driver
	//imageBase = ntHeaders->OptionalHeader.ImageBase;

	if (((UINT32)realBase) > imageBase)
		return ((UINT32)realBase) - imageBase;
	return imageBase - ((UINT32)realBase);
}
void peGetExecSections(UINT8 *peBaseAddr, SectionData *sections)
{
	ImageDosHeader *dosHeader = NULL;
	ImageNtHeaders *ntHeaders = NULL;
	ImageSectionHeader *sectionHeader = NULL;

	UINT16 i, j = 0, execSectionCount = 0, numSections = 0;

	dosHeader = (ImageDosHeader *)peBaseAddr;
	ntHeaders = (ImageNtHeaders *)((UINT8 *)peBaseAddr + dosHeader->e_lfanew);
	numSections = ntHeaders->FileHeader.NumberOfSections;
	sectionHeader = (ImageSectionHeader *)&ntHeaders[1];

	for (i = 0; i < numSections; i++)
	{
		if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(strcmp("INIT", sectionHeader[i].Name) == 0))
		{
			sections[j].VirtualAddress = sectionHeader[i].VirtualAddress;
			sections[j].Size = sectionHeader[i].Misc.VirtualSize;
			//DbgPrint("Section %.8s is executable", sectionHeader[i].Name);
			j++;
		}
	}
}
UINT32 peChecksumBkupExecSections(UINT8 *peBaseAddr,
	void *realBase,
	PEPROCESS proc,
	PKAPC_STATE apc,
	PHYSICAL_ADDRESS *physArr)
{
	UINT16 numExecSections = peGetNumExecSections(peBaseAddr);
	UINT32 checksum = 0, k, i, j,
		numRelocs = peGetNumberOfRelocs(peBaseAddr, realBase, proc, apc),
		relocDelta = peCalculateRelocDiff(peBaseAddr, realBase);
	UINT8 *dataPtr = NULL;
	PHYSICAL_ADDRESS phys = { 0 };
	SectionData *execSections = (SectionData *)MmAllocateNonCachedMemory(
		numExecSections * sizeof(SectionData));
	peGetExecSections(peBaseAddr, execSections);

	//DbgPrint("Found %d relocations, delta of: %x\r\n", numRelocs, relocDelta);

	for (i = 0; i < numExecSections; i++)
	{
		UINT32 numpages = execSections[i].Size / 0x1000, size = execSections[i].Size;
		if (numpages * 0x1000 < execSections[i].Size)
			numpages++;
		for (k = 0; k < numpages; k++)
		{
			dataPtr = (UINT8 *)MmMapIoSpace(physArr[(execSections[i].VirtualAddress / PAGE_SIZE) + k],
				min(size, 0x1000), 0);
			for (j = 0; j < min(size, 0x1000); j++)
			{
				checksum += dataPtr[j];
			}
			MmUnmapIoSpace((void *)dataPtr, min(size, 0x1000));
			size -= 0x1000;
		}
	}

	// Subtract the relocations from the checksum
	// TODO Fix incase of lower load address
	checksum += numRelocs * (relocDelta & 0x000000FF);
	checksum += numRelocs * ((relocDelta & 0x0000FF00) >> 8);
	checksum += numRelocs * ((relocDelta & 0x00FF0000) >> 16);
	checksum += numRelocs * ((relocDelta & 0xFF000000) >> 24);


	MmFreeNonCachedMemory((void *)execSections, numExecSections * sizeof(SectionData));
	return checksum;
}

UINT32 peChecksumExecSections(UINT8 *peBaseAddr,
	void *realBase,
	PEPROCESS proc,
	PKAPC_STATE apc,
	PHYSICAL_ADDRESS *physArr)
{
	UINT16 numExecSections = peGetNumExecSections(peBaseAddr);
	UINT32 checksum = 0, k, i, j,
		numRelocs = peGetNumberOfRelocs(peBaseAddr, realBase, proc, apc),
		relocDelta = peCalculateRelocDiff(peBaseAddr, realBase);
	UINT8 *dataPtr = NULL;
	PHYSICAL_ADDRESS phys = { 0 };
	SectionData *execSections = (SectionData *)MmAllocateNonCachedMemory(
		numExecSections * sizeof(SectionData));
	peGetExecSections(peBaseAddr, execSections);

	//DbgPrint("Found %d relocations, delta of: %x\r\n", numRelocs, relocDelta);

	for (i = 0; i < numExecSections; i++)
	{
		UINT32 numpages = execSections[i].Size / 0x1000, size = execSections[i].Size;
		if (numpages * 0x1000 < execSections[i].Size)
			numpages++;
		for (k = 0; k < numpages; k++)
		{
			KeStackAttachProcess(proc, apc);
			dataPtr = (UINT8 *)MmMapIoSpace(MmGetPhysicalAddress((void *)(((UINT32)realBase) +
				execSections[i].VirtualAddress + (0x1000 * k))),
				0x1000, 0);
			phys = MmGetPhysicalAddress((void *)dataPtr);

			for (j = 0; j < min(size, 0x1000); j++)
			{
				checksum += dataPtr[j];
			}
			MmUnmapIoSpace((void *)dataPtr, 0x1000);
			size -= 0x1000;
			KeUnstackDetachProcess(apc);
		}
	}

	// Subtract the relocations from the checksum
	// TODO Fix incase of lower load address
	checksum += numRelocs * (relocDelta & 0x000000FF);
	checksum += numRelocs * ((relocDelta & 0x0000FF00) >> 8);
	checksum += numRelocs * ((relocDelta & 0x00FF0000) >> 16);
	checksum += numRelocs * ((relocDelta & 0xFF000000) >> 24);


	MmFreeNonCachedMemory((void *)execSections, numExecSections * sizeof(SectionData));
	return checksum;
}
void pagingInitMappingOperations(PagingContext *context, UINT32 numPages)
{
	UINT32 i;
	UINT64 cr3Val;
	const UINT32 tag = '4gaT';
	PHYSICAL_ADDRESS phys = { 0 };
	PageDirectoryEntrySmallPage *pde;
	cr3Val = _Cr3();
	context->CR3Val = cr3Val;
	phys.QuadPart = cr3Val & 0xFFFFF000;

	context->PageArray = (UINT8 *)ExAllocatePoolWithTag(NonPagedPool,
		numPages * PAGE_SIZE, tag);
	context->NumPages = numPages;
	context->PageArrayBitmap = (UINT8 *)ExAllocatePoolWithTag(NonPagedPool,
		numPages, tag);
	RtlZeroMemory(context->PageArrayBitmap, numPages);

}

PMDLX pagingLockProcessMemory(PVOID startAddr,
	UINT32 len,
	PEPROCESS proc,
	PKAPC_STATE apcstate)
{
	PMDLX mdl = NULL;

	// Attach to process to ensure virtual addresses are correct
	KeStackAttachProcess(proc, apcstate);

	// Create MDL to represent the image
	mdl = IoAllocateMdl(startAddr, (ULONG)len, FALSE, FALSE, NULL);
	if (mdl == NULL)
		return NULL;

	// Attempt to probe and lock the pages into memory
	_try
	{
		MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
	}_except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Unable to ProbeAndLockPages! Error: %x\r\n", GetExceptionCode());

		IoFreeMdl(mdl);
		mdl = NULL;
	}

	KeUnstackDetachProcess(apcstate);


	return mdl;
}
void pagingUnlockProcessMemory(PEPROCESS proc, PKAPC_STATE apcstate, PMDLX mdl)
{
	// Attach to process to ensure virtual addresses are correct
	KeStackAttachProcess(proc, apcstate);

	// Unlock & free MDL and corresponding pages
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	KeUnstackDetachProcess(apcstate);
}
void processCreationMonitor(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	PEPROCESS proc = NULL;
	void *PeHeaderVirt = NULL;
	UINT16 numExecSections = 0;
	UINT8 *pePtr = NULL;
	PHYSICAL_ADDRESS phys = { 0 };
	char *procName;
	UINT32 imageSize;
	UINT64 translations = (UINT64)translationArr;

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE periodMeasureThreadHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };

	// Set to anywhere inthe 4GB range
	highestMemoryAddress.QuadPart = ~0;

	// Get the 8.3 image name
	PsLookupProcessByProcessId(ProcessId, &proc);
	procName = PsGetProcessImageFileName(proc);

	// Check if this is the target process
	if (strncmp(TargetAppName, procName, strlen(TargetAppName)) == 0)
	{
		if (Create && VDEBUG) DbgPrint("New Process Created! %s\r\n", procName);
		if (!Create && VDEBUG) DbgPrint("Application quitting %s\r\n", procName);

		// Retrieve virtual pointer to the PE header for target application (in PE context)
		PeHeaderVirt = PsGetProcessSectionBaseAddress(proc);
		//DbgPrint("Virt: %x", PeHeaderVirt);

		// Begin critical section
		// Attach to the target process and grab its CR3 value to use later
		KeStackAttachProcess(proc, (PRKAPC_STATE)&apcstate);

		if (Create)
		{
			
			targetCR3 = _Cr3();
			
		}

		phys = MmGetPhysicalAddress(PeHeaderVirt);
		KeUnstackDetachProcess(&apcstate);
		// End critical section

		targetPePhys = phys;
		targetPeVirt = PeHeaderVirt;
		targetProc = proc;

		if (Create)
		{
			targetPePtr = peMapInImageHeader(phys);
			imageSize = peGetImageSize(targetPePtr);
			if (VDEBUG) DbgPrint("Image Size: %x bytes Num Entries %d\r\n", imageSize, sizeof(TlbTranslation)* (imageSize / PAGE_SIZE));
			DbgPrint("Virt %x - %x %x\r\n", PeHeaderVirt, (UINT32)PeHeaderVirt + imageSize, targetCR3);

			// Ensure Windows doesn't reuse the physical pages
			LockedMdl = pagingLockProcessMemory(PeHeaderVirt, imageSize, proc, &apcstate);
			if (LockedMdl == NULL && VDEBUG)
			{
				DbgPrint("Unable to lock memory\r\n");
			}
			appsize = imageSize;
			appCopy = (UINT8 *)MmAllocateContiguousMemory(imageSize, highestMemoryAddress);
			RtlZeroMemory((void *)appCopy, imageSize);
			copyPe(proc, &apcstate, (UINT8*)PeHeaderVirt, appCopy, imageSize);
			translationArr = allocateAndFillTranslationArray((UINT8*)PeHeaderVirt,
				appCopy,
				imageSize,
				proc,
				&apcstate);

			translations = (UINT64)translationArr;
			// VMCALL to start the TLB splitting
			/*__asm
			{
				PUSHAD
					MOV		EAX, VMCALL_INIT_SPLIT
					MOV     EBX, translations

					_emit 0x0F		// VMCALL
					_emit 0x01
					_emit 0xC1

					POPAD
			}*/
			_InitSplit(VMCALL_INIT_SPLIT, translations);

			/*if (VDEBUG) DbgPrint("Checksum of proc: %x\r\n",
				peChecksumExecSections(targetPePtr, PeHeaderVirt,
				proc, &apcstate, targetPhys));*/

			//pePrintSections(pePtr);

#ifdef PERIODIC_MEASURE
			/* Set up periodic measurement thread */
			KeInitializeEvent(&periodicMeasureThreadWakeUp, NotificationEvent, FALSE); //returns void
			InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL); //returns void

			periodicMeasureThreadExecute = 1; //allows thread to execute
			status = PsCreateSystemThread(&periodMeasureThreadHandle,
				THREAD_ALL_ACCESS, &objectAttributes, NULL, NULL,
				periodicMeasurePe, NULL);
			status = ObReferenceObjectByHandle(periodMeasureThreadHandle, 0, NULL,
				KernelMode, &periodicMeasureThread, NULL);
			ZwClose(periodMeasureThreadHandle); //don't need the handle anymore, ref will remain valid
#endif

		}
		else
		{
			translations = (UINT64)translationArr;
			// VMCALL to stop TLB splitting
			/*__asm
			{
				PUSHAD
					MOV		EAX, VMCALL_END_SPLIT
					MOV     EBX, translations

					_emit 0x0F		// VMCALL
					_emit 0x01
					_emit 0xC1

					POPAD
			}*/
			_InitSplit(VMCALL_END_SPLIT, translations);
			if (LockedMdl != NULL)
			{
				pagingUnlockProcessMemory(proc, &apcstate, LockedMdl);
			}

			if (appCopy != NULL)
			{
				MmFreeContiguousMemory((PVOID)appCopy);
			}

			if (translationArr != NULL)
			{
				freeTranslationArray(translationArr);
			}

			targetCR3 = 0;

#ifdef PERIODIC_MEASURE
			/* Stop the periodic measurement thread */
			periodicMeasureThreadExecute = 0; // Apply brakes
			KeSetEvent(&periodicMeasureThreadWakeUp, 0, TRUE); // Cancel any current wait in the thread
			/* Wait for thread to stop */
			KeWaitForSingleObject(periodicMeasureThread,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			ObDereferenceObject(periodicMeasureThread);
#endif
			peMapOutImageHeader(targetPePtr);
			targetPeVirt = NULL;
		}
		return;
	}
}

void periodicMeasurePe(PVOID context)
{
	LARGE_INTEGER measurementFrequency = { 0 }; // How long to delay

	measurementFrequency.QuadPart = -10000000; // 1 second / 100 nanoseconds
	while (periodicMeasureThreadExecute) {
		measurePe(targetPePhys, targetPeVirt);
		KeWaitForSingleObject(&periodicMeasureThreadWakeUp, Executive,
			KernelMode, TRUE, &measurementFrequency);
	}
}

void measurePe(PHYSICAL_ADDRESS phys, void * peHeaderVirt)
{
	UINT64 b, c;
	if (peHeaderVirt == NULL)
		return;
	b = phys.QuadPart;
	c = (UINT64)peHeaderVirt;
	// VMCALL to stop measure without the EPT TLB splitting
	/*__asm
	{
		PUSHAD
			MOV		EAX, VMCALL_MEASURE
			MOV     EBX, b
			MOV     ECX, c

			_emit 0x0F		// VMCALL
			_emit 0x01
			_emit 0xC1

			POPAD
	}*/
	_SetMeasure(VMCALL_MEASURE, b,c);

}

void copyPe(PEPROCESS proc, PKAPC_STATE apc, UINT8 *srcPtr, UINT8 *targetPtr, UINT32 len)
{
	if (srcPtr == NULL || targetPtr == NULL)
		return;

	// Attach to the process and copy the image to the passed buffer
	KeStackAttachProcess(proc, apc);

	memcpy(targetPtr, srcPtr, len);

	KeUnstackDetachProcess(apc);
}

TlbTranslation * allocateAndFillTranslationArray(UINT8 *codePtr,
	UINT8 *dataPtr,
	UINT32 len,
	PEPROCESS proc,
	PKAPC_STATE apc)
{
	const UINT32 tag = '3gaT';
	UINT32 i = 0, numPages = len / 0x1000;
	TlbTranslation *arr = (TlbTranslation *)ExAllocatePoolWithTag(NonPagedPool,
		(numPages + 1) * sizeof(TlbTranslation),
		tag);

	PHYSICAL_ADDRESS tmpPhys = { 0 };
	TlbTranslation nullTranslation = { 0 };

	targetPhys = (PHYSICAL_ADDRESS *)ExAllocatePoolWithTag(NonPagedPool,
		(numPages + 1) * sizeof(PHYSICAL_ADDRESS),
		tag);
	targetPtes = (PageTableEntry **)ExAllocatePoolWithTag(NonPagedPool,
		(numPages + 1) * sizeof(PageTableEntry *),
		tag);

	if (arr == NULL || targetPtes == NULL || targetPhys == NULL)
	{
		while (1) {};
	}

	RtlZeroMemory(arr, (numPages + 1) * sizeof(TlbTranslation));
	// Loop through the VA space of the PE image and get the physical addresses
	for (i = 0; i < numPages; i++)
	{
		KeStackAttachProcess(proc, apc);
		tmpPhys = MmGetPhysicalAddress((PVOID)((UINT64)codePtr + (i * PAGE_SIZE)));
		KeUnstackDetachProcess(apc);
		targetPtes[i] = pagingMapInPte(targetCR3, (UINT8 *)codePtr + (i * PAGE_SIZE));
		arr[i].CodePhys = tmpPhys.QuadPart;
		targetPhys[i] = tmpPhys;
		//arr[i].DataPhys = tmpPhys.LowPart;
		arr[i].CodeOrData = CODE_EPT;

		arr[i].VirtualAddress = ((UINT64)codePtr + (i * PAGE_SIZE));

		tmpPhys = MmGetPhysicalAddress((PVOID)((UINT64)dataPtr + (i * PAGE_SIZE)));
		arr[i].DataPhys = tmpPhys.QuadPart;
		//arr[i].CodePhys = tmpPhys.LowPart;
		//DbgPrint("Code %x Data %x\r\n", arr[i].CodePhys, arr[i].DataPhys);
	}

	arr[numPages] = nullTranslation; // Zero out the last element
	return arr;
}

void freeTranslationArray(TlbTranslation *arr)
{
	const UINT32 tag = '3gaT';
	UINT32 i = 0;

	for (i = 0; i < appsize / 0x1000; i++)
	{
		pagingMapOutEntry(targetPtes[i]);
	}
	ExFreePoolWithTag(arr, tag);
}

/*

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
}*/

// This function runs at DIRQL, and must NOT cause any page faults
// TODO Check for CodeOrData field
void AppendTlbTranslation(TlbTranslation * transArr, UINT64 phys, UINT8 * virt)
{
	UINT32 i = 0;
	EptPteEntry *pte;
	while (transArr[i].VirtualAddress != (UINT32)virt && transArr[i].DataPhys != 0)
	{
		i++;
	}
	if (transArr[i].VirtualAddress == (UINT32)virt)
	{
		pte = transArr[i].EptPte;
		pte->Present = 1;
		pte->Write = 1;
		pte->Execute = 1;
		pte->PhysAddr = (transArr[i].CodeOrData == CODE_EPT) ?
			transArr[i].CodePhys >> 12 :
			transArr[i].DataPhys >> 12;
		transArr[i].DataPhys = phys;
		transArr[i].CodeOrData = DATA_EPT;
		pte = EptMapAddressToPteDirql(phys, NULL, &memContext);
		if (pte != NULL)
		{
			pte->Present = 0;
			pte->Write = 0;
			pte->Execute = 0;
			transArr[i].EptPte = pte;
		}
		else
		{
			//Beep(1);
			while (1) {}
		}
	}

}

UINT8 *dataPage, *codePage;
TlbTranslation smallArr[2] = { 0 };
void splitPage()
{
	const UINT32 tag = '3gaT';
	PHYSICAL_ADDRESS phys = { 0 };
	TlbTranslation *tlbptr = smallArr;

	dataPage = (UINT8 *)ExAllocatePoolWithTag(NonPagedPool, 2 * PAGE_SIZE, tag);
	codePage = dataPage + PAGE_SIZE;

	dataPage[0] = 0xFF;
	codePage[0] = 0xC3;

	phys = MmGetPhysicalAddress((void *)dataPage);
	smallArr[0].DataPhys = phys.QuadPart;
	phys = MmGetPhysicalAddress((void *)codePage);
	smallArr[0].CodePhys = phys.QuadPart;

	/*__asm
	{
		PUSHAD
			MOV		EAX, VMCALL_INIT_SPLIT
			MOV     EBX, tlbptr

			_emit 0x0F		// VMCALL
			_emit 0x01
			_emit 0xC1

			POPAD
	}*/
	_InitSplit(VMCALL_INIT_SPLIT, (UINT32)tlbptr);

	//Log("Found", codePage[0]);
	codePage[0] = 0xFE;
	//Log("Found", codePage[0]);

	/*__asm
	{
		PUSH EAX
			MOV EAX, codePage
			CALL EAX
			POP EAX
	}*/

	/*__asm
	{
		PUSHAD
			MOV		EAX, VMCALL_END_SPLIT
			MOV     EBX, tlbptr

			_emit 0x0F		// VMCALL
			_emit 0x01
			_emit 0xC1

			POPAD
	}*/
	_InitSplit(VMCALL_END_SPLIT, (UINT32)tlbptr);
	ExFreePoolWithTag(dataPage, tag);
}

UINT32 checksumBuffer(UINT8 * ptr, UINT32 len)
{
	UINT32 i, sum = 0;
	for (i = 0; i < len; i++)
	{
		sum += ptr[i];
	}
	return sum;
}
