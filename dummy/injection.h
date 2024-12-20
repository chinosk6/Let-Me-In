#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#include <ntdef.h>
#include "types.hpp"

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

#define DbgPrint(fmt, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[TLG-Loader]"fmt, __VA_ARGS__);

InjectStat g_CurrentInjectStat = NOT_INJECTING;


typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    PVOID  Unknown1;       // Reserved
    PVOID  Unknown2;       // Reserved
    PVOID  Base;           // Module start address
    ULONG  Size;           // Module size
    ULONG  Flags;
    USHORT Index;
    USHORT Unknown3;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG   ModulesCount;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

// Windows �ں˵�����ZwQuerySystemInformation
NTSTATUS ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE UniqueProcessId;
    // ... ���������ֶΣ�����ĵ������ͷ�ļ�
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

void SleepSec(long long sec) {
    LARGE_INTEGER interval = { 0 };

    // ʱ�䵥λ�� 100 ���루1e-7 �룩��
    // ��� interval.QuadPart Ϊ��������ʾ���ʱ�䣻������ʾ����ʱ�䡣
    // 2 �� = 2 * 1,000,0000(1e7) �� 100 ���� = 20,000,000 (2 * 10^7)
    // ���Եȴ�2�룬QuadPart = -(2 * 10^7)
    interval.QuadPart = -(sec * 10000000LL);

    // KernelMode �� UserMode ���ɣ�ͨ���� KernelMode
    // �ڶ������� Alertable ��ʾ�Ƿ���Ա� APC �ȴ��
    KeDelayExecutionThread(
        KernelMode,
        FALSE,
        &interval
    );
}

BOOLEAN IsWindows11() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (NT_SUCCESS(status))
    {
        // Windows 11
        if (versionInfo.dwMajorVersion == 10 &&
            versionInfo.dwMinorVersion == 0 &&
            versionInfo.dwBuildNumber >= 22000)
        {
            return TRUE;
        }
    }
    return FALSE;
}

ULONG GetWindowsBuildNumber() {
    RTL_OSVERSIONINFOW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (NT_SUCCESS(status))
    {
        return versionInfo.dwBuildNumber;
    }
    return 0;
}


PVOID GetKernelBaseViaSystemModuleInfo(OUT PULONG pSize OPTIONAL)
{
    PVOID pBaseAddress = NULL;
    ULONG bytesNeeded = 0;
    NTSTATUS status = ZwQuerySystemInformation(
        11, // SystemModuleInformation = 11
        NULL,
        0,
        &bytesNeeded
    );
    DbgPrint("ZwQuerySystemInformation: 0x%x\n", status);
    // SleepSec(2);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return NULL;
    }

    PSYSTEM_MODULE_INFORMATION pModuleInfo =
        (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bytesNeeded, 'ludo');
    if (!pModuleInfo)
        return NULL;

    RtlZeroMemory(pModuleInfo, bytesNeeded);
    status = ZwQuerySystemInformation(11, pModuleInfo, bytesNeeded, &bytesNeeded);
    DbgPrint("ZwQuerySystemInformation2: 0x%x\n", status);
    // SleepSec(2);
    
    if (NT_SUCCESS(status)) {
        // �����Ѽ��ص�ģ�飬�ҵ� ntoskrnl.exe
        for (ULONG i = 0; i < pModuleInfo->ModulesCount; i++) {
            CHAR* imageName = pModuleInfo->Module[i].ImageName;
            // һ���ַ�������� "\SystemRoot\system32\ntoskrnl.exe" ������·��
            if (strstr(imageName, "ntoskrnl.exe") ||
                strstr(imageName, "ntkrnlmp.exe") || // SMP�ں�
                strstr(imageName, "ntkrnlpa.exe") || // PAE�ں�
                strstr(imageName, "ntkrpamp.exe"))    // SMP + PAE
            {
                pBaseAddress = pModuleInfo->Module[i].Base;
                if (pSize) {
                    *pSize = pModuleInfo->Module[i].Size;
                }
                break;
            }
        }
    }
    ExFreePool(pModuleInfo);

    return pBaseAddress;
}

// -----------------------------------------------------------------------------------
// ����δ��������
// -----------------------------------------------------------------------------------

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* LPFN_NTCREATETHREADEX)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartAddress,
    IN PVOID Parameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID ByteBuffer
    );

// -----------------------------------------------------------------------------------
// �ṹ������
// -----------------------------------------------------------------------------------

// SSDT��ṹ
typedef struct _SYSTEM_SERVICE_TABLE
{
    PVOID       ServiceTableBase;
    PVOID       ServiceCounterTableBase;
    ULONGLONG   NumberOfServices;
    PVOID       ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// PEB32/PEB64
typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    PVOID CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
{
    ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX
    SIZE_T Size;
    ULONG_PTR Value;
    ULONG Unknown;
} NT_PROC_THREAD_ATTRIBUTE_ENTRY, * NT_PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
{
    ULONG Length;
    NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, * PNT_PROC_THREAD_ATTRIBUTE_LIST;


// ע��ShellCode�ṹ
typedef struct _INJECT_BUFFER
{
    UCHAR Code[0x200];
    union
    {
        UNICODE_STRING Path64;
        UNICODE_STRING32 Path32;
    };
    wchar_t Buffer[488];
    PVOID ModuleHandle;
    ULONG Complete;
    NTSTATUS Status;
} INJECT_BUFFER, * PINJECT_BUFFER;

// -----------------------------------------------------------------------------------
// һЩ�����е�ͨ�ú�����װ�������⿽��ʹ��
// -----------------------------------------------------------------------------------

// ���뺯������ȡSSDT������RVA
// ����1�����뺯������
ULONG GetSSDTRVA(UCHAR* function_name)
{
    NTSTATUS Status;
    HANDLE FileHandle;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION FileInformation;

    // ����NTDLL·��
    UNICODE_STRING uniFileName;
    RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntoskrnl.exe");

    // ��ʼ�����ļ�������
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, &uniFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // ���ļ�
    Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes, &ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
    if (!NT_SUCCESS(Status))
    {
        return 0;
    }

    // ��ȡ�ļ���Ϣ
    Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(FileHandle);
        return 0;
    }

    // �ж��ļ���С�Ƿ����
    if (FileInformation.EndOfFile.HighPart != 0)
    {
        ZwClose(FileHandle);
        return 0;
    }
    // ȡ�ļ���С
    ULONG uFileSize = FileInformation.EndOfFile.LowPart;

    // �����ڴ�
    PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize + 0x100, (ULONG)"PGu");
    if (pBuffer == NULL)
    {
        ZwClose(FileHandle);
        return 0;
    }

    // ��ͷ��ʼ��ȡ�ļ�
    LARGE_INTEGER byteOffset;
    byteOffset.LowPart = 0;
    byteOffset.HighPart = 0;
    Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(FileHandle);
        return 0;
    }

    // ȡ��������
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER pSectionHeader;
    ULONGLONG FileOffset;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;

    // DLL�ڴ�����ת��DOSͷ�ṹ
    pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

    // ȡ��PEͷ�ṹ
    pNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)pBuffer + pDosHeader->e_lfanew);

    // �ж�PEͷ��������Ƿ�Ϊ��
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        return 0;
    }

    // ȡ��������ƫ��
    FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // ȡ����ͷ�ṹ
    pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;

    // �����ڽṹ���е�ַ����
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
    }

    // �������ַ
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pBuffer + FileOffset);

    // ȡ������������ַ
    PULONG AddressOfFunctions;
    FileOffset = pExportDirectory->AddressOfFunctions;

    // �����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
    }
    AddressOfFunctions = (PULONG)((ULONGLONG)pBuffer + FileOffset);

    // ȡ��������������
    PUSHORT AddressOfNameOrdinals;
    FileOffset = pExportDirectory->AddressOfNameOrdinals;

    // �����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
    }
    AddressOfNameOrdinals = (PUSHORT)((ULONGLONG)pBuffer + FileOffset);

    //ȡ�������������
    PULONG AddressOfNames;
    FileOffset = pExportDirectory->AddressOfNames;

    //�����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;

    // ѭ�����н�
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        // Ѱ�ҷ��������Ľ�
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            // �õ��ļ�ƫ��
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
    }
    AddressOfNames = (PULONG)((ULONGLONG)pBuffer + FileOffset);

    //DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", (ULONGLONG)AddressOfFunctions- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNameOrdinals- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNames- (ULONGLONG)pBuffer);
    //DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", pExportDirectory->AddressOfFunctions, pExportDirectory->AddressOfNameOrdinals, pExportDirectory->AddressOfNames);

    // ��ʼ����������
    ULONG uOffset;
    LPSTR FunName;
    ULONG uAddressOfNames;
    ULONG TargetOff = 0;

    // ѭ��������
    for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
    {
        uAddressOfNames = *AddressOfNames;
        pSectionHeader = pOldSectionHeader;
        for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
        {
            // ������ַ��ĳ����Χ��
            if (pSectionHeader->VirtualAddress <= uAddressOfNames && uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
            {
                uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
            }
        }

        // �õ�������
        FunName = (LPSTR)((ULONGLONG)pBuffer + uOffset);

        // �ж��Ƿ����Ҫ��
        if (!_stricmp((const char*)function_name, FunName))
        {
            // ���غ�����ַ
            TargetOff = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
            DbgPrint("���� [ %p ] ������ [ %s ] ���RVA [ %p ] \n", *AddressOfNameOrdinals, FunName, TargetOff);
        }

    }

    ExFreePoolWithTag(pBuffer, (ULONG)"PGu");
    ZwClose(FileHandle);
    return TargetOff;
}

// ���뺯���� ��ȡ�ú�������ģ���±�
ULONG GetIndexByName(UCHAR* function_name)
{
    NTSTATUS Status;
    HANDLE FileHandle;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION FileInformation;

    // ����NTDLL·��
    UNICODE_STRING uniFileName;
    RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntdll.dll");

    // ��ʼ�����ļ�������
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, &uniFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // ���ļ�
    Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes, &ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
    if (!NT_SUCCESS(Status))
    {
        return 0;
    }

    // ��ȡ�ļ���Ϣ
    Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(FileHandle);
        return 0;
    }

    // �ж��ļ���С�Ƿ����
    if (FileInformation.EndOfFile.HighPart != 0)
    {
        ZwClose(FileHandle);
        return 0;
    }

    // ȡ�ļ���С
    ULONG uFileSize = FileInformation.EndOfFile.LowPart;

    // �����ڴ�
    PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize + 0x100, (ULONG)"Ntdl");
    if (pBuffer == NULL)
    {
        ZwClose(FileHandle);
        return 0;
    }

    // ��ͷ��ʼ��ȡ�ļ�
    LARGE_INTEGER byteOffset;
    byteOffset.LowPart = 0;
    byteOffset.HighPart = 0;
    Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(FileHandle);
        return 0;
    }

    // ȡ��������
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER pSectionHeader;
    ULONGLONG FileOffset;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;

    // DLL�ڴ�����ת��DOSͷ�ṹ
    pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

    // ȡ��PEͷ�ṹ
    pNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)pBuffer + pDosHeader->e_lfanew);

    // �ж�PEͷ��������Ƿ�Ϊ��
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        return 0;
    }

    // ȡ��������ƫ��
    FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // ȡ����ͷ�ṹ
    pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;

    // �����ڽṹ���е�ַ����
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
    }

    // �������ַ
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pBuffer + FileOffset);

    // ȡ������������ַ
    PULONG AddressOfFunctions;
    FileOffset = pExportDirectory->AddressOfFunctions;

    // �����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
    }

    // �˴���Ҫע��foa��rvaת������
    AddressOfFunctions = (PULONG)((ULONGLONG)pBuffer + FileOffset);

    // ȡ��������������
    PUSHORT AddressOfNameOrdinals;
    FileOffset = pExportDirectory->AddressOfNameOrdinals;

    // �����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
    }

    // �˴���Ҫע��foa��rvaת������
    AddressOfNameOrdinals = (PUSHORT)((ULONGLONG)pBuffer + FileOffset);

    // ȡ�������������
    PULONG AddressOfNames;
    FileOffset = pExportDirectory->AddressOfNames;

    // �����ڽṹ���е�ַ����
    pSectionHeader = pOldSectionHeader;
    for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
    {
        if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
        {
            FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
    }

    // �˴���Ҫע��foa��rvaת������
    AddressOfNames = (PULONG)((ULONGLONG)pBuffer + FileOffset);

    // ����������
    ULONG uNameOffset;
    ULONG uOffset;
    LPSTR FunName;
    PVOID pFuncAddr;
    ULONG uServerIndex;
    ULONG uAddressOfNames;

    for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
    {
        uAddressOfNames = *AddressOfNames;
        pSectionHeader = pOldSectionHeader;
        for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
        {
            if (pSectionHeader->VirtualAddress <= uAddressOfNames && uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
            {
                uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
            }
        }

        FunName = (LPSTR)((ULONGLONG)pBuffer + uOffset);

        // �жϿ�ͷ�Ƿ���Zw
        if (FunName[0] == 'Z' && FunName[1] == 'w')
        {
            pSectionHeader = pOldSectionHeader;

            // ����������AddressOfNameOrdinals�õ��ļ�ƫ��
            uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];

            for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
            {
                if (pSectionHeader->VirtualAddress <= uOffset && uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
                {
                    uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
                }
            }

            pFuncAddr = (PVOID)((ULONGLONG)pBuffer + uNameOffset);
            uServerIndex = *(PULONG)((ULONGLONG)pFuncAddr + 4);
            FunName[0] = 'N';
            FunName[1] = 't';

            // ���ָ���ı��
            if (!_stricmp(FunName, (const char*)function_name))
            {
                ExFreePoolWithTag(pBuffer, (ULONG)"Ntdl");
                ZwClose(FileHandle);
                return uServerIndex;
            }
        }
    }

    ExFreePoolWithTag(pBuffer, (ULONG)"Ntdl");
    ZwClose(FileHandle);
    return 0;
}

// ��ȡģ�鵼������
PVOID GetModuleExportAddress(IN PVOID ModuleBase, IN PCCHAR FunctionName, IN PEPROCESS EProcess)
{
    PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS32 ImageNtHeaders32 = NULL;
    PIMAGE_NT_HEADERS64 ImageNtHeaders64 = NULL;
    PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = NULL;
    ULONG ExportDirectorySize = 0;
    ULONG_PTR FunctionAddress = 0;

    if (ModuleBase == NULL)
    {
        return NULL;
    }

    if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    ImageNtHeaders32 = (PIMAGE_NT_HEADERS32)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);
    ImageNtHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);

    // �ж�PE�ṹλ��
    if (ImageNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
        ExportDirectorySize = ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else
    {
        ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)ModuleBase);
        ExportDirectorySize = ImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    // �����ڴ浼����
    PUSHORT pAddressOfOrds = (PUSHORT)(ImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)ModuleBase);
    PULONG  pAddressOfNames = (PULONG)(ImageExportDirectory->AddressOfNames + (ULONG_PTR)ModuleBase);
    PULONG  pAddressOfFuncs = (PULONG)(ImageExportDirectory->AddressOfFunctions + (ULONG_PTR)ModuleBase);

    for (ULONG i = 0; i < ImageExportDirectory->NumberOfFunctions; ++i)
    {
        USHORT OrdIndex = 0xFFFF;
        PCHAR  pName = NULL;

        // ���������С�ڵ���0xFFFF ��˵������ŵ���
        if ((ULONG_PTR)FunctionName <= 0xFFFF)
        {
            OrdIndex = (USHORT)i;
        }

        // ������˵�������ֵ���
        else if ((ULONG_PTR)FunctionName > 0xFFFF && i < ImageExportDirectory->NumberOfNames)
        {
            pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)ModuleBase);
            OrdIndex = pAddressOfOrds[i];
        }

        // δ֪��������
        else
        {
            return NULL;
        }

        // �Ա�ģ�����Ƿ�����������Ҫ��
        if (((ULONG_PTR)FunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)FunctionName) == OrdIndex + ImageExportDirectory->Base) || ((ULONG_PTR)FunctionName > 0xFFFF && strcmp(pName, FunctionName) == 0))
        {
            // ���򱣴�����
            FunctionAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)ModuleBase;
            break;
        }
    }
    return (PVOID)FunctionAddress;
}

// ��ȡָ���û�ģ���ַ
PVOID GetUserModuleAddress(IN PEPROCESS EProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN IsWow64)
{
    if (EProcess == NULL)
    {
        return NULL;
    }

    __try
    {
        // ��ʱ250ms����
        LARGE_INTEGER Time = { 0 };
        Time.QuadPart = -250ll * 10 * 1000;

        // 32λִ��
        if (IsWow64)
        {
            // �õ�����PEB���̻�����
            PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(EProcess);
            if (Peb32 == NULL)
            {
                return NULL;
            }

            // �ȴ� 250ms * 10
            for (INT i = 0; !Peb32->Ldr && i < 10; i++)
            {
                // �ȴ�һ����ִ��
                KeDelayExecutionThread(KernelMode, TRUE, &Time);
            }

            // û���ҵ����ؿ�
            if (!Peb32->Ldr)
            {
                return NULL;
            }

            // ���� InLoadOrderModuleList
            for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink; ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList; ListEntry = (PLIST_ENTRY32)ListEntry->Flink)
            {
                UNICODE_STRING UnicodeString;
                PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry32 = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
                RtlUnicodeStringInit(&UnicodeString, (PWCH)LdrDataTableEntry32->BaseDllName.Buffer);

                // �ж�ģ�����Ƿ����Ҫ��
                if (RtlCompareUnicodeString(&UnicodeString, ModuleName, TRUE) == 0)
                {
                    // �����򷵻�ģ���ַ
                    return (PVOID)LdrDataTableEntry32->DllBase;
                }
            }
        }

        // 64λִ��
        else
        {
            // �õ�����PEB���̻�����
            PPEB Peb = PsGetProcessPeb(EProcess);
            if (!Peb)
            {
                return NULL;
            }

            // �ȴ�
            for (INT i = 0; !Peb->Ldr && i < 10; i++)
            {
                // ����ǰ�߳�����ָ������Ŀɾ����򲻿ɲ����ĵȴ�״̬
                KeDelayExecutionThread(KernelMode, TRUE, &Time);
            }
            if (!Peb->Ldr)
            {
                return NULL;
            }

            // ��������
            for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink; ListEntry != &Peb->Ldr->InLoadOrderModuleList; ListEntry = ListEntry->Flink)
            {
                PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                // �ж�ģ�����Ƿ����Ҫ��
                if (RtlCompareUnicodeString(&LdrDataTableEntry->BaseDllName, ModuleName, TRUE) == 0)
                {
                    // ����ģ���ַ
                    return LdrDataTableEntry->DllBase;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}

//�õ�ntos�Ļ�ַ
ULONGLONG GetOsBaseAddress(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING osName = { 0 };
    WCHAR wzData[0x100] = L"ntoskrnl.exe";

    RtlInitUnicodeString(&osName, wzData);

    LDR_DATA_TABLE_ENTRY* pDataTableEntry, * pTempDataTableEntry;

    // ˫ѭ��������
    PLIST_ENTRY pList;

    // ָ�����������DriverSection
    pDataTableEntry = (LDR_DATA_TABLE_ENTRY*)pDriverObject->DriverSection;

    // �ж��Ƿ�Ϊ��
    if (!pDataTableEntry)
    {
        return 0;
    }

    // �õ������ַ
    pList = pDataTableEntry->InLoadOrderLinks.Flink;

    // �ж��Ƿ����ͷ��
    while (pList != &pDataTableEntry->InLoadOrderLinks)
    {
        pTempDataTableEntry = (LDR_DATA_TABLE_ENTRY*)pList;

        // �����ntoskrnl.exe�򷵻ظ�ģ���ַ
        if (RtlEqualUnicodeString(&pTempDataTableEntry->BaseDllName, &osName, TRUE))
        {
            return (ULONGLONG)pTempDataTableEntry->DllBase;
        }
        pList = pList->Flink;
    }
    return 0;
}


typedef struct _TableGetInformation {
    char* KiSystemServiceStart_pattern;
    size_t patternSize;
    int addressScanSize;
    int codeScanSize;
} TableGetInformation, * PTableGetInformation;


TableGetInformation GetDescInfo() {
    TableGetInformation info = { 0 };
    const int winVer = GetWindowsBuildNumber();

    if (winVer < 22000) {  // Windows 10 ������
        DbgPrint("Win 10 And Lower");
        const char* pattern = "\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00";
        info.patternSize = 14;
        info.KiSystemServiceStart_pattern = ExAllocatePoolWithTag(NonPagedPool, info.patternSize + 1, 'patT');
        if (info.KiSystemServiceStart_pattern) {
            RtlCopyMemory(info.KiSystemServiceStart_pattern, pattern, info.patternSize);
            info.KiSystemServiceStart_pattern[info.patternSize] = '\0'; // ȷ���� NULL ��β
        }
        info.addressScanSize = 0x50000;
        info.codeScanSize = 50;
    }
    else if (winVer < 26100) {  // Windows 11 24H2 ����
        DbgPrint("Lower Than Win 11 24h2");
        const char* pattern = "\xC6\x45\xAB\x02\x65\x48\x8b\x1c\x25\x88\x01\x00\x00";
        info.patternSize = 14;
        info.KiSystemServiceStart_pattern = ExAllocatePoolWithTag(NonPagedPool, info.patternSize + 1, 'patT');
        if (info.KiSystemServiceStart_pattern) {
            RtlCopyMemory(info.KiSystemServiceStart_pattern, pattern, info.patternSize);
            info.KiSystemServiceStart_pattern[info.patternSize] = '\0';
        }
        info.addressScanSize = 0x60000;
        info.codeScanSize = 250;
    }
    else if (winVer >= 26100) {  // Windows 11 24H2 ������
        DbgPrint("Win 11 24h2 And Higher");
        const char* pattern = "\xC6\x45\xAB\x02\xC6\x45\xA8\x01\x65\x48\x8b\x1c\x25\x88\x01\x00\x00";
        info.patternSize = 18;
        info.KiSystemServiceStart_pattern = ExAllocatePoolWithTag(NonPagedPool, info.patternSize + 1, 'patT');
        if (info.KiSystemServiceStart_pattern) {
            RtlCopyMemory(info.KiSystemServiceStart_pattern, pattern, info.patternSize);
            info.KiSystemServiceStart_pattern[info.patternSize] = '\0';
        }
        info.addressScanSize = 0x1E0000;
        info.codeScanSize = 280;
    }

    return info;
}

void FreeTableGetInformation(PTableGetInformation info) {
    if (info && info->KiSystemServiceStart_pattern) {
        ExFreePoolWithTag(info->KiSystemServiceStart_pattern, 'patT');
        info->KiSystemServiceStart_pattern = NULL;
        info->patternSize = 0;
    }
}

// �õ�SSDT��Ļ���ַ
ULONGLONG GetKeServiceDescriptorTable64(/*PDRIVER_OBJECT DriverObject*/) {
    // BOOLEAN isWin11 = IsWindows11();
    // DbgPrint("IsWindows11: %s", isWin11 ? "true" : "false");

    /* Windows 10 ������
    nt!KiSystemServiceUser+0xdc:
    fffff806`42c79987 8bf8            mov     edi,eax
    fffff806`42c79989 c1ef07          shr     edi,7
    fffff806`42c7998c 83e720          and     edi,20h
    fffff806`42c7998f 25ff0f0000      and     eax,0FFFh

    nt!KiSystemServiceRepeat:
    fffff806`42c79994 4c8d15e59e3b00  lea     r10,[nt!KeServiceDescriptorTable (fffff806`43033880)]
    fffff806`42c7999b 4c8d1dde203a00  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff806`4301ba80)]
    fffff806`42c799a2 f7437880000000  test    dword ptr [rbx+78h],80h
    fffff806`42c799a9 7413            je      nt!KiSystemServiceRepeat+0x2a (fffff806`42c799be)
    */
    // char KiSystemServiceStart_pattern_win10[14] = "\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00";

    /* Windows 11 23h2������
    _stricmp 1403D3070
    KiSystemServiceUser 140429A94

    fffff803`14e24bc0 nt!KiSystemCall64 (KiSystemCall64)
    0: kd> uf nt!KiSystemCall64Shadow
    Flow analysis was incomplete, some code may be missing
    nt!KiSystemServiceUser:
    fffff803`14e24e1a c645ab02        mov     byte ptr [rbp-55h],2
    fffff803`14e24e1e 65488b1c2588010000 mov   rbx,qword ptr gs:[188h]
    fffff803`14e24e27 0f0d8b90000000  prefetchw [rbx+90h]
    fffff803`14e24e2e 0fae5dac        stmxcsr dword ptr [rbp-54h]
    ......
    nt!KiSystemServiceRepeat:
    fffff803`14e24ef4 4c8d15c5c99d00  lea     r10,[nt!KeServiceDescriptorTable (fffff803`158018c0)]
    fffff803`14e24efb 4c8d1dfe208e00  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff803`15707000)]
    fffff803`14e24f02 f7437880000000  test    dword ptr [rbx+78h],80h
    */
    /* Windows 11 24h2
    _stricmp at 00000001404BAC80
    KiSystemServiceUser at 000000014068D0E2
    KiSystemServiceRepeat at 000000014068D1D4
    */
    

    // char KiSystemServiceStart_pattern_win11[14] = "\xC6\x45\xAB\x02\x65\x48\x8b\x1c\x25\x88\x01\x00\x00";

    // char KiSystemServiceStart_pattern[14];

    TableGetInformation descInfo = GetDescInfo();

    /*
    ULONG rva = GetRvaFromModule(L"\\SystemRoot\\system32\\ntoskrnl.exe", "_stricmp");
    DbgPrint("NtReadFile VA = %p \n", rva);
    ULONG _stricmp_offset = 0x19d710;
    */

    // ������ DriverObject������ֱ�ӻ�ȡ ntoskrnl.exe ��ַ
    ULONGLONG ntBase = (ULONGLONG)GetKernelBaseViaSystemModuleInfo(NULL);
    DbgPrint("ntBase: %llu\n", ntBase);
    // SleepSec(2);

    if (ntBase == 0) {
        DbgPrint("[-] Failed to get ntoskrnl base address\n");
        FreeTableGetInformation(&descInfo);
        return 0;
    }

    ULONGLONG CodeScanStart = GetSSDTRVA((UCHAR*)"_stricmp") + ntBase;
    DbgPrint("CodeScanStart: %llu\n", CodeScanStart);
    // SleepSec(2);

    ULONGLONG i, tbl_address, b;
    // for (i = 0; i < 0x60000; i++)
    for (i = 0; i < descInfo.addressScanSize; i++)
    {
        // �Ƚ�����
        if (!memcmp((char*)(ULONGLONG)CodeScanStart + i, descInfo.KiSystemServiceStart_pattern, descInfo.patternSize - 1))
        {
            DbgPrint("�ҵ�����\n");
            for (b = 0; b < descInfo.codeScanSize; b++)
            {
                tbl_address = ((ULONGLONG)CodeScanStart + i + b);

                // 4c 8d 15 e5 9e 3b 00  lea r10,[nt!KeServiceDescriptorTable (fffff802`64da4880)]
                // if (*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x158d4c)
                if (*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x8d4c)
                {
                    FreeTableGetInformation(&descInfo);
                    return ((LONGLONG)tbl_address + 7) + *(LONG*)(tbl_address + 3);
                }
            }
        }
    }
    FreeTableGetInformation(&descInfo);
    return 0;
}

// ����SSDT��ŵõ�������ַ
ULONGLONG GetSSDTFuncCurAddr(ULONG index)
{
    /*
    mov rax, rcx                   ; rcx=Native API �� index
    lea r10,[rdx]                  ; rdx=ssdt ��ַ
    mov edi,eax                    ; index
    shr edi,7
    and edi,20h
    mov r10, qword ptr [r10+rdi]   ; ServiceTableBase
    movsxd r11,dword ptr [r10+rax] ; û�����Ƶļ�ssdt�ĵ�ַ
    mov rax,r11
    sar r11,4
    add r10,r11
    mov rax,r10
    ret
    */
    LONG dwtmp = 0;
    PULONG ServiceTableBase = NULL;
    ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
    dwtmp = ServiceTableBase[index];

    // ������4λ֮����ϻ���ַ �Ϳ��Եõ�ssdt�ĵ�ַ
    dwtmp = dwtmp >> 4;

    return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}

// ���ݽ���ID���ؽ���EPROCESS
PEPROCESS LookupProcess(HANDLE Pid)
{
    PEPROCESS eprocess = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
    {
        return eprocess;
    }
    else
    {
        return NULL;
    }
}

// �����û�����������õ��ý���PID
HANDLE GetProcessID(PCHAR ProcessName)
{
    ULONG i = 0;
    PEPROCESS eproc = NULL;
    for (i = 4; i < 100000000; i = i + 4)
    {
        eproc = LookupProcess((HANDLE)i);
        if (eproc != NULL)
        {
            ObDereferenceObject(eproc);

            // ���ݽ������õ�����EPEPROCESS
            if (strstr(PsGetProcessImageFileName(eproc), ProcessName) != NULL)
            {
                return PsGetProcessId(eproc);
            }
        }
    }
    return NULL;
}


NTSTATUS GetProcessIdByNameUsingZwQuery(_In_ PCWSTR targetName, _Out_ PHANDLE pPid)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000; // ��ʼ�����С������ϵͳ��ģ������Ҫ����
    ULONG returnLength = 0;

    *pPid = NULL;

    // ���ϳ��Է����㹻�Ļ�����
    while (TRUE)
    {
        buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'psIQ');
        if (!buffer)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(buffer, bufferSize);

        status = ZwQuerySystemInformation(5, buffer, bufferSize, &returnLength);  // SystemProcessInformation - 5
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            // ���������������������
            ExFreePool(buffer);
            buffer = NULL;
            bufferSize *= 2;
            continue;
        }
        break;
    }

    if (!NT_SUCCESS(status))
    {
        if (buffer) ExFreePool(buffer);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    for (;;)
    {
        // ��������
        if (spi->ImageName.Buffer)
        {
            // ImageName �Ǹ� UNICODE_STRING
            if (_wcsicmp(spi->ImageName.Buffer, targetName) == 0)
            {
                *pPid = spi->UniqueProcessId;
                break;
            }
        }
        // �ƶ�����һ��������Ϣ
        if (spi->NextEntryOffset == 0)
        {
            break; // ��ĩβ��
        }
        spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    ExFreePool(buffer);
    return STATUS_SUCCESS;
}


HANDLE GetProcessIDByName(_In_ PCWSTR TargetName) {
    HANDLE pid = NULL;
    NTSTATUS stat = GetProcessIdByNameUsingZwQuery(TargetName, &pid);
    if (NT_SUCCESS(stat))
    {
        return pid;
    }
    return NULL;
}

HANDLE WaitingGetProcessIDByName(_In_ PCWSTR TargetName, int maxRetryTime) {
    HANDLE pid = NULL;
    int retryTime = 0;

    do {
        if (g_CurrentInjectStat == INJ_CANCEL_WAITING) {
            g_CurrentInjectStat = NOT_INJECTING;
            DbgPrint("ȡ���ȴ�����\n");
            return 0;
        }

        pid = GetProcessIDByName(TargetName);
        retryTime++;
        DbgPrint("WaitingGetProcess: %ls, retryTime: %d, pid: %d\n", TargetName, retryTime, pid);
        if (pid || (retryTime >= maxRetryTime)) {
            return pid;
        }
        SleepSec(1);
    } while (pid == NULL);

    return pid;
}
