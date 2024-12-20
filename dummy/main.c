#include "injection.h"
#include "environment.hpp"
#include "ioctl.hpp"
#include "types.hpp"

#define RETURN_ENTRY(NTSTATUS, desc) if (NT_SUCCESS(NTSTATUS)) {         \
    /*DriverSetOperationResult(0x0, desc);                                 \
    DriverEventsCleanup();*/                                               \
    return NTSTATUS;                                                     \
}                                                                        \
else {                                                                   \
    /*DriverSetOperationResult(0x1, #NTSTATUS" - "##desc);                 \
    DriverEventsCleanup();*/                                               \
    return NTSTATUS;                                                     \
}

WCHAR tlgInstallPath[1024];

// 创建64位注入代码
PINJECT_BUFFER GetNative64Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllFullPath)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PINJECT_BUFFER InjectBuffer = NULL;
    SIZE_T Size = PAGE_SIZE;

    UCHAR Code[] = {
        0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
        0x48, 0x31, 0xC9,                       // xor rcx, rcx
        0x48, 0x31, 0xD2,                       // xor rdx, rdx
        0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
        0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +28
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
        0xFF, 0xD0,                             // call rax
        0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44
        0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
        0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +60
        0x89, 0x02,                             // mov [rdx], eax
        0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
        0xC3                                    // ret
    };

    Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &InjectBuffer, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(Status))
    {
        PUNICODE_STRING UserPath = &InjectBuffer->Path64;
        UserPath->Length = 0;
        UserPath->MaximumLength = sizeof(InjectBuffer->Buffer);
        UserPath->Buffer = InjectBuffer->Buffer;

        RtlUnicodeStringCopy(UserPath, DllFullPath);

        // Copy code
        memcpy(InjectBuffer, Code, sizeof(Code));

        // Fill stubs
        *(ULONGLONG*)((PUCHAR)InjectBuffer + 12) = (ULONGLONG)UserPath;
        *(ULONGLONG*)((PUCHAR)InjectBuffer + 22) = (ULONGLONG)&InjectBuffer->ModuleHandle;
        *(ULONGLONG*)((PUCHAR)InjectBuffer + 32) = (ULONGLONG)LdrLoadDll;
        *(ULONGLONG*)((PUCHAR)InjectBuffer + 44) = (ULONGLONG)&InjectBuffer->Complete;
        *(ULONGLONG*)((PUCHAR)InjectBuffer + 60) = (ULONGLONG)&InjectBuffer->Status;

        return InjectBuffer;
    }

    UNREFERENCED_PARAMETER(DllFullPath);
    return NULL;
}

// 创建32位注入代码
PINJECT_BUFFER GetNative32Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllFullPath)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PINJECT_BUFFER InjectBuffer = NULL;
    SIZE_T Size = PAGE_SIZE;

    // Code
    UCHAR Code[] = {
        0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
        0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +6
        0x6A, 0,                                // push Flags  
        0x6A, 0,                                // push PathToFile
        0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
        0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
        0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE     
        0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +31
        0x89, 0x02,                             // mov [edx], eax
        0xC2, 0x04, 0x00                        // ret 4
    };

    Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &InjectBuffer, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(Status))
    {
        // Copy path
        PUNICODE_STRING32 pUserPath = &InjectBuffer->Path32;
        pUserPath->Length = DllFullPath->Length;
        pUserPath->MaximumLength = DllFullPath->MaximumLength;
        pUserPath->Buffer = (ULONG)(ULONG_PTR)InjectBuffer->Buffer;

        // Copy path
        memcpy((PVOID)pUserPath->Buffer, DllFullPath->Buffer, DllFullPath->Length);

        // Copy code
        memcpy(InjectBuffer, Code, sizeof(Code));

        // Fill stubs
        *(ULONG*)((PUCHAR)InjectBuffer + 1) = (ULONG)(ULONG_PTR)&InjectBuffer->ModuleHandle;
        *(ULONG*)((PUCHAR)InjectBuffer + 6) = (ULONG)(ULONG_PTR)pUserPath;
        *(ULONG*)((PUCHAR)InjectBuffer + 15) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)InjectBuffer + 15) - 5 + 1);
        *(ULONG*)((PUCHAR)InjectBuffer + 20) = (ULONG)(ULONG_PTR)&InjectBuffer->Complete;
        *(ULONG*)((PUCHAR)InjectBuffer + 31) = (ULONG)(ULONG_PTR)&InjectBuffer->Status;

        return InjectBuffer;
    }

    UNREFERENCED_PARAMETER(DllFullPath);
    return NULL;
}

// -----------------------------------------------------------------------------------
// 启动子线程函数(注入函数)
// -----------------------------------------------------------------------------------

// 启动线程
NTSTATUS NTAPI SeCreateThreadEx(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID StartAddress, IN PVOID Parameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList)
{
    NTSTATUS Status = STATUS_SUCCESS;

    // 根据字符串NtCreateThreadEx得到下标,并通过下标查询SSDT函数地址
    LPFN_NTCREATETHREADEX NtCreateThreadEx = (LPFN_NTCREATETHREADEX)(GetSSDTFuncCurAddr(GetIndexByName((UCHAR*)"NtCreateThreadEx")));
    DbgPrint("From: %p --> %p \n", NtCreateThreadEx, StartAddress);

    if (NtCreateThreadEx)
    {
        // 如果之前的模式是用户模式，地址传递到ZwCreateThreadEx必须在用户模式空间
        // 切换到内核模式允许使用内核模式地址
        /*
        dt !_KTHREAD
        +0x1c8 Win32Thread      : Ptr64 Void
        + 0x140 WaitBlockFill11 : [176] UChar
        + 0x1f0 Ucb : Ptr64 _UMS_CONTROL_BLOCK
        + 0x232 PreviousMode : Char
        */

        // Windows10 PreviousMode = 0x232
        PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + 0x232;

        // 64位 pPrevMode = 01
        UCHAR prevMode = *pPrevMode;

        // 内核模式
        *pPrevMode = KernelMode;

        // 创建线程
        Status = NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartAddress, Parameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, AttributeList);

        // 恢复之前的线程模式
        *pPrevMode = prevMode;
    }
    else
    {
        Status = STATUS_NOT_FOUND;
    }
    return Status;
}

// 执行线程
NTSTATUS ExecuteInNewThread(IN PVOID BaseAddress, IN PVOID Parameter, IN ULONG Flags, IN BOOLEAN Wait, OUT PNTSTATUS ExitStatus)
{
    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    // 初始化对象属性
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    // 创建线程
    NTSTATUS Status = SeCreateThreadEx(&ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION, &ObjectAttributes, ZwCurrentProcess(), BaseAddress, Parameter, Flags, 0, 0x1000, 0x100000, NULL);
    // 等待线程完成
    if (NT_SUCCESS(Status)) {
        DbgPrint("SeCTEx Success.\n");

        if (Wait) {
            // 延迟 60s
            LARGE_INTEGER Timeout = { 0 };
            Timeout.QuadPart = -(60ll * 10 * 1000 * 1000);

            Status = ZwWaitForSingleObject(ThreadHandle, TRUE, &Timeout);
            if (NT_SUCCESS(Status))
            {
                // 查询线程退出码
                THREAD_BASIC_INFORMATION ThreadBasicInfo = { 0 };
                ULONG ReturnLength = 0;

                Status = ZwQueryInformationThread(ThreadHandle, ThreadBasicInformation, &ThreadBasicInfo, sizeof(ThreadBasicInfo), &ReturnLength);

                if (NT_SUCCESS(Status) && ExitStatus)
                {
                    // 这里是查询当前的dll是否注入成功
                    *ExitStatus = ThreadBasicInfo.ExitStatus;
                }
                else if (!NT_SUCCESS(Status))
                {
                    DbgPrint("%s: ZwQueryInformationThread failed with status 0x%X\n", __FUNCTION__, Status);
                }
            }
            else {
                DbgPrint("%s: ZwWaitForSingleObject failed with status 0x%X\n", __FUNCTION__, Status);
            }
        }
    }
    else {
        DbgPrint("%s: ZwCTEx failed with status 0x%X\n", __FUNCTION__, Status);
    }

    if (ThreadHandle)
    {
        ZwClose(ThreadHandle);
    }
    return Status;
}

// 切换到目标进程创建内核线程进行注入 (cr3切换)
NTSTATUS AttachAndInjectProcess(IN HANDLE ProcessID, PWCHAR DllPath)
{
    PEPROCESS EProcess = NULL;
    KAPC_STATE ApcState;
    NTSTATUS Status = STATUS_SUCCESS;

    if (ProcessID == NULL)
    {
        Status = STATUS_UNSUCCESSFUL;
        return Status;
    }

    __try
    {
        // 获取EProcess
        Status = PsLookupProcessByProcessId(ProcessID, &EProcess);
        DbgPrint("PsLookupProcessByProcessId: 0x%x\n", Status);
        // SleepSec(2);

        if (Status != STATUS_SUCCESS)
        {
            return Status;
        }

        // 判断目标进程x86 or x64
        BOOLEAN IsWow64 = (PsGetProcessWow64Process(EProcess) != NULL) ? TRUE : FALSE;
        DbgPrint("IsWow64: %d\n", IsWow64);
        // SleepSec(2);

        // 将当前线程连接到目标进程的地址空间
        KeStackAttachProcess((PRKPROCESS)EProcess, &ApcState);

        PVOID NtdllAddress = NULL;
        PVOID LdrLoadDll = NULL;
        UNICODE_STRING NtdllUnicodeString = { 0 };
        UNICODE_STRING DllFullPath = { 0 };

        // 获取ntdll模块基地址
        RtlInitUnicodeString(&NtdllUnicodeString, L"Ntdll.dll");
        NtdllAddress = GetUserModuleAddress(EProcess, &NtdllUnicodeString, IsWow64);
        DbgPrint("NtdllAddress: %p\n", NtdllAddress);
        // SleepSec(2);

        if (!NtdllAddress)
        {
            Status = STATUS_NOT_FOUND;
        }

        // 获取LdrLoadDll
        if (NT_SUCCESS(Status))
        {
            LdrLoadDll = GetModuleExportAddress(NtdllAddress, "LdrLoadDll", EProcess);
            DbgPrint("LdrLoadDll: %p\n", LdrLoadDll);
            // SleepSec(2);

            if (!LdrLoadDll)
            {
                Status = STATUS_NOT_FOUND;
            }
        }

        PINJECT_BUFFER InjectBuffer = NULL;
        if (IsWow64)
        {
            // 注入32位DLL
            RtlInitUnicodeString(&DllFullPath, DllPath);
            InjectBuffer = GetNative32Code(LdrLoadDll, &DllFullPath);
            DbgPrint("[*] 注入32位DLL \n");
        }
        else
        {
            // 注入64位DLL
            RtlInitUnicodeString(&DllFullPath, DllPath);
            InjectBuffer = GetNative64Code(LdrLoadDll, &DllFullPath);
            DbgPrint("[*] 注入64位DLL \n");
        }
        // SleepSec(2);

        //创建线程,执行构造的 shellcode
        ExecuteInNewThread(InjectBuffer, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, FALSE, &Status);
        if (!NT_SUCCESS(Status))
        {
            DbgPrint("ExecuteInNewThread Failed: 0x%x\n", Status);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_UNSUCCESSFUL;
    }
    // 释放EProcess
    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(EProcess);
    return Status;
}

#define TARGET_PROCESS_NAME L"umamusume.exe"

VOID ProcessNotifyCallback(
    _Inout_   PEPROCESS Process,
    _In_      HANDLE ProcessId,
    _In_opt_  PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo) {
        // 进程创建
        DbgPrint("Process create: PID=%p, Image=%wZ\n", ProcessId, CreateInfo->ImageFileName);

        if (CreateInfo->ImageFileName->Buffer != NULL)
        {
            PCUNICODE_STRING imageFileName = &CreateInfo->ImageFileName;
            PWCHAR processName = wcsrchr(imageFileName->Buffer, L'\\');

            if (processName != NULL)
            {
                processName++;

                if (_wcsicmp(processName, TARGET_PROCESS_NAME) == 0)
                {
                    DbgPrint("%ls detected! PID: %p\n", TARGET_PROCESS_NAME, ProcessId);
                    
                    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
                    if (NT_SUCCESS(status)) {
                        DbgPrint("ProcessNotifyCallback unregistered successfully\n");
                    }
                    else {
                        DbgPrint("Failed to unregister ProcessNotifyCallback\n");
                    }

                    // TODO AttachAndInjectProcess
                }
            }
        }
    }
    else {
        // 进程退出
        DbgPrint("Process exit: PID=%p\n", ProcessId);
    }
}


NTSTATUS DoInjection() {
    if (g_CurrentInjectStat != NOT_INJECTING) {
        return STATUS_DUPLICATE_PRIVILEGES;
    }
    else if (g_CurrentInjectStat == INJ_CANCEL_WAITING) {
        g_CurrentInjectStat = NOT_INJECTING;
        return STATUS_CANCELLED;
    }
    g_CurrentInjectStat = INJECTING;

    ULONG length = 0;
    NTSTATUS status = ReadSystemEnvironmentVariable(L"TLG_DIRECTORY", tlgInstallPath, sizeof(tlgInstallPath), &length);
    if (NT_SUCCESS(status)) {
        DbgPrint("Environment Path: %ws\n", tlgInstallPath);
    }
    else {
        DbgPrint("Read TLG_DIRECTORY Failed: 0x%X\n", status);
        return STATUS_NOT_FOUND;
    }

    status = AppendToPath(tlgInstallPath, sizeof(tlgInstallPath), L"loader.dll");
    if (NT_SUCCESS(status)) {
        DbgPrint("Full path: %ws\n", tlgInstallPath);
    }
    else {
        DbgPrint("Failed to create full path: 0x%x\n", status);
        return status;
    }


    /*
    NTSTATUS eventsInitStat = DriverEventsInit();
    if (!NT_SUCCESS(eventsInitStat)) {
        DbgPrint("DriverEventsInit failed: 0x%x\n", eventsInitStat);
    }
    DbgPrint("DriverEventsInit: 0x%x\n", eventsInitStat);*/

    // SleepSec(2);

    // 获取SSDT表基址
    // KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable64(DriverObject);
    KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable64();
    DbgPrint("GetKeServiceDescriptorTable64 end\n");
    // SleepSec(2);
    if (KeServiceDescriptorTable == 0) {
        DbgPrint("GetKeServiceDescriptorTable64 failed\n");
        // return STATUS_FAIL_CHECK;
        RETURN_ENTRY(STATUS_FAIL_CHECK, "GetKeServiceDescriptorTable64");
    }

    // 得到进程PID
    // HANDLE processid = GetProcessID("umamusume.exe");
    HANDLE processid = GetProcessIDByName(TARGET_PROCESS_NAME);
    DbgPrint("进程PID = %d \n", processid);
    SleepSec(2);

    if (!processid) {
        DbgPrint("进程未找到，等待启动...\n");
        // DriverSetOperationResult(0X0, "Waiting for %ls", TARGET_PROCESS_NAME);

        /*
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Register ProcessNotifyCallback failed： 0x%x\n", status);
            // return STATUS_NOT_FOUND;

            processid = WaitingGetProcessIDByName(TARGET_PROCESS_NAME, 2147483647);
            DbgPrint("进程等待结束: %d\n", processid);
        }*/

        processid = WaitingGetProcessIDByName(TARGET_PROCESS_NAME, 2147483647);
        DbgPrint("进程等待结束: %d\n", processid);
    }

    if (!processid) {
        DbgPrint("进程未找到，执行结束\n");
        RETURN_ENTRY(STATUS_NOT_FOUND, "Process not found or timeout.");
    }
    // DriverSetOperationResult(0X0, "Found %ls at %d. Injecting...", TARGET_PROCESS_NAME, processid);

    // return STATUS_SUCCESS;

    // 附加执行注入
    NTSTATUS injectStat = AttachAndInjectProcess(processid, tlgInstallPath);
    DbgPrint("injection stat: 0x%x\n", injectStat);

    // DriverObject->DriverUnload = Unload;

    // DriverSetOperationResult(NT_SUCCESS(injectStat) ? 0x0 : 0x1, "Injection status: 0x%x", injectStat);

    return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegPath);

    // DbgPrint("Hello LyShark \n");
    DbgPrint("Started\n");

    // return DoInjection();
    IOInit();
    return STATUS_SUCCESS;
}
