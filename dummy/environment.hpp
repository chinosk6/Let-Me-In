#pragma once

#include <ntddk.h>
#include <ntstrsafe.h>

typedef NTSTATUS(*ZW_QUERY_ATTRIBUTES_FILE)(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
    );

NTSTATUS AppendToPath(
    PWCHAR BasePath,          // 原始路径，例如 L"C:\\Windows\\System32\\"
    SIZE_T BufferSize,        // BasePath 缓冲区的总大小（字节数）
    PCWSTR Suffix            // 要拼接的后缀，例如 L"xxx.dll"
) {
    NTSTATUS status;

    // 使用 RtlStringCbCatW 拼接字符串（确保缓冲区大小足够）
    status = RtlStringCbCatW(BasePath, BufferSize, Suffix);
    if (!NT_SUCCESS(status)) {
        // 拼接失败可能是因为缓冲区太小或其他问题
        DbgPrint("Failed to append string, status=0x%X\n", status);
    }

    return status;
}

NTSTATUS ReadSystemEnvironmentVariable(
    PCWSTR VariableName,      // 要读取的环境变量名称，例如L"Path"
    PWCHAR ValueBuffer,       // 用于接收结果的缓冲区（宽字符串）
    ULONG ValueBufferSize,    // 缓冲区大小（字节数）
    PULONG ResultLength       // [可选]输出读取到的字节数（包括终止符）
)
{
    NTSTATUS status;
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    ULONG requiredLength = 0;

    RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
    InitializeObjectAttributes(&objectAttributes, &keyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &objectAttributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&valueName, VariableName);

    // 首先查询所需大小
    status = ZwQueryValueKey(
        hKey,
        &valueName,
        KeyValuePartialInformation,
        NULL,
        0,
        &requiredLength
    );

    if (status != STATUS_BUFFER_TOO_SMALL) {
        // 如果不是因为Buffer小而失败，则说明没有这个值或其他错误
        ZwClose(hKey);
        return status;
    }

    PKEY_VALUE_PARTIAL_INFORMATION keyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, requiredLength, 'vneE');
    if (!keyValueInfo) {
        ZwClose(hKey);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(
        hKey,
        &valueName,
        KeyValuePartialInformation,
        keyValueInfo,
        requiredLength,
        &requiredLength
    );

    if (NT_SUCCESS(status)) {
        // 确保是REG_SZ类型或可转化为字符串的类型
        if (keyValueInfo->Type == REG_SZ || keyValueInfo->Type == REG_EXPAND_SZ) {
            ULONG dataLen = keyValueInfo->DataLength;
            if (dataLen <= ValueBufferSize) {
                // 将数据复制到调用者的缓冲区
                RtlCopyMemory(ValueBuffer, keyValueInfo->Data, dataLen);

                // 确保字符串终止（如果原数据不是以\0结束，要手动添加）
                if (dataLen > sizeof(WCHAR) && ((PWCHAR)(keyValueInfo->Data))[dataLen / sizeof(WCHAR) - 1] != L'\0') {
                    ValueBuffer[dataLen / sizeof(WCHAR)] = L'\0';
                }

                if (ResultLength) {
                    *ResultLength = dataLen;
                }
            }
            else {
                // 缓冲区太小
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
        else {
            // 类型不是字符串类型
            status = STATUS_INVALID_PARAMETER;
        }
    }

    ExFreePool(keyValueInfo);
    ZwClose(hKey);
    return status;
}


NTSTATUS WriteSystemEnvironmentVariable(
    PCUNICODE_STRING VariableName,
    PCWSTR ValueData
)
{
    NTSTATUS status;
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyName;

    RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
    InitializeObjectAttributes(&objectAttributes, &keyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_SET_VALUE, &objectAttributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, VariableName->Buffer);

    // 环境变量通常为 REG_SZ
    status = ZwSetValueKey(
        hKey,
        &valueName,
        0,
        REG_SZ,
        (PVOID)ValueData,
        ((ULONG)wcslen(ValueData) + 1) * sizeof(WCHAR)
    );

    ZwClose(hKey);
    return status;
}
