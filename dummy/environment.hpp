#pragma once

#include <ntddk.h>
#include <ntstrsafe.h>

typedef NTSTATUS(*ZW_QUERY_ATTRIBUTES_FILE)(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
    );

NTSTATUS AppendToPath(
    PWCHAR BasePath,          // ԭʼ·�������� L"C:\\Windows\\System32\\"
    SIZE_T BufferSize,        // BasePath ���������ܴ�С���ֽ�����
    PCWSTR Suffix            // Ҫƴ�ӵĺ�׺������ L"xxx.dll"
) {
    NTSTATUS status;

    // ʹ�� RtlStringCbCatW ƴ���ַ�����ȷ����������С�㹻��
    status = RtlStringCbCatW(BasePath, BufferSize, Suffix);
    if (!NT_SUCCESS(status)) {
        // ƴ��ʧ�ܿ�������Ϊ������̫С����������
        DbgPrint("Failed to append string, status=0x%X\n", status);
    }

    return status;
}

NTSTATUS ReadSystemEnvironmentVariable(
    PCWSTR VariableName,      // Ҫ��ȡ�Ļ����������ƣ�����L"Path"
    PWCHAR ValueBuffer,       // ���ڽ��ս���Ļ����������ַ�����
    ULONG ValueBufferSize,    // ��������С���ֽ�����
    PULONG ResultLength       // [��ѡ]�����ȡ�����ֽ�����������ֹ����
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

    // ���Ȳ�ѯ�����С
    status = ZwQueryValueKey(
        hKey,
        &valueName,
        KeyValuePartialInformation,
        NULL,
        0,
        &requiredLength
    );

    if (status != STATUS_BUFFER_TOO_SMALL) {
        // ���������ΪBufferС��ʧ�ܣ���˵��û�����ֵ����������
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
        // ȷ����REG_SZ���ͻ��ת��Ϊ�ַ���������
        if (keyValueInfo->Type == REG_SZ || keyValueInfo->Type == REG_EXPAND_SZ) {
            ULONG dataLen = keyValueInfo->DataLength;
            if (dataLen <= ValueBufferSize) {
                // �����ݸ��Ƶ������ߵĻ�����
                RtlCopyMemory(ValueBuffer, keyValueInfo->Data, dataLen);

                // ȷ���ַ�����ֹ�����ԭ���ݲ�����\0������Ҫ�ֶ���ӣ�
                if (dataLen > sizeof(WCHAR) && ((PWCHAR)(keyValueInfo->Data))[dataLen / sizeof(WCHAR) - 1] != L'\0') {
                    ValueBuffer[dataLen / sizeof(WCHAR)] = L'\0';
                }

                if (ResultLength) {
                    *ResultLength = dataLen;
                }
            }
            else {
                // ������̫С
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
        else {
            // ���Ͳ����ַ�������
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

    // ��������ͨ��Ϊ REG_SZ
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
