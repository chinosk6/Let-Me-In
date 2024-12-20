#pragma once

#include <ntifs.h>
#include "types.hpp"

NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
NTSTATUS DoInjection();

#define DRIVER_NAME L"\\Driver\\TLGDRIVER05"
#define DRIVER_DEVICE_NAME L"\\Device\\TLGDRIVER05"
#define DRIVER_DOS_NAME L"\\DosDevices\\TLGDRIVER05"

ULONG CODE_START_INJECT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x775, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
ULONG CODE_STOP_INJECT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x776, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

extern InjectStat g_CurrentInjectStat;

typedef struct _ControlInfo {
	NTSTATUS status;

} ControlInfo, *PControlInfo;


NTSTATUS unsupportedIO(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS createIO(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS closeIO(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS ctlIO(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	static PEPROCESS s_target_process;

	irp->IoStatus.Information = sizeof(ControlInfo);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	PControlInfo buffer = (ControlInfo*)irp->AssociatedIrp.SystemBuffer;

	if (stack) {
		if (buffer && sizeof(*buffer) >= sizeof(ControlInfo)) {
			const auto ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;

			if (ctl_code == CODE_START_INJECT) {
				buffer->status = DoInjection();
				if (g_CurrentInjectStat != INJ_CANCEL_WAITING) {
					g_CurrentInjectStat = NOT_INJECTING;
				}
			}
			if (ctl_code == CODE_STOP_INJECT) {
				DbgPrint("取消等待进程事件, g_CurrentInjectStat： %d\n", g_CurrentInjectStat);
				if (g_CurrentInjectStat == INJECTING) {
					g_CurrentInjectStat = INJ_CANCEL_WAITING;
				}
				buffer->status = 0x0;
			}
		}
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS real_main(
	_In_ struct _DRIVER_OBJECT* DriverObject,
	_In_ PUNICODE_STRING RegistryPath) 
{
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING dev_name, sym_link;
	PDEVICE_OBJECT dev_obj;

	RtlInitUnicodeString(&dev_name, DRIVER_DEVICE_NAME);
	auto status = IoCreateDevice(DriverObject, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
	if (status != STATUS_SUCCESS) return status;

	RtlInitUnicodeString(&sym_link, DRIVER_DOS_NAME);
	status = IoCreateSymbolicLink(&sym_link, &dev_name);
	if (status != STATUS_SUCCESS) return status;

	// SetFlag(dev_obj->Flags, DO_BUFFERED_IO); //set DO_BUFFERED_IO bit to 1
	dev_obj->Flags |= DO_BUFFERED_IO;

	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++) //set all MajorFunction's to unsupported
		DriverObject->MajorFunction[t] = unsupportedIO;

	//then set supported functions to appropriate handlers
	DriverObject->MajorFunction[IRP_MJ_CREATE] = createIO; //link our io create function
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = closeIO; //link our io close function
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctlIO; //link our control code handler
	DriverObject->DriverUnload = NULL; //add later

	ClearFlag(dev_obj->Flags, DO_DEVICE_INITIALIZING); //set DO_DEVICE_INITIALIZING bit to 0 (we are done initializing)
	return status;
}

void IOInit() {
	UNICODE_STRING drv_name;
	RtlInitUnicodeString(&drv_name, DRIVER_NAME);
	NTSTATUS drvStat = IoCreateDriver(&drv_name, &real_main);
	DbgPrint("IoCreateDriver: 0x%x\n", drvStat);
}
