#pragma once
#include <Windows.h>

ULONG CODE_START_INJECT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x775, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
ULONG CODE_STOP_INJECT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x776, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

struct ControlInfo {
    NTSTATUS status;
};

class DriverManager {
    HANDLE m_driver_handle = nullptr;
    std::string drvName;

    DriverManager(const std::string& driverName) {
        drvName = driverName;
        InitDrvHandle();
    }

public:
    static DriverManager GetUniqueInstance(const std::string& driverName = R"(\\.\TLGDRIVER05)") {
        return {driverName};
    }

    static DriverManager& GetInstance(const std::string& driverName = R"(\\.\TLGDRIVER05)") {
        static DriverManager instance(driverName);
        return instance;
    }

    HANDLE InitDrvHandle() {
        m_driver_handle = CreateFileA(drvName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return m_driver_handle;
    }

    HANDLE GetDriverHandle() {
        return m_driver_handle;
    }

    NTSTATUS StartInject() {
        if (!m_driver_handle) {
            return STATUS_INVALID_HANDLE;
        }

        ControlInfo controlInfo{};
        controlInfo.status = STATUS_WAIT_0;
        DeviceIoControl(m_driver_handle, CODE_START_INJECT, &controlInfo, sizeof(controlInfo), &controlInfo, sizeof(controlInfo), nullptr, nullptr);

        return controlInfo.status;
    }

    NTSTATUS CancelWaitInject() {
        if (!m_driver_handle) {
            return STATUS_INVALID_HANDLE;
        }

        ControlInfo controlInfo{};
        controlInfo.status = STATUS_WAIT_0;
        DeviceIoControl(m_driver_handle, CODE_STOP_INJECT, &controlInfo, sizeof(controlInfo), &controlInfo, sizeof(controlInfo), nullptr, nullptr);

        return controlInfo.status;
    }
};
