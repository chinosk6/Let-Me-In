#include <Windows.h>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <filesystem>
#include <libKDU.h>
#include "tlgPipe.hpp"
#include "driver_res.h"
//#include "drv64_res.h"
//#include "kdu_res.h"
#include "device_control.hpp"
#include "utils.hpp"

// #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)  // From ntdef.h

#pragma pack(push, 1)
typedef struct _SHARED_RESULT {
    ULONG Status;
    CHAR  ErrorMessage[256];
} SHARED_RESULT, *PSHARED_RESULT;
#pragma pack(pop)


typedef LONG (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

ULONG GetWindowsBuildNumber() {
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (hNtDll) {
        auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtDll, "RtlGetVersion");
        if (RtlGetVersion)
        {
            RTL_OSVERSIONINFOEXW osInfo = {0};
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);

            if (RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo) == 0) {
                return osInfo.dwBuildNumber;
            }
        }
        else {
            printf("RtlGetVersion not found.\n");
        }
    }
    else {
        printf("Load ntdll failed.\n");
    }
    return 0;
}

template <size_t arrSize>
bool SaveFileFromArray(std::array<unsigned char, arrSize>& arr, const char* filePath) {
    std::ofstream outFile(filePath, std::ios::out | std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to open file for writing: " << filePath << std::endl;
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(arr.data()), arr.size());

    if (!outFile) {
        std::cerr << "Error occurred while writing to file." << std::endl;
        return false;
    }

    outFile.close();
    return true;
}

std::string ErrorCodeToString(DWORD errorMessageID) {
    if (errorMessageID == 0) {
        return "No error";
    }

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&messageBuffer, 0, nullptr);

    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);
    message = std::format("{} - {}", errorMessageID, message);
    return message;
}

std::string GetLastErrorAsString() {
    return ErrorCodeToString(::GetLastError());
}

void DeleteFileIfExists(const char* fileName) {
    if (std::filesystem::exists(fileName)) {
        std::filesystem::remove(fileName);
    }
}

BOOL LoadDriverLibKDU() {  // BSOD PAGE_FAULT_IN_NONPAGED_AREA - resolved
    if (!SaveFileFromArray(tlgDriverData, "tlgLoader.sys")) {
        std::cerr << "Extract driver failed." << std::endl;
    }

    const auto osVer = GetWindowsBuildNumber();
    printf("osVer: %lu\n", osVer);

    BOOLEAN hvciEnabled;
    BOOLEAN hvciStrict;
    BOOLEAN hvciIUM;
    if (ntsupQueryHVCIState(&hvciEnabled, &hvciStrict, &hvciIUM)) {
        if (hvciEnabled) {
            wprintf(L"[WARNING] Windows HVCI mode detected. The plugin may not load in this mode. Please go to Windows Security Center and disable \"Core Isolation - Memory Integrity.\"\n");
            // 检测到 HVCI，插件可能无法通过这个模式加载。请前往 Windows 安全中心关闭内核隔离 - 内存完整性。
            wprintf(L"[WARNING] \u68c0\u6d4b\u5230\u0020\u0048\u0056\u0043\u0049\uff0c\u63d2\u4ef6\u53ef\u80fd\u65e0\u6cd5\u901a\u8fc7\u8fd9\u4e2a\u6a21\u5f0f\u52a0\u8f7d\u3002\u8bf7\u524d\u5f80\u0020\u0057\u0069\u006e\u0064\u006f\u0077\u0073\u0020\u5b89\u5168\u4e2d\u5fc3\u5173\u95ed\u5185\u6838\u9694\u79bb\u0020\u002d\u0020\u5185\u5b58\u5b8c\u6574\u6027\u3002\n");
        }
    }

    auto ret = libKDUMapDriver(hvciEnabled, osVer, 20, 1, L"tlgLoader.sys", NULL, NULL);

    DeleteFileIfExists("tlgLoader.sys");

    return ret;
}

/*
bool LoadDriver() {
#define REMOVE_FILES() DeleteFileIfExists("kdu.exe"); DeleteFileIfExists("drv64.dll"); DeleteFileIfExists("tlgLoader.sys")

    if (!(SaveFileFromArray(kduData, "kdu.exe") && SaveFileFromArray(drv64Data, "drv64.dll") && SaveFileFromArray(tlgDriverData, "tlgLoader.sys"))) {
        REMOVE_FILES();
        return false;
    }

    STARTUPINFOA startupInfo{
        .cb = sizeof(STARTUPINFOA),
        .hStdInput = GetStdHandle(STD_INPUT_HANDLE),
        .hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE),
        .hStdError = GetStdHandle(STD_ERROR_HANDLE)
    };
    startupInfo.dwFlags |= STARTF_USESTDHANDLES;
    PROCESS_INFORMATION pi{};

    std::string cmd = "kdu.exe -prv 20 -map tlgLoader.sys";
    // std::string cmd = "kdu.exe -prv 20 -scv 3 -drvn tlgdriverv02 -drvr tlgdriverv02 -map tlgLoader.sys";

    if (CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startupInfo, &pi)) {
        DWORD dwReturn = 0;
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &dwReturn);
        printf("Loader exit: %lu\n", dwReturn);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (dwReturn == 0) {
            REMOVE_FILES();
            return false;
        }
    }
    else {
        auto lastError = GetLastError();
        std::cerr << "Failed to create loader process: " << ErrorCodeToString(lastError) << std::endl;
        if (lastError == 740) {
            wprintf(L"Please start as Administrator.\n\u8bf7\u4ee5\u7ba1\u7406\u5458\u542f\u52a8\u7a0b\u5e8f\n");
        }

        REMOVE_FILES();
        return false;
    }

    REMOVE_FILES();
    return true;
}*/

bool WriteCurrentPathToEnv() {
    char currentPath[MAX_PATH];
    DWORD length = GetModuleFileNameA(nullptr, currentPath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        std::cerr << "Failed to get current path. Error: " << GetLastError() << std::endl;
        return false;
    }

    // 去掉文件名，保留目录部分
    std::string fullPath(currentPath);
    size_t lastSlash = fullPath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        fullPath = fullPath.substr(0, lastSlash);
    }
    if ((!fullPath.ends_with('\\')) && (!fullPath.ends_with('/'))) {
        fullPath += "\\";
    }

    // 设置系统环境变量
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"(SYSTEM\CurrentControlSet\Control\Session Manager\Environment)", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (RegSetValueExA(hKey, "TLG_DIRECTORY", 0, REG_SZ, (const BYTE*)fullPath.c_str(), fullPath.size() + 1) != ERROR_SUCCESS) {
        std::cerr << "Failed to set registry value. Error: " << GetLastError() << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);

    // 通知系统更新环境变量
    if (!SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)"Environment", SMTO_ABORTIFHUNG, 5000, nullptr)) {
        std::cerr << "Failed to broadcast environment change. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "Successfully set TLG_PATH to: " << fullPath << std::endl;
    return true;
}


BOOL WINAPI ConsoleHandler(DWORD event) {
    switch (event) {
        case CTRL_CLOSE_EVENT:  // 点击关闭按钮
        case CTRL_C_EVENT:      // 按下 Ctrl+C
        case CTRL_BREAK_EVENT: {
            printf("CancelWaitInject\n");
            auto driver = DriverManager::GetUniqueInstance();
            printf("CancelWaitInject ret: 0x%lx\n", driver.CancelWaitInject());
            return TRUE;
        }
    }
    return FALSE;
}


int programMain() {
    if (TlgPipe::IsPipeCreated()) {
        std::cerr << "TLG Loader is already running..." << std::endl;
        return 1;
    }
    TlgPipe::InitPipe();

    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "SetConsoleCtrlHandler Failed." << std::endl;
        return 1;
    }

    if (!WriteCurrentPathToEnv()) {
        std::cerr << "Failed to set current path." << std::endl;
        return 1;
    }

    auto driver = DriverManager::GetInstance();

    if (driver.GetDriverHandle() == INVALID_HANDLE_VALUE) {
        printf("Driver Not Loaded.\n");
        // const auto loadDriverStat = LoadDriver();
        const auto loadDriverStat = LoadDriverLibKDU();
        printf("LoadDriver: %d\n", loadDriverStat);
        if (!loadDriverStat) {
            return 1;
        }

        if (driver.InitDrvHandle() == INVALID_HANDLE_VALUE) {
            printf("InitDrvHandle failed: %p\n", driver.GetDriverHandle());
            return 1;
        }
    }
    else {
        printf("Driver Loaded.\n");
    }

    std::cout << "Now you can start umamusume." << std::endl;
    std::cout << "\u73b0\u5728\u4f60\u53ef\u4ee5\u542f\u52a8\u0020\u0075\u006d\u0061\u006d\u0075\u0073\u0075\u006d\u0065\u0020\u4e86" << std::endl;

    NTSTATUS injectStatus = driver.StartInject();
    if (!NT_SUCCESS(injectStatus)) {
        printf("Injection Failed: 0x%lx\n", injectStatus);
        return 1;
    }
    printf("Injection Status: 0x%lx\n", injectStatus);

    return TlgPipe::pipeLoopMain();
}

int main() {
    if (programMain() != 0) {
        printf("Press Enter To Exit.");
        getchar();
    }
}
