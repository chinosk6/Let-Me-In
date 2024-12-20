#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <format>

namespace TlgPipe {
    const std::string PIPE_NAME = R"(\\.\pipe\TlgExtPluginPipe)";
    HANDLE gPipe = INVALID_HANDLE_VALUE;

    HANDLE createPipe() {
        return CreateNamedPipe(
                PIPE_NAME.c_str(),
                PIPE_ACCESS_DUPLEX,               // 双向通信
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,                                // 最大实例数
                1024,                             // 输出缓冲区大小
                1024,                             // 输入缓冲区大小
                0,                                // 默认超时时间
                nullptr                           // 默认安全属性
        );
    }

    void InitPipe() {
        gPipe = createPipe();
    }

    bool IsPipeCreated() {
        HANDLE hPipe = CreateNamedPipe(
                PIPE_NAME.c_str(),
                PIPE_ACCESS_DUPLEX,               // 双向通信
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,                                // 最大实例数
                1024,                             // 输出缓冲区大小
                1024,                             // 输入缓冲区大小
                0,                                // 默认超时时间
                nullptr                           // 默认安全属性
        );

        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
            return false;
        }

        return true;
    }

    int pipeLoopMain() {
        // HANDLE gPipe = createPipe();

        if (gPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create named pipe. Error: " << GetLastError() << std::endl;
            return 1;
        }

        std::cout << "Waiting for umamusume connection..." << std::endl;

        if (!ConnectNamedPipe(gPipe, nullptr)) {
            std::cerr << "Failed to connect to named pipe. Error: " << GetLastError() << std::endl;
            CloseHandle(gPipe);
            return 1;
        }

        std::cout << "Client connected." << std::endl;

        char buffer[1024];
        bool opened = false;
        while (true) {
            DWORD bytesRead;
            if (ReadFile(gPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
                buffer[bytesRead] = '\0';
                std::string startCommand = buffer;
                if (startCommand == "exit") {
                    break;
                }
                if (opened) {
                    continue;
                }

                ULONG pluginPID = -1;
                STARTUPINFOA startupInfo{ .cb = sizeof(STARTUPINFOA) };
                PROCESS_INFORMATION pi{};
                if (CreateProcessA(NULL, startCommand.data(), NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &pi)) {
                    printf("open external plugin: %s (%lu)\n", startCommand.c_str(), pi.dwProcessId);
                    pluginPID = pi.dwProcessId;
//                    DWORD dwRetun = 0;
//                    WaitForSingleObject(pi.hProcess, INFINITE);
//                    GetExitCodeProcess(pi.hProcess, &dwRetun);
//                    printf("plugin exit: %d\n", dwRetun);
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    opened = true;
                }
                else {
                    printf("Open external plugin failed.\n");
                }

                std::string response = std::format("{}", pluginPID);
                DWORD bytesWritten;
                WriteFile(gPipe, response.c_str(), response.size(), &bytesWritten, nullptr);
            } else {
                std::cerr << "ReadFile failed. Error: " << GetLastError() << std::endl;
                break;
            }
        }

        CloseHandle(gPipe);
        return 0;
    }

}
