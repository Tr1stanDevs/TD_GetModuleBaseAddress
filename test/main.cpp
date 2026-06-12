#include <cstdint>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>


DWORD GetPid(const wchar_t* ProcName) {
    DWORD PID = 0;

    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W PE;
    PE.dwSize = sizeof(PE);

    if (hsnap == INVALID_HANDLE_VALUE) return PID;

    if (Process32FirstW(hsnap, &PE)) {
        do {
            if (_wcsicmp(ProcName, PE.szExeFile) == 0) {
                PID = PE.th32ProcessID;
                break;
            }
        } while (Process32NextW(hsnap, &PE));
    }

    CloseHandle(hsnap);

    std::cout << "your pid is: " << PID << std::endl;
    return PID;
}

uintptr_t GetModuleBaseAddress(const DWORD PID) {
    uintptr_t mod_base = 0;
    HANDLE msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, PID);
    if (msnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W ME;
    ME.dwSize = sizeof(ME);

    if (Module32FirstW(msnap, &ME)) {
        do {
              if (PID == ME.th32ProcessID) {
                mod_base = (uintptr_t)ME.modBaseAddr;
                break;
              }
        } while (Module32NextW(msnap, &ME));
    }
    CloseHandle(msnap);
    return mod_base;
}

int main() {
    DWORD PID = GetPid(L"RadeonSoftware.exe");
    uintptr_t baseaddy = GetModuleBaseAddress(PID);

    return 0;
}