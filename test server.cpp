#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

struct Client {
    SOCKET socket;
    int id;
};

std::vector<Client> clients;
std::mutex clientsMutex;
int nextId = 1;

// Remove client safely
void removeClient(int id) {
    std::lock_guard<std::mutex> lock(clientsMutex);

    for (auto it = clients.begin(); it != clients.end(); ++it) {
        if (it->id == id) {
            closesocket(it->socket);
            clients.erase(it);
            std::cout << "[-] Client " << id << " removed.\n";
            return;
        }
    }
}// when the code is ready the code will connect to my pc
// i can make it shorter but usually lke 5-10min just terminate i will  make it faster to test
// open windows defender
// Handle receiving from a client
void handleClient(Client client) {
    char buffer[512];
    int bytes;

    while (true) {
        bytes = recv(client.socket, buffer, sizeof(buffer) - 1, 0);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::cout << "\n[Client " << client.id << "] " << buffer << "\n> ";
        }
        else {
            std::cout << "\n[-] Client " << client.id << " disconnected.\n";
            removeClient(client.id);
            break;
        }
    }
}

// Accept incoming clients
void acceptClients(SOCKET listenSocket) {
    while (true) {
        SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);

        if (clientSocket != INVALID_SOCKET) {
            std::lock_guard<std::mutex> lock(clientsMutex);

            Client c;
            c.socket = clientSocket;
            c.id = nextId++;

            clients.push_back(c);

            std::cout << "[+] Client connected (ID: " << c.id << ")\n";

            std::thread(handleClient, c).detach();
        }
    }
}

// Chat with selected client
void chatWithClient(int id) {
    SOCKET targetSocket = INVALID_SOCKET;

    {
        std::lock_guard<std::mutex> lock(clientsMutex);

        for (const auto& c : clients) {
            if (c.id == id) {
                targetSocket = c.socket;
                break;
            }
        }
    }

    if (targetSocket == INVALID_SOCKET) {
        std::cout << "Client not found.\n";
        return;
    }

    std::cout << "Connected to client " << id << ". Type 'back' to return.\n";

    std::string msg;
    while (true) {
        std::cout << "Client " << id << "> ";
        std::getline(std::cin, msg);

        if (msg == "back") break;

        int result = send(targetSocket, msg.c_str(), (int)msg.length(), 0);

        if (result == SOCKET_ERROR) {
            std::cout << "Send failed. Client may have disconnected.\n";
            removeClient(id);
            break;
        }
    }
}

// Main interface loop
void interfaceLoop() {
    while (true) {
        std::cout << "\nCommands:\n";
        std::cout << "list\n";
        std::cout << "select <id>\n";
        std::cout << "exit\n> ";

        std::string input;
        std::getline(std::cin, input);

        if (input == "list") {
            std::lock_guard<std::mutex> lock(clientsMutex);

            if (clients.empty()) {
                std::cout << "No clients connected.\n";
            }
            else {
                for (const auto& c : clients) {
                    std::cout << "Client ID: " << c.id << "\n";
                }
            }
        }
        else if (input.rfind("select", 0) == 0) {
            try {
                int id = std::stoi(input.substr(7));
                chatWithClient(id);
            }
            catch (...) {
                std::cout << "Invalid command format.\n";
            }
        }
        else if (input == "exit") {
            break;
        }
        else {
            std::cout << "Unknown command.\n";
        }
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }

    addrinfo hints{}, * result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(nullptr, "3000", &hints, &result) != 0) {
        std::cerr << "getaddrinfo failed.\n";
        WSACleanup();
        return 1;
    }
    
    SOCKET listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed.\n";
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    if (bind(listenSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        std::cerr << "Bind failed.\n";
        closesocket(listenSocket);
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed.\n";
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server listening on port 8080...\n";

    std::thread acceptThread(acceptClients, listenSocket);

    interfaceLoop();

  
    closesocket(listenSocket);
    WSACleanup();

    return 0;
}