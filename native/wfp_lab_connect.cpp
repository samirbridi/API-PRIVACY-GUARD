// API Privacy Guard - dedicated TCP connect-only lab client.
// Never sends data. Run manually ONLY in an isolated disposable Windows VM.
// No privilege escalation, filtering, packet inspection or firewall changes.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cwchar>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

static bool lab_private_ipv4(UINT32 ip) {
    const unsigned first = (ip >> 24) & 255;
    const unsigned second = (ip >> 16) & 255;
    return first == 10 || (first == 172 && second >= 16 && second <= 31) ||
           (first == 192 && second == 168);
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 5 || std::wcscmp(argv[1], L"--ip") ||
        std::wcscmp(argv[3], L"--port")) {
        std::wcerr << L"Usage: wfp_lab_connect.exe --ip RFC1918_IPV4 --port NUMBER\n";
        return 2;
    }
    IN_ADDR ip{};
    if (InetPtonW(AF_INET, argv[2], &ip) != 1 ||
        !lab_private_ipv4(ntohl(ip.S_un.S_addr))) {
        std::wcerr << L"Only owned RFC1918 IPv4 lab destinations accepted.\n";
        return 2;
    }
    wchar_t* end = nullptr;
    const unsigned long port = std::wcstoul(argv[4], &end, 10);
    if (!argv[4][0] || *end || port == 0 || port > 65535) {
        std::wcerr << L"Invalid port.\n";
        return 2;
    }
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::wcout << L"APG_TEST_CONNECT=inconclusive\n";
        return 3;
    }
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        std::wcout << L"APG_TEST_CONNECT=inconclusive\n";
        return 3;
    }
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(static_cast<u_short>(port));
    remote.sin_addr = ip;
    u_long nonblocking = 1;
    bool reached = false;
    if (ioctlsocket(sock, FIONBIO, &nonblocking) == 0) {
        const int first = connect(sock, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));
        if (first == 0) {
            reached = true;
        } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set write_ready;
            fd_set error_ready;
            FD_ZERO(&write_ready);
            FD_ZERO(&error_ready);
            FD_SET(sock, &write_ready);
            FD_SET(sock, &error_ready);
            timeval deadline{};
            deadline.tv_sec = 3;
            const int count = select(0, nullptr, &write_ready, &error_ready, &deadline);
            if (count > 0) {
                int error = 0;
                int size = sizeof(error);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                               reinterpret_cast<char*>(&error), &size) == 0 && error == 0)
                    reached = true;
            }
        }
    }
    closesocket(sock);
    WSACleanup();
    // Not reachable != WFP blocked. Network/server failures produce the same result.
    std::wcout << (reached ? L"APG_TEST_CONNECT=reachable\n" :
                             L"APG_TEST_CONNECT=unreachable\n");
    return reached ? 0 : 1;
}
