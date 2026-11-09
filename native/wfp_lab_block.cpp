// API PRIVACY GUARD - WFP temporary filter, disposable Windows VM ONLY.
// WARNING: This program CAN block a real outbound connection.
// Compile manually with MSVC/Windows SDK; never run in CI, installers, agents, or MCP.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <objbase.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <cwchar>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")

static void check(DWORD rc, const char* operation) {
    if (rc) throw std::runtime_error(std::string(operation) + " WFP error " + std::to_string(rc));
}

static bool public_ipv4(UINT32 a) {
    unsigned a8 = (a >> 24) & 255, b8 = (a >> 16) & 255;
    // Reject private, loopback, link-local, multicast, special and documentation IPs.
    if (a8 == 0 || a8 == 10 || a8 == 127 || a8 >= 224 ||
        a8 == 169 || a8 == 172 && b8 >= 16 && b8 <= 31 ||
        a8 == 192 && (b8 == 168 || b8 == 0) ||
        a8 == 100 && b8 >= 64 && b8 <= 127 ||
        a8 == 198 && (b8 == 18 || b8 == 19 || b8 == 51) ||
        a8 == 203 && b8 == 0) return false;
    return true;
}

struct Engine {
    HANDLE handle = nullptr;
    ~Engine() { if (handle) FwpmEngineClose0(handle); }
    Engine() = default;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
};
struct AppId {
    FWP_BYTE_BLOB* ptr = nullptr;
    ~AppId() { if (ptr) FwpmFreeMemory0(reinterpret_cast<void**>(&ptr)); }
    AppId() = default;
    AppId(const AppId&) = delete;
    AppId& operator=(const AppId&) = delete;
};

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 14 || std::wcscmp(argv[1], L"--lab-block") ||
            std::wcscmp(argv[2], L"--exe") || std::wcscmp(argv[4], L"--ip") ||
            std::wcscmp(argv[6], L"--port") || std::wcscmp(argv[8], L"--protocol") ||
            std::wcscmp(argv[10], L"--seconds") || std::wcscmp(argv[12], L"--confirm") ||
            std::wcscmp(argv[13], L"LAB-ONLY-EPHEMERAL-BLOCK")) {
            std::wcerr << L"Requires --lab-block --exe PATH --ip IPv4 --port PORT"
                       << L" --protocol tcp|udp --seconds 5..30"
                       << L" --confirm LAB-ONLY-EPHEMERAL-BLOCK\n";
            return 2;
        }

        wchar_t ack[64]{};
        DWORD n = GetEnvironmentVariableW(L"APG_WFP_DISPOSABLE_VM", ack, 64);
        if (n != 20 || std::wcscmp(ack, L"I_ACCEPT_VM_ONLY_LAB")) {
            std::wcerr << L"Denied: must acknowledge disposable VM via environment variable.\n";
            return 3;
        }

        std::wstring exe(argv[3]);
        if (exe.size() < 7 || exe.size() > 512 || exe[1] != L':' ||
            exe[2] != L'\\' || exe.find(L"..") != std::wstring::npos ||
            exe.find(L'/') != std::wstring::npos ||
            exe.find(L':', 2) != std::wstring::npos ||
            exe.substr(exe.size() - 4) != L".exe")
            throw std::runtime_error("Invalid absolute executable path");
        DWORD attributes = GetFileAttributesW(exe.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("Executable absent or reparse point");
        std::wstring fullpath(32768, L'\0');
        DWORD length = GetFullPathNameW(exe.c_str(), static_cast<DWORD>(fullpath.size()),
                                        fullpath.data(), nullptr);
        if (!length || length >= fullpath.size() || _wcsicmp(fullpath.c_str(), exe.c_str()))
            throw std::runtime_error("Non-canonical executable path");

        IN_ADDR addr{};
        if (InetPtonW(AF_INET, argv[5], &addr) != 1)
            throw std::runtime_error("Numeric IPv4 only");
        UINT32 host_ip = ntohl(addr.S_un.S_addr); // WFP FWP_UINT32 requires host byte order.
        if (!public_ipv4(host_ip))
            throw std::runtime_error("Non-public destination refused");
        wchar_t* endp = nullptr;
        unsigned long port = std::wcstoul(argv[7], &endp, 10);
        if (!argv[7][0] || *endp || port < 1 || port > 65535)
            throw std::runtime_error("Port invalid");
        unsigned long seconds = std::wcstoul(argv[11], &endp, 10);
        if (!argv[11][0] || *endp || seconds < 5 || seconds > 30)
            throw std::runtime_error("Duration outside 5..30 seconds");
        bool tcp = std::wcscmp(argv[9], L"tcp") == 0;
        bool udp = std::wcscmp(argv[9], L"udp") == 0;
        if (!tcp && !udp) throw std::runtime_error("Protocol must be tcp or udp");

        Engine engine;
        FWPM_SESSION0 session{};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = const_cast<wchar_t*>(L"API Privacy Guard lab");
        session.displayData.description = const_cast<wchar_t*>(L"One ephemeral filter; lab only");
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session,
                              &engine.handle), "FwpmEngineOpen0");

        AppId app;
        check(FwpmGetAppIdFromFileName0(exe.c_str(), &app.ptr), "FwpmGetAppIdFromFileName0");
        if (!app.ptr || !app.ptr->size) throw std::runtime_error("Empty application ID");

        FWPM_SUBLAYER0 layer{};
        if (CoCreateGuid(&layer.subLayerKey) != S_OK)
            throw std::runtime_error("Failed to generate sublayer GUID");
        layer.displayData.name = const_cast<wchar_t*>(L"APG temporary lab sublayer");
        layer.weight = 0x100;

        FWPM_FILTER_CONDITION0 condition[4]{};
        condition[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition[0].matchType = FWP_MATCH_EQUAL;
        condition[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        condition[0].conditionValue.byteBlob = app.ptr;
        condition[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition[1].matchType = FWP_MATCH_EQUAL;
        condition[1].conditionValue.type = FWP_UINT32;
        condition[1].conditionValue.uint32 = host_ip;
        condition[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        condition[2].matchType = FWP_MATCH_EQUAL;
        condition[2].conditionValue.type = FWP_UINT16;
        condition[2].conditionValue.uint16 = static_cast<UINT16>(port);
        condition[3].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        condition[3].matchType = FWP_MATCH_EQUAL;
        condition[3].conditionValue.type = FWP_UINT8;
        condition[3].conditionValue.uint8 =
            static_cast<UINT8>(tcp ? IPPROTO_TCP : IPPROTO_UDP);

        FWPM_FILTER0 filter{};
        if (CoCreateGuid(&filter.filterKey) != S_OK)
            throw std::runtime_error("Failed to generate filter GUID");
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.subLayerKey = layer.subLayerKey;
        filter.displayData.name = const_cast<wchar_t*>(L"APG one scoped lab block");
        filter.action.type = FWP_ACTION_BLOCK;
        filter.weight.type = FWP_EMPTY;
        filter.numFilterConditions = 4;
        filter.filterCondition = condition;

        check(FwpmTransactionBegin0(engine.handle, 0), "FwpmTransactionBegin0");
        bool pending = true;
        try {
            check(FwpmSubLayerAdd0(engine.handle, &layer, nullptr), "FwpmSubLayerAdd0");
            check(FwpmFilterAdd0(engine.handle, &filter, nullptr, nullptr), "FwpmFilterAdd0");
            check(FwpmTransactionCommit0(engine.handle), "FwpmTransactionCommit0");
            pending = false;
        } catch (...) {
            if (pending) FwpmTransactionAbort0(engine.handle);
            throw;
        }
        std::wcout << L"Temporary scoped filter installed for " << seconds << L" seconds.\n";
        Sleep(static_cast<DWORD>(seconds * 1000));
        // Engine destructor closes the dynamic session: filter and sublayer expire.
        std::wcout << L"Lifetime expired. Releasing dynamic WFP session.\n";
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << "APG lab refused/failed: " << exc.what() << "\n";
        return 4;
    }
}
