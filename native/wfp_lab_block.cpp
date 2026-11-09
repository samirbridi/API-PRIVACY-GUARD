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
#include <wincrypt.h>
#include <array>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

static void check(DWORD rc, const char* operation) {
    if (rc) throw std::runtime_error(std::string(operation) + " WFP error " + std::to_string(rc));
}

static bool lab_private_ipv4(UINT32 ip) {
    const unsigned first = (ip >> 24) & 255;
    const unsigned second = (ip >> 16) & 255;
    // Only RFC1918: approved, owned, isolated host-only VM networks.
    // A private address is NOT by itself proof that a VM is isolated.
    return first == 10 ||
           (first == 172 && second >= 16 && second <= 31) ||
           (first == 192 && second == 168);
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

struct ReadonlyExecutable {
    HANDLE file = INVALID_HANDLE_VALUE;
    explicit ReadonlyExecutable(const std::wstring& path) {
        // No write/delete sharing; hold the handle until AFTER the WFP session ends.
        file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                           nullptr);
        if (file == INVALID_HANDLE_VALUE)
            throw std::runtime_error("Cannot lock executable for local SHA-256 validation");
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file, &info) ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
            info.nNumberOfLinks != 1)
            throw std::runtime_error("Executable reparse point, link or file metadata refused");
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
            size.QuadPart > 256LL * 1024 * 1024)
            throw std::runtime_error("Executable size invalid for lab");
        std::wstring actual(32768, L'\0');
        DWORD length = GetFinalPathNameByHandleW(file, actual.data(),
                         static_cast<DWORD>(actual.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!length || length >= actual.size())
            throw std::runtime_error("Could not resolve opened executable");
        actual.resize(length);
        if (actual.rfind(L"\\\\?\\", 0) == 0) actual.erase(0, 4);
        if (_wcsicmp(actual.c_str(), path.c_str()) != 0)
            throw std::runtime_error("Resolved executable does not match the approved path");
    }
    ~ReadonlyExecutable() {
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
    ReadonlyExecutable(const ReadonlyExecutable&) = delete;
    ReadonlyExecutable& operator=(const ReadonlyExecutable&) = delete;
};

struct CryptoProvider {
    HCRYPTPROV handle = 0;
    ~CryptoProvider() { if (handle) CryptReleaseContext(handle, 0); }
};
struct CryptoHash {
    HCRYPTHASH handle = 0;
    ~CryptoHash() { if (handle) CryptDestroyHash(handle); }
};

static std::wstring sha256_open_file(HANDLE file) {
    CryptoProvider provider;
    if (!CryptAcquireContextW(&provider.handle, nullptr, nullptr,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        throw std::runtime_error("SHA-256 provider unavailable");
    CryptoHash hash;
    if (!CryptCreateHash(provider.handle, CALG_SHA_256, 0, 0, &hash.handle))
        throw std::runtime_error("SHA-256 initialization failed");
    std::array<BYTE, 65536> buffer{};
    DWORD count = 0;
    for (;;) {
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr))
            throw std::runtime_error("SHA-256 file read failed");
        if (count == 0) break;
        if (!CryptHashData(hash.handle, buffer.data(), count, 0))
            throw std::runtime_error("SHA-256 update failed");
    }
    std::array<BYTE, 32> digest{};
    DWORD size = static_cast<DWORD>(digest.size());
    if (!CryptGetHashParam(hash.handle, HP_HASHVAL, digest.data(), &size, 0) ||
        size != digest.size())
        throw std::runtime_error("SHA-256 finalization failed");
    static constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring hex;
    hex.reserve(64);
    for (BYTE b : digest) {
        hex.push_back(digits[b >> 4]);
        hex.push_back(digits[b & 0x0F]);
    }
    return hex;
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 16 || std::wcscmp(argv[1], L"--lab-block") ||
            std::wcscmp(argv[2], L"--exe") || std::wcscmp(argv[4], L"--sha256") ||
            std::wcscmp(argv[6], L"--ip") || std::wcscmp(argv[8], L"--port") ||
            std::wcscmp(argv[10], L"--protocol") || std::wcscmp(argv[12], L"--seconds") ||
            std::wcscmp(argv[14], L"--confirm") ||
            std::wcscmp(argv[15], L"LAB-ONLY-EPHEMERAL-BLOCK")) {
            std::wcerr << L"Requires --lab-block --exe PATH --sha256 HASH --ip IPv4 --port PORT"
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

        std::wstring expected_hash(argv[5]);
        if (expected_hash.size() != 64) throw std::runtime_error("SHA-256 pin required");
        for (wchar_t digit : expected_hash)
            if (!((digit >= L'0' && digit <= L'9') ||
                  (digit >= L'a' && digit <= L'f')))
                throw std::runtime_error("SHA-256 must be lower-case hexadecimal");

        IN_ADDR addr{};
        if (InetPtonW(AF_INET, argv[7], &addr) != 1)
            throw std::runtime_error("Numeric IPv4 only");
        UINT32 host_ip = ntohl(addr.S_un.S_addr); // WFP FWP_UINT32 requires host byte order.
        if (!lab_private_ipv4(host_ip))
            throw std::runtime_error("Lab helper requires RFC1918 private IPv4 destination");
        wchar_t* endp = nullptr;
        unsigned long port = std::wcstoul(argv[9], &endp, 10);
        if (!argv[9][0] || *endp || port < 1 || port > 65535)
            throw std::runtime_error("Port invalid");
        unsigned long seconds = std::wcstoul(argv[13], &endp, 10);
        if (!argv[13][0] || *endp || seconds < 5 || seconds > 30)
            throw std::runtime_error("Duration outside 5..30 seconds");
        bool tcp = std::wcscmp(argv[11], L"tcp") == 0;
        bool udp = std::wcscmp(argv[11], L"udp") == 0;
        if (!tcp && !udp) throw std::runtime_error("Protocol must be tcp or udp");

        // Re-check the operator-approved digest in the native helper, not just
        // in Python. Keep a restrictive file handle open until the session ends.
        ReadonlyExecutable target(exe);
        if (sha256_open_file(target.file) != expected_hash)
            throw std::runtime_error("Executable SHA-256 differs from approved pin");

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

        UINT64 filter_id = 0;
        check(FwpmTransactionBegin0(engine.handle, 0), "FwpmTransactionBegin0");
        bool pending = true;
        try {
            check(FwpmSubLayerAdd0(engine.handle, &layer, nullptr), "FwpmSubLayerAdd0");
            check(FwpmFilterAdd0(engine.handle, &filter, nullptr, &filter_id), "FwpmFilterAdd0");
            if (filter_id == 0) throw std::runtime_error("Missing WFP runtime filter ID");
            check(FwpmTransactionCommit0(engine.handle), "FwpmTransactionCommit0");
            pending = false;
        } catch (...) {
            if (pending) FwpmTransactionAbort0(engine.handle);
            throw;
        }
        // Ephemeral filter ID is safe to share for VM lifecycle verification.
        // The WFP application identity blob is never printed.
        std::wcout << L"APG_FILTER_ID=" << filter_id << std::endl;
        std::wcout << L"Temporary scoped filter installed for " << seconds << L" seconds.\n";
        Sleep(static_cast<DWORD>(seconds * 1000));
        // Confirm successful closing, with the destructor retained as fallback.
        check(FwpmEngineClose0(engine.handle), "FwpmEngineClose0");
        engine.handle = nullptr;
        std::wcout << L"APG_SESSION_CLOSED=true" << std::endl;
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << "APG lab refused/failed: " << exc.what() << "\n";
        return 4;
    }
}
