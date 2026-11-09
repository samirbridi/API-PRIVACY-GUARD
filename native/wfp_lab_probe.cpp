// API PRIVACY GUARD - read-only WFP lab filter lifecycle probe.
// This program does not create, delete, or change any WFP filtering policy.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <fwpmu.h>
#include <fwperr.h>
#include <iostream>
#include <cwchar>
#include <cstdint>
#include <limits>

#pragma comment(lib, "fwpuclnt.lib")

static bool parse_id(const wchar_t* raw, UINT64& value) {
    if (!raw || !*raw) return false;
    UINT64 result = 0;
    for (const wchar_t* p = raw; *p; ++p) {
        if (*p < L'0' || *p > L'9') return false;
        const UINT64 digit = static_cast<UINT64>(*p - L'0');
        if (result > (std::numeric_limits<UINT64>::max() - digit) / 10) return false;
        result = result * 10 + digit;
    }
    if (!result) return false;
    value = result;
    return true;
}

int wmain(int argc, wchar_t** argv) {
    UINT64 filter_id = 0;
    if (argc != 3 || std::wcscmp(argv[1], L"--filter-id") != 0 ||
        !parse_id(argv[2], filter_id)) {
        std::wcerr << L"Usage: wfp_lab_probe.exe --filter-id DECIMAL_ID\n";
        return 2;
    }

    HANDLE engine = nullptr;
    DWORD rc = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine);
    if (rc != ERROR_SUCCESS || !engine) {
        std::wcerr << L"APG_FILTER_QUERY_ERROR=" << rc << L" (open)\n";
        return 3;
    }

    FWPM_FILTER0* filter = nullptr;
    rc = FwpmFilterGetById0(engine, filter_id, &filter);
    if (filter) FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
    DWORD close_rc = FwpmEngineClose0(engine);
    if (close_rc != ERROR_SUCCESS) {
        std::wcerr << L"APG_FILTER_QUERY_ERROR=" << close_rc << L" (close)\n";
        return 4;
    }
    if (rc == ERROR_SUCCESS) {
        std::wcout << L"APG_FILTER_PRESENT=true\n";
        return 0;
    }
    if (rc == FWP_E_FILTER_NOT_FOUND) {
        std::wcout << L"APG_FILTER_PRESENT=false\n";
        return 0;
    }
    // Permission, RPC and other errors are NOT proof of successful rollback.
    std::wcerr << L"APG_FILTER_QUERY_ERROR=" << rc << L" (lookup)\n";
    return 5;
}
