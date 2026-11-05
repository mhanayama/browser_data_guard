#include "../service/identity.hpp"
#include <sddl.h>
#include <filesystem>
#include <iostream>
#include <functional>

void expectFailure(const std::function<void()>& action, const char* expected) {
    try { action(); }
    catch (const std::exception& error) {
        if (std::string(error.what()).find(expected) != std::string::npos) return;
        throw;
    }
    throw std::runtime_error("verification unexpectedly granted trust");
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 2) throw std::runtime_error("Run via Invoke-UserTests.ps1 to supply the independent SHA-256 pin.");
        wchar_t image[32768]{};
        if (!GetModuleFileNameW(nullptr, image, 32768)) bdg::fail("GetModuleFileName");
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) bdg::fail("OpenProcessToken");
        bdg::Handle token(raw);
        DWORD bytes = 0;
        GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
        std::vector<BYTE> buffer(bytes);
        if (!GetTokenInformation(token.value, TokenUser, buffer.data(), bytes, &bytes)) bdg::fail("TokenUser");
        LPWSTR text = nullptr;
        if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) bdg::fail("SID string");
        std::wstring owner(text); LocalFree(text);
        const std::wstring badHash(64, L'0');
        expectFailure([&] { bdg::verifyProcess(GetCurrentProcessId(), image, L"abc", owner, true); }, "64 hexadecimal");
        expectFailure([&] { bdg::verifyProcess(GetCurrentProcessId(), image, badHash, L"S-1-0-0", true); }, "owner mismatch");
        expectFailure([&] { bdg::verifyProcess(GetCurrentProcessId(), image, badHash, owner, true); }, "SHA-256 mismatch");
        wchar_t unrelated[32768]{};
        if (!GetModuleFileNameW(GetModuleHandleW(L"kernel32.dll"), unrelated, 32768)) bdg::fail("GetModuleFileName kernel32");
        expectFailure([&] { bdg::verifyProcess(GetCurrentProcessId(), unrelated, badHash, owner, true); }, "path mismatch");
        expectFailure([&] { bdg::verifyProcess(GetCurrentProcessId(), L"relative.exe", badHash, owner, true); }, "absolute path");
        {
            auto verified = bdg::verifyProcess(GetCurrentProcessId(), image, argv[1], owner, true);
            if (GetProcessId(verified.process.value) != GetCurrentProcessId() || !verified.image)
                throw std::runtime_error("verified process identity incorrect");
        }
        expectFailure([&] { bdg::verifyProcess(GetCurrentProcessId(), image, argv[1], owner, false); }, "Authenticode validation failed");
        if (bdg::json(L"a\"\\\n\t") != "\"a\\\"\\\\\\u000a\\u0009\"") throw std::runtime_error("JSON escaping failed");
        if (bdg::timestamp(0) != "1601-01-01T00:00:00.000Z") throw std::runtime_error("FILETIME conversion failed");
        std::cout << "9 user-mode assertions passed (no driver connection or profile access)\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
