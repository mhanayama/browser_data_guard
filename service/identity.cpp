#include "identity.hpp"
#include <bcrypt.h>
#include <wintrust.h>
#include <Softpub.h>
#include <sddl.h>
#include <algorithm>
#include <cwctype>
#include <cstring>
#include <filesystem>

namespace bdg {
namespace {
void checkCrypto(NTSTATUS status) { if (status < 0) fail("BCrypt", static_cast<DWORD>(status)); }
struct Algorithm {
    BCRYPT_ALG_HANDLE value = nullptr;
    ~Algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
};
struct Hash {
    BCRYPT_HASH_HANDLE value = nullptr;
    ~Hash() { if (value) BCryptDestroyHash(value); }
};
std::wstring sha256(HANDLE file) {
    Algorithm algorithm;
    checkCrypto(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0));
    DWORD size = 0, returned = 0;
    checkCrypto(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&size), sizeof(size), &returned, 0));
    std::vector<UCHAR> object(size);
    Hash hash;
    checkCrypto(BCryptCreateHash(algorithm.value, &hash.value, object.data(), size, nullptr, 0, 0));
    std::vector<UCHAR> buffer(64 * 1024);
    DWORD read = 0;
    for (;;) {
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) fail("hash image read");
        if (!read) break;
        checkCrypto(BCryptHashData(hash.value, buffer.data(), read, 0));
    }
    UCHAR digest[32]{};
    checkCrypto(BCryptFinishHash(hash.value, digest, sizeof(digest), 0));
    const wchar_t hex[] = L"0123456789abcdef";
    std::wstring result;
    for (auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
bool validSignature(HANDLE file, const std::wstring& path) {
    WINTRUST_FILE_INFO info{};
    info.cbStruct = sizeof(info);
    info.pcwszFilePath = path.c_str();
    info.hFile = file;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    return status == ERROR_SUCCESS;
}
void checkOwner(HANDLE process, const std::wstring& expected) {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &raw)) fail("OpenProcessToken");
    Handle token(raw);
    DWORD needed = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !needed) fail("TokenUser size");
    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(token.value, TokenUser, buffer.data(), needed, &needed)) fail("TokenUser");
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(expected.c_str(), &sid)) fail("owner SID");
    const bool match = EqualSid(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, sid) != FALSE;
    LocalFree(sid);
    if (!match) fail("process owner mismatch", ERROR_ACCESS_DENIED);
}
}

VerifiedProcess verifyProcess(DWORD pid, const std::wstring& expectedImage,
    const std::wstring& expectedSha256, const std::wstring& expectedOwnerSid, bool unsignedLab) {
    if (!std::filesystem::path(expectedImage).is_absolute()) fail("expected image must use an absolute path", ERROR_INVALID_PARAMETER);
    if (expectedSha256.size() != 64 || !std::all_of(expectedSha256.begin(), expectedSha256.end(), [](wchar_t c) {
        return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
    })) fail("expected SHA-256 must have 64 hexadecimal digits", ERROR_INVALID_PARAMETER);
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!process) fail("OpenProcess");
    if (WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT) fail("process has exited", ERROR_NOT_FOUND);
    checkOwner(process.value, expectedOwnerSid);
    std::vector<wchar_t> buffer(32768);
    DWORD length = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process.value, 0, buffer.data(), &length)) fail("QueryFullProcessImageName");
    std::wstring runningPath(buffer.data(), length);
    Handle image = openImage(expectedImage);
    Handle running = openImage(runningPath);
    const auto canonical = finalPath(image.value);
    if (_wcsicmp(canonical.c_str(), finalPath(running.value).c_str()) != 0)
        fail("full executable path mismatch", ERROR_ACCESS_DENIED);
    FILE_ID_INFO expectedId{}, runningId{};
    if (!GetFileInformationByHandleEx(image.value, FileIdInfo, &expectedId, sizeof(expectedId)) ||
        !GetFileInformationByHandleEx(running.value, FileIdInfo, &runningId, sizeof(runningId))) fail("image file identity");
    if (expectedId.VolumeSerialNumber != runningId.VolumeSerialNumber ||
        std::memcmp(&expectedId.FileId, &runningId.FileId, sizeof(expectedId.FileId)) != 0)
        fail("image file ID mismatch", ERROR_ACCESS_DENIED);
    auto expectedHash = expectedSha256;
    std::transform(expectedHash.begin(), expectedHash.end(), expectedHash.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    if (sha256(image.value) != expectedHash) fail("image SHA-256 mismatch", ERROR_ACCESS_DENIED);
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(image.value, zero, nullptr, FILE_BEGIN)) fail("reset image pointer");
    const bool signedImage = validSignature(image.value, canonical);
    if (!signedImage && !unsignedLab) fail("Authenticode validation failed (offline revocation cache required)", ERROR_ACCESS_DENIED);
    if (WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT) fail("process exited during verification", ERROR_NOT_FOUND);
    return {std::move(process), std::move(image), canonical, signedImage};
}
}
