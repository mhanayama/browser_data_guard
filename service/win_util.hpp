#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <string_view>
#include <stdexcept>
#include <utility>
#include <vector>

namespace bdg {
inline void fail(const char* what, DWORD code = GetLastError()) {
    throw std::runtime_error(std::string(what) + " (error " + std::to_string(code) + ")");
}
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, INVALID_HANDLE_VALUE)) {}
    explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
};
inline std::wstring finalPath(HANDLE file, DWORD volume = VOLUME_NAME_DOS) {
    std::vector<wchar_t> buffer(32768);
    DWORD n = GetFinalPathNameByHandleW(file, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | volume);
    if (!n || n >= buffer.size()) fail("GetFinalPathNameByHandle");
    return {buffer.data(), n};
}
inline Handle openImage(const std::wstring& path) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) fail("open image without write/delete sharing");
    return file;
}
inline std::string utf8(std::wstring_view value) {
    if (value.empty()) return {};
    int count = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!count) fail("UTF-8 size");
    std::string result(static_cast<size_t>(count), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), count, nullptr, nullptr)) fail("UTF-8 conversion");
    return result;
}
inline std::string json(std::wstring_view value) {
    const char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : utf8(value)) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 0x20) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
        else out += static_cast<char>(c);
    }
    return out + '"';
}
inline std::string timestamp(unsigned long long ticks) {
    FILETIME ft{static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)};
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) fail("FileTimeToSystemTime");
    char buffer[40]{};
    sprintf_s(buffer, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buffer;
}
}
