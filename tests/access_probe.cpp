#include "../service/win_util.hpp"
#include <iostream>

namespace {
struct Gate {
    bdg::Handle gate, ready;
    Gate(const std::wstring& gateName, const std::wstring& readyName) {
        if (!gateName.empty()) {
            gate.value = OpenEventW(SYNCHRONIZE, FALSE, gateName.c_str());
            if (!gate) bdg::fail("OpenEvent gate");
        }
        if (!readyName.empty()) {
            ready.value = OpenEventW(EVENT_MODIFY_STATE, FALSE, readyName.c_str());
            if (!ready) bdg::fail("OpenEvent ready");
        }
    }
    void wait() {
        if (ready && !SetEvent(ready.value)) bdg::fail("SetEvent ready");
        if (gate && WaitForSingleObject(gate.value, 60000) != WAIT_OBJECT_0) bdg::fail("gate timeout", WAIT_TIMEOUT);
    }
};
int operation(const std::wstring& op, const std::wstring& file, const std::wstring& dest, Gate& gate) {
    bool held = op == L"hold-read" || op == L"hold-map";
    if (!held) gate.wait();
    if (op == L"copy") {
        if (dest.empty()) bdg::fail("copy destination required", ERROR_INVALID_PARAMETER);
        if (!CopyFileW(file.c_str(), dest.c_str(), TRUE)) bdg::fail("CopyFile");
    } else if (op == L"hardlink") {
        if (dest.empty()) bdg::fail("hardlink destination required", ERROR_INVALID_PARAMETER);
        if (!CreateHardLinkW(dest.c_str(), file.c_str(), nullptr)) bdg::fail("CreateHardLink");
    } else if (op == L"rename") {
        if (dest.empty()) bdg::fail("rename destination required", ERROR_INVALID_PARAMETER);
        if (!MoveFileExW(file.c_str(), dest.c_str(), 0)) bdg::fail("MoveFileEx");
    } else if (op == L"delete") {
        if (!DeleteFileW(file.c_str())) bdg::fail("DeleteFile");
    } else {
        DWORD access = GENERIC_READ, disposition = OPEN_EXISTING;
        if (op == L"metadata") access = FILE_READ_ATTRIBUTES;
        else if (op == L"truncate-zero") { access = 0; disposition = TRUNCATE_EXISTING; }
        else if (op == L"truncate") { access = GENERIC_WRITE; disposition = TRUNCATE_EXISTING; }
        else if (op == L"max-allowed") access = MAXIMUM_ALLOWED;
        else if (op == L"write") access = GENERIC_WRITE;
        else if (op != L"read" && op != L"map" && op != L"hold-read" && op != L"hold-map")
            bdg::fail("unknown probe operation", ERROR_INVALID_PARAMETER);
        bdg::Handle input(CreateFileW(file.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!input) bdg::fail("CreateFile");
        if (op == L"map" || op == L"hold-map") {
            bdg::Handle mapping(CreateFileMappingW(input.value, nullptr, PAGE_READONLY, 0, 0, nullptr));
            if (!mapping) bdg::fail("CreateFileMapping");
            const auto* view = static_cast<const volatile BYTE*>(MapViewOfFile(mapping.value, FILE_MAP_READ, 0, 0, 1));
            if (!view) bdg::fail("MapViewOfFile");
            try { if (held) gate.wait(); std::cout << "byte=" << static_cast<unsigned>(*view) << '\n'; }
            catch (...) { UnmapViewOfFile(const_cast<const BYTE*>(view)); throw; }
            UnmapViewOfFile(const_cast<const BYTE*>(view));
        } else if (op == L"read" || op == L"hold-read" || op == L"max-allowed") {
            if (held) gate.wait();
            BYTE byte = 0; DWORD read = 0;
            if (!ReadFile(input.value, &byte, 1, &read, nullptr)) bdg::fail("ReadFile");
        } else if (op == L"write") {
            const BYTE byte = 'X'; DWORD written = 0;
            if (!WriteFile(input.value, &byte, 1, &written, nullptr)) bdg::fail("WriteFile");
        }
    }
    return 0;
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        std::wstring gateName, readyName;
        int i = 1;
        while (i < argc && (std::wstring(argv[i]) == L"--gate" || std::wstring(argv[i]) == L"--ready")) {
            std::wstring key = argv[i++];
            if (i >= argc) bdg::fail("missing event name", ERROR_INVALID_PARAMETER);
            (key == L"--gate" ? gateName : readyName) = argv[i++];
        }
        if (argc - i < 2 || argc - i > 3) bdg::fail("usage: bdg-probe [--gate name] [--ready name] read|copy|map|metadata|write|delete|rename|hardlink|truncate|truncate-zero|max-allowed|hold-read|hold-map file [destination]", ERROR_INVALID_PARAMETER);
        Gate gate(gateName, readyName);
        return operation(argv[i], argv[i + 1], argc - i == 3 ? argv[i + 2] : L"", gate);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        /* fail() includes the exact Win32 error; API denied opens are distinct from other errors. */
        return std::string(error.what()).find("(error 5)") != std::string::npos ? 2 : 1;
    }
}
