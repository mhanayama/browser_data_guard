#include "../service/event_log.hpp"
#include <iostream>

int main() {
    for (DWORD id : {BDG_EVENT_OBSERVED, BDG_EVENT_DENIED, BDG_EVENT_ALLOWED,
                     BDG_EVENT_AUDIT_LOSS, BDG_EVENT_STATUS, BDG_EVENT_ERROR}) {
        WCHAR buffer[32768]{};
        DWORD_PTR insertion[] = {reinterpret_cast<DWORD_PTR>(L"fixture metadata")};
        DWORD count = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ARGUMENT_ARRAY,
            GetModuleHandleW(nullptr), id, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buffer, static_cast<DWORD>(_countof(buffer)),
            reinterpret_cast<va_list*>(insertion));
        if (!count || std::wstring(buffer).find(L"fixture metadata") == std::wstring::npos) {
            std::cerr << "Message resource failed for event " << id << ": " << GetLastError() << '\n'; return 1;
        }
    }
    std::cout << "6 Windows event message resources passed.\n";
    return 0;
}
