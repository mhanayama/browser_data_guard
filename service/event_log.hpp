#pragma once
#include "win_util.hpp"
#include "BdgEvents.h"

namespace bdg {
class EventLog {
    HANDLE source_ = nullptr;
public:
    EventLog() {
        source_ = RegisterEventSourceW(nullptr, L"BrowserDataGuard");
        if (!source_) fail("RegisterEventSource");
    }
    ~EventLog() { if (source_) DeregisterEventSource(source_); }
    EventLog(const EventLog&) = delete;
    EventLog& operator=(const EventLog&) = delete;
    void write(DWORD id, WORD type, std::wstring text) {
        if (text.size() > 16000) { text.resize(16000); text += L"\n[metadata truncated]"; }
        LPCWSTR strings[] = {text.c_str()};
        if (!ReportEventW(source_, type, 0, id, nullptr, 1, 0, strings, nullptr)) fail("ReportEvent");
    }
};
}
