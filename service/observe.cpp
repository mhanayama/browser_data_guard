#include "observe.hpp"
#include "event_log.hpp"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <objbase.h>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <algorithm>

namespace bdg {
namespace {
// Microsoft-Windows-Kernel-File, manifest decoded by TDH; no private kernel structures.
const GUID provider{0xedd08927,0x9cc4,0x4e65,{0xb9,0x70,0xc2,0x56,0x0f,0xb5,0xc2,0x89}};
struct Rule { std::wstring app, category, path; bool subtree; };
std::wstring wide(const std::string& text) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!n) fail("policy UTF-8", ERROR_INVALID_DATA);
    std::wstring result(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), n);
    return result;
}
std::wstring lower(std::wstring text) {
    if (!text.empty()) CharLowerBuffW(text.data(), static_cast<DWORD>(text.size()));
    return text;
}
std::wstring devicePath(std::wstring path) {
    if (path.size() < 3 || path[1] != L':' || path[2] != L'\\' || path.find(L':', 2) != std::wstring::npos)
        fail("policy requires local DOS paths", ERROR_INVALID_DATA);
    WCHAR volume[32768]{};
    if (!QueryDosDeviceW(path.substr(0, 2).c_str(), volume, _countof(volume))) fail("QueryDosDevice");
    path = std::wstring(volume) + path.substr(2);
    while (path.size() > 1 && path.back() == L'\\') path.pop_back();
    return lower(path);
}
std::vector<Rule> loadRules(const std::wstring& file) {
    if (std::filesystem::file_size(file) > 4 * 1024 * 1024) fail("policy too large", ERROR_INVALID_DATA);
    std::ifstream input{std::filesystem::path(file), std::ios::binary};
    std::string line;
    if (!std::getline(input, line) || line != "BDG-OBSERVE-1") fail("invalid observe policy", ERROR_INVALID_DATA);
    std::vector<Rule> rules;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream row(line);
        std::string kind, app, category, path;
        if (!std::getline(row, kind, '\t') || !std::getline(row, app, '\t') ||
            !std::getline(row, category, '\t') || !std::getline(row, path) || (kind != "file" && kind != "tree") ||
            path.empty() || path.size() > 32768 || path.find('\t') != std::string::npos || rules.size() >= 4096)
            fail("invalid observe rule", ERROR_INVALID_DATA);
        rules.push_back({wide(app), wide(category), devicePath(wide(path)), kind == "tree"});
    }
    if (rules.empty() || !input.eof()) fail("empty or unreadable observe policy", ERROR_INVALID_DATA);
    return rules;
}
struct Identity { DWORD pid = 0; std::wstring image; };
Identity identify(DWORD tid, ULONGLONG when) {
    Handle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
    if (!thread) return {};
    DWORD pid = GetProcessIdOfThread(thread.value);
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process) return {};
    FILETIME born{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process.value, &born, &exit, &kernel, &user)) return {};
    ULONGLONG creation = (static_cast<ULONGLONG>(born.dwHighDateTime) << 32) | born.dwLowDateTime;
    if (creation > when) return {}; // Never attribute an older event to a recycled process.
    WCHAR image[32768]{}; DWORD size = _countof(image);
    if (!QueryFullProcessImageNameW(process.value, 0, image, &size)) return {};
    return {pid, std::wstring(image, size)};
}
struct Aggregate {
    size_t rule = 0; USHORT operation = 0; std::wstring target;
    ULONGLONG when = 0, count = 0, bytes = 0; Identity identity;
};
using AggregateKey = std::tuple<size_t,DWORD,USHORT,std::wstring>;
struct Monitor {
    std::vector<Rule> rules;
    std::unordered_map<ULONGLONG, std::pair<size_t,std::wstring>> objects, keys;
    std::map<AggregateKey, Aggregate> pending;
    std::mutex lock;
    std::atomic<ULONGLONG> received{0}, decoded{0}, matched{0}, unmapped{0}, dropped{0}, decodeErrors{0};
    std::atomic<bool> failed{false};
    static std::vector<BYTE> property(EVENT_RECORD* event, const wchar_t* name) {
        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name); descriptor.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        if (TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size > 65536) return {};
        std::vector<BYTE> bytes(size);
        if (TdhGetProperty(event, 0, nullptr, 1, &descriptor, size, bytes.data()) != ERROR_SUCCESS) return {};
        return bytes;
    }
    static ULONGLONG number(EVENT_RECORD* event, const wchar_t* name) {
        auto bytes = property(event, name); ULONGLONG value = 0;
        if (bytes.size() != 4 && bytes.size() != 8) return 0;
        memcpy(&value, bytes.data(), bytes.size()); return value;
    }
    static std::wstring text(EVENT_RECORD* event, const wchar_t* name) {
        auto bytes = property(event, name);
        if (bytes.size() < 2 || bytes.size() % 2) return {};
        std::wstring value(bytes.size() / 2, L'\0'); memcpy(value.data(), bytes.data(), bytes.size());
        auto end = value.find(L'\0'); if (end != std::wstring::npos) value.resize(end);
        return value;
    }
    std::optional<size_t> match(const std::wstring& path) const {
        for (size_t i = 0; i < rules.size(); ++i) {
            const auto& rule = rules[i];
            if (path == rule.path || (path.size() > rule.path.size() && path.compare(0, rule.path.size(), rule.path) == 0 &&
                (path[rule.path.size()] == L':' || (rule.subtree && path[rule.path.size()] == L'\\')))) return i;
        }
        return {};
    }
    void event(EVENT_RECORD* event) {
        if (!IsEqualGUID(event->EventHeader.ProviderId, provider)) return;
        ++received;
        USHORT id = event->EventHeader.EventDescriptor.Id;
        if (id != 10 && id != 11 && id != 12 && id != 14 && id != 15 && id != 16 && id != 30) return;
        std::lock_guard guard(lock);
        if (id == 10 || id == 11) {
            auto key = number(event, L"FileKey");
            auto name = lower(text(event, L"FileName"));
            if (!key || name.empty()) { ++decodeErrors; return; }
            keys.erase(key);
            if (auto rule = match(name)) {
                if (keys.size() >= 16384) { keys.clear(); ++dropped; }
                keys[key] = {*rule, name};
            }
            ++decoded; return;
        }
        auto object = number(event, L"FileObject");
        if (id == 14) { if (object) objects.erase(object); return; } // Close frees this object identity.
        std::optional<std::pair<size_t,std::wstring>> target;
        if (id == 12 || id == 30) {
            auto name = lower(text(event, L"FileName"));
            if (object) objects.erase(object); // Clear old state on pointer reuse, including non-target creates.
            if (name.empty()) { ++decodeErrors; return; }
            if (auto rule = match(name)) {
                target = std::pair{*rule, name};
                if (objects.size() >= 16384) { objects.clear(); ++dropped; }
                if (object) objects[object] = *target;
            }
        } else if (id == 15 || id == 16) {
            if (!object) { ++decodeErrors; return; }
            auto found = objects.find(object);
            if (found != objects.end()) target = found->second;
            else {
                auto key = keys.find(number(event, L"FileKey"));
                if (key != keys.end()) target = key->second;
                else ++unmapped;
            }
        } else return;
        ++decoded;
        if (!target) return;
        ++matched;
        auto tid = static_cast<DWORD>(number(event, L"IssuingThreadId"));
        if (!tid) tid = static_cast<DWORD>(number(event, L"ThreadId"));
        if (pending.size() >= 4096) { ++dropped; return; }
        auto key = std::tuple{target->first, tid, id, target->second};
        auto& row = pending[key];
        auto when = static_cast<ULONGLONG>(event->EventHeader.TimeStamp.QuadPart);
        if (!row.count) { row.rule = target->first; row.operation = id; row.target = target->second; row.identity = identify(tid, when); }
        row.when = when; ++row.count;
        if (id == 15 || id == 16) row.bytes += number(event, L"IOSize");
    }
    static void WINAPI callback(EVENT_RECORD* record) noexcept {
        auto& monitor = *static_cast<Monitor*>(record->UserContext);
        try { monitor.event(record); }
        catch (...) { monitor.failed = true; }
    }
};
struct Session {
    TRACEHANDLE handle = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
    std::wstring name; std::vector<BYTE> buffer;
    std::thread thread; std::atomic<ULONG> result{ERROR_SUCCESS};
    std::atomic<bool> finished{false};
    EVENT_TRACE_PROPERTIES* properties() { return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data()); }
    Session() : buffer(sizeof(EVENT_TRACE_PROPERTIES) + 2048) {
        GUID guid{}; if (FAILED(CoCreateGuid(&guid))) fail("CoCreateGuid", ERROR_GEN_FAILURE);
        WCHAR formatted[40]{}; StringFromGUID2(guid, formatted, _countof(formatted));
        name = L"BDG-Observe-" + std::wstring(formatted);
        auto p = properties(); p->Wnode.BufferSize = static_cast<ULONG>(buffer.size());
        p->Wnode.Guid = guid; p->Wnode.ClientContext = 2; p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); p->BufferSize = 64;
        p->MinimumBuffers = 8; p->MaximumBuffers = 64; p->FlushTimer = 1;
        ULONG status = StartTraceW(&handle, name.c_str(), p);
        if (status) { handle = 0; fail("StartTrace observation", status); }
    }
    void start(Monitor& monitor) {
        EVENT_TRACE_LOGFILEW logfile{}; logfile.LoggerName = name.data();
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = Monitor::callback; logfile.Context = &monitor;
        consumer = OpenTraceW(&logfile);
        if (consumer == INVALID_PROCESSTRACE_HANDLE) fail("OpenTrace observation");
        thread = std::thread([this] { result = ProcessTrace(&consumer, 1, nullptr, nullptr); finished = true; });
        // Filename + all lifecycle + create + read + write. Never captures file contents or stacks.
        ULONG status = EnableTraceEx2(handle, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
            0x3B0, 0, 0, nullptr);
        if (status) fail("EnableTraceEx2 Kernel-File", status);
    }
    ~Session() {
        if (handle) ControlTraceW(handle, name.c_str(), properties(), EVENT_TRACE_CONTROL_STOP);
        if (consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(consumer);
        if (thread.joinable()) thread.join();
    }
};
}

void observeFiles(const std::wstring& policy, const std::wstring& logPath, HANDLE stop,
                  DWORD seconds, const std::function<void()>& ready) {
    Monitor monitor; monitor.rules = loadRules(policy);
    EventLog windowsLog;
    std::ofstream log; log.exceptions(std::ios::failbit | std::ios::badbit);
    auto open = [&] { log.open(std::filesystem::path(logPath), std::ios::binary | std::ios::app); };
    open();
    Session session; session.start(monitor);
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) fail("GetProcessTimes");
    ULONGLONG birth = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    ULONGLONG started = GetTickCount64(), next = 0, sequence = 0;
    ready();
    windowsLog.write(BDG_EVENT_STATUS, EVENTLOG_INFORMATION_TYPE, L"ETW observation started. No enforcement. Rules: " + std::to_wstring(monitor.rules.size()));
    ULONGLONG lastLoss = 0;
    while (WaitForSingleObject(stop, 200) == WAIT_TIMEOUT) {
        if (monitor.failed || session.finished) fail("ETW consumer stopped", ERROR_GEN_FAILURE);
        auto p = session.properties();
        ULONG status = ControlTraceW(session.handle, session.name.c_str(), p, EVENT_TRACE_CONTROL_QUERY);
        if (status) fail("ETW session health query", status);
        if (GetTickCount64() >= next) {
            if (std::filesystem::file_size(logPath) >= 8 * 1024 * 1024) {
                log.close();
                auto previous = logPath + L".1";
                if (!MoveFileExW(logPath.c_str(), previous.c_str(), MOVEFILE_REPLACE_EXISTING)) fail("rotate observation log");
                open();
            }
            FILETIME now{}; GetSystemTimeAsFileTime(&now);
            ULONGLONG ticks = (static_cast<ULONGLONG>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
            ULONGLONG loss = p->EventsLost + p->RealTimeBuffersLost + monitor.dropped.load();
            if (loss != lastLoss) {
                windowsLog.write(BDG_EVENT_AUDIT_LOSS, EVENTLOG_WARNING_TYPE, L"Missing audit/correlation data: " + std::to_wstring(loss));
                lastLoss = loss;
            }
            log << "{\"type\":\"heartbeat\",\"mode\":\"observe-etw\",\"armed\":false,\"observing\":true,\"timestamp\":\"" << timestamp(ticks)
                << "\",\"servicePid\":" << GetCurrentProcessId() << ",\"serviceStart\":" << birth
                << ",\"ruleCount\":" << monitor.rules.size() << ",\"eventsReceived\":" << monitor.received.load()
                << ",\"eventsDecoded\":" << monitor.decoded.load() << ",\"eventsMatched\":" << monitor.matched.load()
                << ",\"unmappedReadsWrites\":" << monitor.unmapped.load() << ",\"decodeErrors\":" << monitor.decodeErrors.load()
                << ",\"lostEvents\":" << loss << "}\n";
            std::map<AggregateKey, Aggregate> batch;
            { std::lock_guard guard(monitor.lock); batch.swap(monitor.pending); }
            for (const auto& [key, row] : batch) {
                UNREFERENCED_PARAMETER(key);
                const auto& rule = monitor.rules[row.rule];
                auto image = row.identity.image;
                log << "{\"type\":\"access\",\"source\":\"etw\",\"decision\":\"observe\",\"timestamp\":\"" << timestamp(row.when)
                    << "\",\"sequence\":" << ++sequence << ",\"pid\":" << row.identity.pid
                    << ",\"processName\":" << json(image.empty() ? L"不明" : std::filesystem::path(image).filename().wstring())
                    << ",\"executablePath\":" << json(image) << ",\"target\":" << json(row.target)
                    << ",\"browser\":" << json(rule.app) << ",\"category\":" << json(rule.category)
                    << ",\"operation\":\"" << (row.operation == 15 ? "read" : row.operation == 16 ? "write" : "open")
                    << "\",\"count\":" << row.count << ",\"requestedBytes\":" << row.bytes
                    << ",\"attribution\":\"best-effort-live-thread\",\"outcome\":\"not-collected\"}\n";
                windowsLog.write(BDG_EVENT_OBSERVED, EVENTLOG_INFORMATION_TYPE,
                    L"Mode: ETW observation only\nApplication: " + rule.app + L"\nCategory: " + rule.category +
                    L"\nProcess (best effort): " + image + L"\nPID: " + std::to_wstring(row.identity.pid) + L"\nTarget: " + row.target +
                    L"\nOperation: " + (row.operation == 15 ? L"read" : row.operation == 16 ? L"write" : L"open") +
                    L"\nRequests: " + std::to_wstring(row.count) + L"\nRequested bytes: " + std::to_wstring(row.bytes));
            }
            log.flush(); next = GetTickCount64() + 2000;
        }
        if (seconds && GetTickCount64() - started >= static_cast<ULONGLONG>(seconds) * 1000) break;
    }
    log << "{\"type\":\"stopped\"}\n" << std::flush;
    windowsLog.write(BDG_EVENT_STATUS, EVENTLOG_INFORMATION_TYPE, L"ETW observation stopped.");
}
}
