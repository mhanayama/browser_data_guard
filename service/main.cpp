#include "identity.hpp"
#include "observe.hpp"
#include "event_log.hpp"
#include "../shared/bdg_policy.h"
#include <fltUser.h>
#include <shellapi.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <limits>

static_assert(BDG_PROCESS_QUERY_LIMITED_INFORMATION == PROCESS_QUERY_LIMITED_INFORMATION);

static_assert((FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA | FILE_WRITE_EA |
    FILE_EXECUTE | FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
    ACCESS_SYSTEM_SECURITY | MAXIMUM_ALLOWED | GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ) == 0xF30D017Fu);

namespace {
struct Options {
    bool service = false, console = false, status = false, unsignedLab = false, observe = false;
    DWORD pid = 0, seconds = 0;
    std::wstring image, hash, owner, log, ntPath, policy;
} options;
HANDLE stopEvent = nullptr;
SERVICE_STATUS_HANDLE serviceHandle = nullptr;
SERVICE_STATUS serviceStatus{};
void report(DWORD state, DWORD error = NO_ERROR);

DWORD number(const std::wstring& text) {
    size_t end = 0;
    auto value = std::stoull(text, &end);
    if (end != text.size() || !value || value > std::numeric_limits<DWORD>::max()) bdg::fail("invalid number", ERROR_INVALID_PARAMETER);
    return static_cast<DWORD>(value);
}
Options parse(int argc, wchar_t** argv) {
    Options result;
    for (int i = 1; i < argc; ++i) {
        std::wstring key = argv[i];
        auto value = [&]() -> std::wstring { if (++i >= argc) bdg::fail("missing argument", ERROR_INVALID_PARAMETER); return argv[i]; };
        if (key == L"--service") result.service = true;
        else if (key == L"--console") result.console = true;
        else if (key == L"--status") result.status = true;
        else if (key == L"--observe") result.observe = true;
        else if (key == L"--policy") result.policy = value();
        else if (key == L"--nt-path") result.ntPath = value();
        else if (key == L"--allow-unsigned-lab") result.unsignedLab = true;
        else if (key == L"--trust-pid") result.pid = number(value());
        else if (key == L"--run-seconds") result.seconds = number(value());
        else if (key == L"--image") result.image = value();
        else if (key == L"--sha256") result.hash = value();
        else if (key == L"--owner-sid") result.owner = value();
        else if (key == L"--log") result.log = value();
        else bdg::fail("unknown argument", ERROR_INVALID_PARAMETER);
    }
    if (static_cast<int>(result.service) + result.console + result.status + !result.ntPath.empty() != 1)
        bdg::fail("choose --console, --service, --status, or --nt-path", ERROR_INVALID_PARAMETER);
    if ((result.console || result.service) && result.log.empty()) bdg::fail("--log is required", ERROR_INVALID_PARAMETER);
    if (!(result.console || result.service) && (result.pid || result.seconds || !result.log.empty()))
        bdg::fail("runtime options require --console or --service", ERROR_INVALID_PARAMETER);
    if (result.pid && (result.image.empty() || result.hash.empty() || result.owner.empty()))
        bdg::fail("trust requires --image, --sha256 and --owner-sid", ERROR_INVALID_PARAMETER);
    if (!result.pid && (!result.image.empty() || !result.hash.empty() || !result.owner.empty() || result.unsignedLab))
        bdg::fail("identity options require --trust-pid", ERROR_INVALID_PARAMETER);
    if (result.observe && (!(result.console || result.service) || result.policy.empty() || result.pid))
        bdg::fail("--observe requires console/service, --policy, and no trust grant", ERROR_INVALID_PARAMETER);
    if (!result.observe && !result.policy.empty()) bdg::fail("--policy requires --observe", ERROR_INVALID_PARAMETER);
    return result;
}

BDG_REPLY send(HANDLE port, BDG_U32 operation, HANDLE process = nullptr) {
    BDG_COMMAND command{BDG_VERSION, sizeof(BDG_COMMAND), operation, 0, reinterpret_cast<BDG_U64>(process)};
    BDG_REPLY reply{};
    DWORD returned = 0;
    HRESULT hr = FilterSendMessage(port, &command, sizeof(command), &reply, sizeof(reply), &returned);
    if (FAILED(hr)) bdg::fail("FilterSendMessage", static_cast<DWORD>(hr));
    if (returned != sizeof(reply) || reply.Version != BDG_VERSION || reply.Size != sizeof(reply) ||
        reply.ProtectedRoot[BDG_PATH_CHARS - 1] != 0 || reply.Event.Target[BDG_PATH_CHARS - 1] != 0 ||
        reply.Event.Image[BDG_PATH_CHARS - 1] != 0) bdg::fail("invalid driver reply", ERROR_INVALID_DATA);
    return reply;
}
bdg::Handle connect() {
    HANDLE raw = nullptr;
    HRESULT hr = FilterConnectCommunicationPort(BDG_PORT_NAME, 0, nullptr, 0, nullptr, &raw);
    if (FAILED(hr)) bdg::fail("FilterConnectCommunicationPort (requires elevation and loaded filter)", static_cast<DWORD>(hr));
    return bdg::Handle(raw);
}
std::wstring path(const BDG_CHAR* data) { return reinterpret_cast<const wchar_t*>(data); }

void run() {
    if (options.observe) {
        bdg::observeFiles(options.policy, options.log, stopEvent, options.seconds, [] { if (options.service) report(SERVICE_RUNNING); });
        return;
    }
    std::ofstream log;
    bdg::EventLog windowsLog;
    log.exceptions(std::ios::failbit | std::ios::badbit);
    log.open(std::filesystem::path(options.log), std::ios::binary | std::ios::app);
    std::optional<bdg::VerifiedProcess> trusted; /* outlives the port and its kernel grant */
    auto port = connect();
    auto state = send(port.value, BDG_CMD_STATUS);
    if (!state.Armed) bdg::fail("driver has no attached protected instance", ERROR_NOT_READY);
    if (options.pid) {
        trusted.emplace(bdg::verifyProcess(options.pid, options.image, options.hash, options.owner, options.unsignedLab));
        state = send(port.value, BDG_CMD_TRUST_PROCESS, trusted->process.value);
    }
    log << "{\"type\":\"status\",\"armed\":true,\"root\":" << bdg::json(path(state.ProtectedRoot))
        << ",\"trusted\":" << (state.TrustedProcessPresent ? "true" : "false")
        << ",\"signatureValid\":" << (trusted && trusted->signatureValid ? "true" : "false")
        << ",\"unsignedLab\":" << (options.unsignedLab ? "true" : "false") << "}\n" << std::flush;
    if (options.service) report(SERVICE_RUNNING);
    windowsLog.write(BDG_EVENT_STATUS, EVENTLOG_INFORMATION_TYPE, L"Lab collector started. Synthetic root only: " + path(state.ProtectedRoot));
    BDG_U64 lost = 0;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) bdg::fail("GetProcessTimes");
    const ULONGLONG serviceStart = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    ULONGLONG nextHeartbeat = 0;
    const ULONGLONG started = GetTickCount64();
    while (WaitForSingleObject(stopEvent, 0) == WAIT_TIMEOUT) {
        state = send(port.value, BDG_CMD_GET_EVENT);
        if (!state.Armed) bdg::fail("protected instance detached or volume dismounted", ERROR_NOT_READY);
        if (GetTickCount64() >= nextHeartbeat) {
            FILETIME now{};
            GetSystemTimeAsFileTime(&now);
            const ULONGLONG ticks = (static_cast<ULONGLONG>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
            log << "{\"type\":\"heartbeat\",\"timestamp\":\"" << bdg::timestamp(ticks)
                << "\",\"mode\":\"synthetic\",\"armed\":true,\"servicePid\":" << GetCurrentProcessId()
                << ",\"serviceStart\":" << serviceStart << "}\n" << std::flush;
            nextHeartbeat = GetTickCount64() + 2000;
        }
        if (state.LostEvents != lost) {
            log << "{\"type\":\"audit_loss\",\"lostEvents\":" << state.LostEvents << "}\n" << std::flush;
            lost = state.LostEvents;
            windowsLog.write(BDG_EVENT_AUDIT_LOSS, EVENTLOG_WARNING_TYPE, L"Lost events: " + std::to_wstring(lost));
        }
        if (state.EventPresent) {
            const auto& event = state.Event;
            const auto image = path(event.Image);
            const auto name = std::filesystem::path(image).filename().wstring();
            log << "{\"type\":\"access\",\"timestamp\":\"" << bdg::timestamp(event.Timestamp)
                << "\",\"sequence\":" << event.Sequence << ",\"pid\":" << event.ProcessId
                << ",\"processName\":" << bdg::json(name) << ",\"executablePath\":" << bdg::json(image)
                << ",\"target\":" << bdg::json(path(event.Target))
                << ",\"browser\":\"Synthetic\",\"category\":\"TestData\",\"decision\":\""
                << (event.Decision == BDG_DECISION_DENY ? "deny" : "allow")
                << "\",\"reason\":" << event.Reason << ",\"desiredAccess\":" << event.DesiredAccess
                << ",\"createOptions\":" << event.CreateOptions << ",\"flags\":" << event.Flags << "}\n" << std::flush;
            windowsLog.write(event.Decision == BDG_DECISION_DENY ? BDG_EVENT_DENIED : BDG_EVENT_ALLOWED,
                event.Decision == BDG_DECISION_DENY ? EVENTLOG_WARNING_TYPE : EVENTLOG_INFORMATION_TYPE,
                L"Mode: synthetic lab\nProcess: " + image + L"\nPID: " + std::to_wstring(event.ProcessId) +
                L"\nTarget: " + path(event.Target) + L"\nReason: " + std::to_wstring(event.Reason) + L"\nFlags: " + std::to_wstring(event.Flags));
        } else {
            WaitForSingleObject(stopEvent, 100);
        }
        if (options.seconds && GetTickCount64() - started >= static_cast<ULONGLONG>(options.seconds) * 1000) break;
    }
    send(port.value, BDG_CMD_CLEAR_TRUST);
    log << "{\"type\":\"stopped\"}\n" << std::flush;
    windowsLog.write(BDG_EVENT_STATUS, EVENTLOG_INFORMATION_TYPE, L"Lab collector stopped.");
    /* Port closes before the retained image/process references on exit or exception. */
}

void report(DWORD state, DWORD error) {
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = state;
    serviceStatus.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    serviceStatus.dwWin32ExitCode = error;
    serviceStatus.dwServiceSpecificExitCode = error == ERROR_SERVICE_SPECIFIC_ERROR ? 1 : 0;
    serviceStatus.dwWaitHint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 5000 : 0;
    SetServiceStatus(serviceHandle, &serviceStatus);
}
void WINAPI control(DWORD code) {
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING);
        SetEvent(stopEvent);
    }
}
void WINAPI serviceMain(DWORD, LPWSTR*) {
    serviceHandle = RegisterServiceCtrlHandlerW(options.observe ? L"BdgMonitor" : L"BdgService", control);
    if (!serviceHandle) return;
    report(SERVICE_START_PENDING);
    try { run(); report(SERVICE_STOPPED); }
    catch (const std::exception& error) {
        try { bdg::EventLog events; events.write(BDG_EVENT_ERROR, EVENTLOG_ERROR_TYPE, std::wstring(error.what(), error.what() + strlen(error.what()))); } catch (...) {}
        report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
    }
    catch (...) { report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR); }
}
BOOL WINAPI consoleControl(DWORD code) {
    if (code == CTRL_C_EVENT || code == CTRL_BREAK_EVENT || code == CTRL_CLOSE_EVENT) {
        SetEvent(stopEvent); return TRUE;
    }
    return FALSE;
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        options = parse(argc, argv);
        if (!options.ntPath.empty()) {
            bdg::Handle directory(CreateFileW(options.ntPath.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (!directory) bdg::fail("open directory for NT path");
            std::wcout << bdg::finalPath(directory.value, VOLUME_NAME_NT) << L'\n';
            return 0;
        }
        if (options.status) {
            auto port = connect();
            auto reply = send(port.value, BDG_CMD_STATUS);
            std::wcout << L"armed=" << reply.Armed << L" trusted=" << reply.TrustedProcessPresent
                       << L" lost=" << reply.LostEvents << L" root=" << path(reply.ProtectedRoot) << L'\n';
            return reply.Armed ? 0 : 2;
        }
        bdg::Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!stop) bdg::fail("CreateEvent");
        stopEvent = stop.value;
        if (options.service) {
            SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(options.observe ? L"BdgMonitor" : L"BdgService"), serviceMain}, {nullptr, nullptr}};
            if (!StartServiceCtrlDispatcherW(table)) bdg::fail("StartServiceCtrlDispatcher");
        } else {
            if (!SetConsoleCtrlHandler(consoleControl, TRUE)) bdg::fail("SetConsoleCtrlHandler");
            run();
            SetConsoleCtrlHandler(consoleControl, FALSE);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BDG: " << error.what() << '\n';
        return 1;
    }
}
