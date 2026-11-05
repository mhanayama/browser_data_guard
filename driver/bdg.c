#include <fltKernel.h>
#include "../shared/bdg_policy.h"

#define BDG_TAG 'gDdB'
typedef struct _BDG_QUEUED_EVENT {
    BDG_EVENT Event;
    PEPROCESS Process;
} BDG_QUEUED_EVENT;

static PFLT_FILTER gFilter;
static PFLT_PORT gServerPort;
static PFLT_PORT gClientPort;
static WCHAR gRootBuffer[BDG_PATH_CHARS];
static UNICODE_STRING gRoot;
static UNICODE_STRING gVolume;
static EX_PUSH_LOCK gTrustLock;
static PEPROCESS gTrusted;
static EX_PUSH_LOCK gQueueLock;
static BDG_QUEUED_EVENT gQueue[BDG_QUEUE_CAPACITY];
static ULONG gHead, gCount;
static ULONGLONG gSequence, gLost;
static volatile LONG gInstances;

DRIVER_INITIALIZE DriverEntry;
C_ASSERT(sizeof(BDG_COMMAND) == 24);
C_ASSERT(sizeof(BDG_EVENT) == 2096);
C_ASSERT(sizeof(BDG_REPLY) == 3152);

/* Name information and command replies may be pageable. Never raise to DISPATCH
   while copying them. All registered entry points here run at <= APC_LEVEL. */
_IRQL_requires_max_(APC_LEVEL)
_Acquires_exclusive_lock_(gQueueLock)
static VOID BdgLockQueue(VOID)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gQueueLock);
}
_IRQL_requires_max_(APC_LEVEL)
_Releases_exclusive_lock_(gQueueLock)
static VOID BdgUnlockQueue(VOID)
{
    ExReleasePushLockExclusive(&gQueueLock);
    KeLeaveCriticalRegion();
}

static VOID BdgReplaceTrust(PEPROCESS process)
{
    PEPROCESS old;
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gTrustLock);
    old = gTrusted;
    gTrusted = process; /* consumes caller's reference */
    ExReleasePushLockExclusive(&gTrustLock);
    KeLeaveCriticalRegion();
    if (old) ObDereferenceObject(old);
}

static BOOLEAN BdgTrusted(PEPROCESS process)
{
    BOOLEAN trusted;
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gTrustLock);
    trusted = process != NULL && process == gTrusted;
    ExReleasePushLockShared(&gTrustLock);
    KeLeaveCriticalRegion();
    return trusted;
}

static VOID BdgCopyPath(BDG_CHAR* target, PCUNICODE_STRING source, BDG_U32* flags, ULONG flag)
{
    USHORT chars = source->Length / sizeof(WCHAR);
    if (chars >= BDG_PATH_CHARS) {
        chars = BDG_PATH_CHARS - 1;
        *flags |= flag;
    }
    RtlCopyMemory(target, source->Buffer, chars * sizeof(WCHAR));
    target[chars] = 0;
}

static VOID BdgRecord(PFLT_CALLBACK_DATA data, PCUNICODE_STRING name, ULONG decision, ULONG reason)
{
    LARGE_INTEGER now;
    PEPROCESS process = FltGetRequestorProcess(data);
    BDG_QUEUED_EVENT* entry;
    KeQuerySystemTimePrecise(&now);
    BdgLockQueue();
    ++gSequence;
    if (gCount == BDG_QUEUE_CAPACITY) {
        ++gLost;
        BdgUnlockQueue();
        return; /* losing audit never grants access */
    }
    entry = &gQueue[(gHead + gCount) % BDG_QUEUE_CAPACITY];
    RtlZeroMemory(entry, sizeof(*entry));
    entry->Process = process;
    if (process) ObReferenceObject(process);
    entry->Event.Sequence = gSequence;
    entry->Event.Timestamp = (ULONGLONG)now.QuadPart;
    entry->Event.ProcessId = process ? (ULONGLONG)(ULONG_PTR)PsGetProcessId(process) : 0;
    entry->Event.Decision = decision;
    entry->Event.Reason = reason;
    entry->Event.DesiredAccess = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    entry->Event.CreateOptions = data->Iopb->Parameters.Create.Options;
    if (name) BdgCopyPath(entry->Event.Target, name, &entry->Event.Flags, BDG_EVENT_TARGET_TRUNCATED);
    ++gCount;
    BdgUnlockQueue();
}

static FLT_PREOP_CALLBACK_STATUS BdgPreCreate(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID* completion)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    NTSTATUS status;
    BOOLEAN protectedPath, trusted;
    ULONG rootChars, pathChars;
    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(completion);

    if (!BdgSensitiveCreate(data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                           data->Iopb->Parameters.Create.Options))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) {
        /* Only the configured NTFS volume is attached. Never silently pass a lookup error. */
        BdgRecord(data, NULL, BDG_DECISION_DENY, BDG_REASON_NAME_FAILURE);
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    rootChars = gRoot.Length / sizeof(WCHAR);
    pathChars = name->Name.Length / sizeof(WCHAR);
    protectedPath = RtlPrefixUnicodeString(&gRoot, &name->Name, TRUE) &&
        BdgPathBoundary(rootChars, pathChars, pathChars > rootChars ? name->Name.Buffer[rootChars] : 0);
    if (!protectedPath) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    trusted = BdgTrusted(FltGetRequestorProcess(data));
    BdgRecord(data, &name->Name, trusted ? BDG_DECISION_ALLOW : BDG_DECISION_DENY, BDG_REASON_POLICY);
    FltReleaseFileNameInformation(name);
    if (trusted) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    data->IoStatus.Status = STATUS_ACCESS_DENIED;
    data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static NTSTATUS BdgInstanceSetup(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_SETUP_FLAGS flags,
                                DEVICE_TYPE deviceType, FLT_FILESYSTEM_TYPE filesystem)
{
    WCHAR buffer[128];
    UNICODE_STRING volume;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(flags);
    if (deviceType != FILE_DEVICE_DISK_FILE_SYSTEM || filesystem != FLT_FSTYPE_NTFS)
        return STATUS_FLT_DO_NOT_ATTACH;
    volume.Buffer = buffer;
    volume.Length = 0;
    volume.MaximumLength = sizeof(buffer);
    status = FltGetVolumeName(objects->Volume, &volume, NULL);
    if (!NT_SUCCESS(status) || !RtlEqualUnicodeString(&volume, &gVolume, TRUE))
        return STATUS_FLT_DO_NOT_ATTACH;
    InterlockedIncrement(&gInstances);
    return STATUS_SUCCESS;
}

static VOID BdgInstanceTeardownStart(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_TEARDOWN_FLAGS flags)
{
    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(flags);
    InterlockedDecrement(&gInstances);
}

static NTSTATUS BdgQueryTeardown(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags)
{
    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(flags);
    return STATUS_FLT_DO_NOT_DETACH; /* use explicit unload for lab recovery */
}

static NTSTATUS BdgConnect(PFLT_PORT port, PVOID serverCookie, PVOID context,
                           ULONG contextSize, PVOID* cookie)
{
    UNREFERENCED_PARAMETER(serverCookie);
    UNREFERENCED_PARAMETER(context);
    if (contextSize != 0) return STATUS_INVALID_PARAMETER;
    gClientPort = port;
    *cookie = PsGetCurrentProcess();
    ObReferenceObject(*cookie);
    return STATUS_SUCCESS;
}

static VOID BdgDisconnect(PVOID cookie)
{
    BdgReplaceTrust(NULL);
    FltCloseClientPort(gFilter, &gClientPort);
    ObDereferenceObject(cookie);
}

static NTSTATUS BdgMessage(PVOID cookie, PVOID input, ULONG inputSize, PVOID output,
                           ULONG outputSize, PULONG returned)
{
    BDG_COMMAND command;
    BDG_REPLY* reply;
    PEPROCESS process = NULL, eventProcess = NULL;
    PUNICODE_STRING image = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    *returned = 0;
    if (PsGetCurrentProcess() != (PEPROCESS)cookie || !input || !output ||
        inputSize != sizeof(command) || outputSize != sizeof(BDG_REPLY)) return STATUS_INVALID_PARAMETER;
    /* User buffers are unlocked and may be unaligned. Capture once under SEH. */
    __try { RtlCopyMemory(&command, input, sizeof(command)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    if (!BdgValidCommand(&command)) return STATUS_INVALID_PARAMETER;
    reply = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*reply), BDG_TAG);
    if (!reply) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(reply, sizeof(*reply));

    if (command.Command == BDG_CMD_TRUST_PROCESS) {
        status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)command.ProcessHandle,
            BDG_PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, UserMode, (PVOID*)&process, NULL);
        if (!NT_SUCCESS(status)) goto done;
        BdgReplaceTrust(process);
    } else if (command.Command == BDG_CMD_CLEAR_TRUST) {
        BdgReplaceTrust(NULL);
    } else if (command.Command == BDG_CMD_GET_EVENT) {
        BdgLockQueue();
        if (gCount) {
            reply->Event = gQueue[gHead].Event;
            eventProcess = gQueue[gHead].Process;
            gQueue[gHead].Process = NULL;
            gHead = (gHead + 1) % BDG_QUEUE_CAPACITY;
            --gCount;
            reply->EventPresent = 1;
        }
        BdgUnlockQueue();
        if (reply->EventPresent) {
            if (eventProcess && NT_SUCCESS(SeLocateProcessImageName(eventProcess, &image))) {
                BdgCopyPath(reply->Event.Image, image, &reply->Event.Flags, BDG_EVENT_IMAGE_TRUNCATED);
                ExFreePool(image);
            } else {
                reply->Event.Flags |= BDG_EVENT_IMAGE_UNAVAILABLE;
            }
        }
        if (eventProcess) ObDereferenceObject(eventProcess);
    }
    reply->Version = BDG_VERSION;
    reply->Size = sizeof(*reply);
    reply->Armed = InterlockedCompareExchange(&gInstances, 0, 0) > 0;
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gTrustLock);
    reply->TrustedProcessPresent = gTrusted != NULL;
    ExReleasePushLockShared(&gTrustLock);
    KeLeaveCriticalRegion();
    BdgLockQueue();
    reply->LostEvents = gLost;
    BdgUnlockQueue();
    RtlCopyMemory(reply->ProtectedRoot, gRootBuffer, gRoot.Length + sizeof(WCHAR));
    __try {
        RtlCopyMemory(output, reply, sizeof(*reply));
        *returned = sizeof(*reply);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (reply->EventPresent) {
            BdgLockQueue();
            ++gLost;
            BdgUnlockQueue();
        }
    }
done:
    ExFreePoolWithTag(reply, BDG_TAG);
    return status;
}

static NTSTATUS BdgReadConfiguration(PUNICODE_STRING registryPath)
{
    HANDLE service = NULL, parameters = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    PKEY_VALUE_PARTIAL_INFORMATION value;
    ULONG bytes, volumeChars;
    NTSTATUS status;
    const ULONG capacity = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(gRootBuffer);
    value = ExAllocatePool2(POOL_FLAG_PAGED, capacity, BDG_TAG);
    if (!value) return STATUS_INSUFFICIENT_RESOURCES;
    InitializeObjectAttributes(&attributes, registryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&service, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) goto done;
    RtlInitUnicodeString(&name, L"Parameters");
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, service, NULL);
    status = ZwOpenKey(&parameters, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) goto done;
    RtlInitUnicodeString(&name, L"SyntheticMode");
    status = ZwQueryValueKey(parameters, &name, KeyValuePartialInformation, value, capacity, &bytes);
    if (!NT_SUCCESS(status)) goto done;
    if (value->Type != REG_DWORD || value->DataLength != sizeof(ULONG) || *(ULONG*)value->Data != 1) {
        status = STATUS_INVALID_PARAMETER; goto done;
    }
    RtlInitUnicodeString(&name, L"ProtectedRoot");
    status = ZwQueryValueKey(parameters, &name, KeyValuePartialInformation, value, capacity, &bytes);
    if (!NT_SUCCESS(status)) goto done;
    if (value->Type != REG_SZ || value->DataLength < 2 * sizeof(WCHAR) ||
        value->DataLength > sizeof(gRootBuffer) || value->DataLength % sizeof(WCHAR) != 0) {
        status = STATUS_INVALID_PARAMETER; goto done;
    }
    RtlCopyMemory(gRootBuffer, value->Data, value->DataLength);
    if (gRootBuffer[value->DataLength / sizeof(WCHAR) - 1] != 0) {
        status = STATUS_INVALID_PARAMETER; goto done;
    }
    RtlInitUnicodeString(&gRoot, gRootBuffer);
    if (gRoot.Length + sizeof(WCHAR) != value->DataLength) {
        status = STATUS_INVALID_PARAMETER; goto done;
    }
    volumeChars = BdgValidateLabRoot((const BDG_CHAR*)gRoot.Buffer, gRoot.Length / sizeof(WCHAR));
    if (!volumeChars) { status = STATUS_INVALID_PARAMETER; goto done; }
    gVolume = gRoot;
    gVolume.Length = (USHORT)(volumeChars * sizeof(WCHAR));
done:
    if (parameters) ZwClose(parameters);
    if (service) ZwClose(service);
    ExFreePoolWithTag(value, BDG_TAG);
    return status;
}

static NTSTATUS BdgUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    ULONG i;
    UNREFERENCED_PARAMETER(flags);
    FltCloseCommunicationPort(gServerPort);
    FltUnregisterFilter(gFilter); /* quiesce callbacks/connections before releasing state */
    BdgReplaceTrust(NULL);
    for (i = 0; i < BDG_QUEUE_CAPACITY; ++i)
        if (gQueue[i].Process) { ObDereferenceObject(gQueue[i].Process); gQueue[i].Process = NULL; }
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION gOperations[] = {
    { IRP_MJ_CREATE, 0, BdgPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};
static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, gOperations,
    BdgUnload, BdgInstanceSetup, BdgQueryTeardown, BdgInstanceTeardownStart, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING port = RTL_CONSTANT_STRING(BDG_PORT_NAME);
    ExInitializePushLock(&gTrustLock);
    ExInitializePushLock(&gQueueLock);
    status = BdgReadConfiguration(registryPath);
    if (!NT_SUCCESS(status)) return status;
    status = FltRegisterFilter(driverObject, &gRegistration, &gFilter);
    if (!NT_SUCCESS(status)) return status;
    status = FltBuildDefaultSecurityDescriptor(&descriptor, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&attributes, &port, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, descriptor);
        status = FltCreateCommunicationPort(gFilter, &gServerPort, &attributes, NULL,
                                           BdgConnect, BdgDisconnect, BdgMessage, 1);
        FltFreeSecurityDescriptor(descriptor);
    }
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(gFilter); return status; }
    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        /* Same teardown path also releases any records created during a partial start. */
        BdgUnload(0);
    }
    return status;
}
