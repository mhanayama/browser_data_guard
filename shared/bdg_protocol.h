#pragma once
/* Fixed x64 ABI, usable from WDK C and user-mode C++. No embedded pointers. */
typedef unsigned int BDG_U32;
typedef unsigned long long BDG_U64;
typedef unsigned short BDG_CHAR;
#define BDG_VERSION 1u
#define BDG_PATH_CHARS 512u
#define BDG_QUEUE_CAPACITY 64u
#define BDG_PORT_NAME L"\\BdgLabPort"
/* Documented process access right from winnt.h, which must not be included in KM. */
#define BDG_PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define BDG_CMD_STATUS 1u
#define BDG_CMD_TRUST_PROCESS 2u
#define BDG_CMD_CLEAR_TRUST 3u
#define BDG_CMD_GET_EVENT 4u
#define BDG_DECISION_ALLOW 1u
#define BDG_DECISION_DENY 2u
#define BDG_REASON_POLICY 1u
#define BDG_REASON_NAME_FAILURE 2u
#define BDG_EVENT_TARGET_TRUNCATED 1u
#define BDG_EVENT_IMAGE_TRUNCATED 2u
#define BDG_EVENT_IMAGE_UNAVAILABLE 4u

#pragma pack(push, 8)
typedef struct _BDG_COMMAND {
    BDG_U32 Version;
    BDG_U32 Size;
    BDG_U32 Command;
    BDG_U32 Reserved;
    BDG_U64 ProcessHandle; /* Caller-owned handle; never a PID. */
} BDG_COMMAND;

typedef struct _BDG_EVENT {
    BDG_U64 Sequence;
    BDG_U64 Timestamp; /* UTC FILETIME, 100ns since 1601. */
    BDG_U64 ProcessId; /* Display only; never an authorization key. */
    BDG_U32 Decision;
    BDG_U32 Reason;
    BDG_U32 DesiredAccess;
    BDG_U32 CreateOptions;
    BDG_U32 Flags;
    BDG_U32 Reserved;
    BDG_CHAR Target[BDG_PATH_CHARS];
    BDG_CHAR Image[BDG_PATH_CHARS];
} BDG_EVENT;

typedef struct _BDG_REPLY {
    BDG_U32 Version;
    BDG_U32 Size;
    BDG_U32 Armed;
    BDG_U32 TrustedProcessPresent;
    BDG_U32 EventPresent;
    BDG_U32 Reserved;
    BDG_U64 LostEvents; /* Cumulative, including failed event delivery. */
    BDG_CHAR ProtectedRoot[BDG_PATH_CHARS];
    BDG_EVENT Event;
} BDG_REPLY;
#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(BDG_COMMAND) == 24);
static_assert(sizeof(BDG_EVENT) == 2096);
static_assert(sizeof(BDG_REPLY) == 3152);
static_assert(sizeof(wchar_t) == sizeof(BDG_CHAR), "Windows UTF-16 ABI required");
#endif
