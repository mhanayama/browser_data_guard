#pragma once
#include "bdg_protocol.h"

/* Values are Windows ACCESS_MASK / create-options values. No CRT or WDK needed. */
static __inline int BdgSensitiveCreate(BDG_U32 access, BDG_U32 options)
{
    const BDG_U32 sensitive = 0xF30D017Fu; /* data/EA/execute/mutation/security/generic/MAXIMUM_ALLOWED */
    return (access & sensitive) != 0 || (options & 0x00001000u) != 0 ||
           ((options >> 24) & 0xffu) != 1u; /* Only FILE_OPEN is non-mutating. */
}

static __inline int BdgPathBoundary(BDG_U32 rootChars, BDG_U32 pathChars, BDG_CHAR next)
{
    return pathChars == rootChars || (pathChars > rootChars && (next == '\\' || next == ':'));
}

static __inline BDG_CHAR BdgAsciiFold(BDG_CHAR c)
{
    return c >= 'A' && c <= 'Z' ? (BDG_CHAR)(c + ('a' - 'A')) : c;
}

/* Deliberately accepts only a volume-root lab path, never live browser paths. */
static __inline BDG_U32 BdgValidateLabRoot(const BDG_CHAR* path, BDG_U32 chars)
{
    const char prefix[] = "\\Device\\HarddiskVolume";
    const char suffix[] = "\\BDG-Lab\\Protected";
    BDG_U32 i, volumeEnd;
    if (chars < sizeof(prefix) + sizeof(suffix) - 1 || chars >= BDG_PATH_CHARS) return 0;
    for (i = 0; i < sizeof(prefix) - 1; ++i)
        if (BdgAsciiFold(path[i]) != BdgAsciiFold((BDG_CHAR)prefix[i])) return 0;
    volumeEnd = i;
    while (i < chars && path[i] >= '0' && path[i] <= '9') ++i;
    if (i == volumeEnd) return 0;
    volumeEnd = i;
    if (chars - i != sizeof(suffix) - 1) return 0;
    for (i = 0; i < sizeof(suffix) - 1; ++i)
        if (BdgAsciiFold(path[volumeEnd + i]) != BdgAsciiFold((BDG_CHAR)suffix[i])) return 0;
    return volumeEnd;
}

static __inline int BdgValidCommand(const BDG_COMMAND* command)
{
    return command->Version == BDG_VERSION && command->Size == sizeof(BDG_COMMAND) &&
        command->Reserved == 0 && command->Command >= BDG_CMD_STATUS &&
        command->Command <= BDG_CMD_GET_EVENT &&
        (command->Command == BDG_CMD_TRUST_PROCESS ? command->ProcessHandle != 0 :
                                                  command->ProcessHandle == 0);
}
