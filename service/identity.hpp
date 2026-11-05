#pragma once
#include "win_util.hpp"

namespace bdg {
struct VerifiedProcess {
    Handle process;
    Handle image; /* retained to deny subsequent write/delete opens of the verified image */
    std::wstring path;
    bool signatureValid;
};
VerifiedProcess verifyProcess(DWORD pid, const std::wstring& expectedImage,
    const std::wstring& expectedSha256, const std::wstring& expectedOwnerSid, bool unsignedLab);
}
