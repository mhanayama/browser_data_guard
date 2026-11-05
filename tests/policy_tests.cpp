#include "../shared/bdg_policy.h"
#include <iostream>
#include <string>
#include <vector>

namespace {
unsigned checks = 0;
void check(bool value, const char* label) {
    ++checks;
    if (!value) { std::cerr << "FAIL: " << label << '\n'; std::exit(1); }
}
BDG_U32 root(const std::wstring& path) {
    std::vector<BDG_CHAR> chars(path.begin(), path.end());
    return BdgValidateLabRoot(chars.data(), static_cast<BDG_U32>(chars.size()));
}
}
int main() {
    constexpr BDG_U32 open = 0x01000000;
    for (auto right : {1u, 2u, 4u, 8u, 16u, 32u, 64u, 256u, 0x10000u, 0x40000u, 0x80000u,
                      0x1000000u, 0x2000000u, 0x10000000u, 0x20000000u, 0x40000000u, 0x80000000u})
        check(BdgSensitiveCreate(right, open) != 0, "sensitive right must be intercepted");
    for (auto right : {0u, 0x80u, 0x20000u, 0x100000u, 0x120080u})
        check(!BdgSensitiveCreate(right, open), "metadata-only FILE_OPEN");
    for (unsigned disposition : {0u, 2u, 3u, 4u, 5u, 255u})
        check(BdgSensitiveCreate(0, disposition << 24) != 0, "mutating/unknown disposition with zero access");
    check(BdgSensitiveCreate(0, open | 0x1000) != 0, "delete on close with zero access");
    check(BdgSensitiveCreate(1, open | 0x4000) != 0, "backup intent does not exempt reads");
    check(BdgPathBoundary(10, 10, 0) != 0, "root itself");
    check(BdgPathBoundary(10, 15, '\\') != 0, "child");
    check(BdgPathBoundary(10, 15, ':') != 0, "alternate stream");
    check(!BdgPathBoundary(10, 15, 'X'), "sibling prefix is not protected");
    check(!BdgPathBoundary(10, 9, 0), "shorter path");
    check(root(L"\\Device\\HarddiskVolume3\\BDG-Lab\\Protected") != 0, "canonical lab root");
    check(root(L"\\device\\harddiskvolume123\\bdg-lab\\protected") != 0, "ASCII case folding");
    for (const auto* invalid : {L"C:\\BDG-Lab\\Protected", L"\\Device\\HarddiskVolume\\BDG-Lab\\Protected",
        L"\\Device\\HarddiskVolume3\\Users\\a\\BDG-Lab\\Protected", L"\\Device\\HarddiskVolume3\\BDG-Lab\\Protected\\",
        L"\\Device\\HarddiskVolume3\\BDG-Lab\\ProtectedX", L"\\Device\\HarddiskVolume3\\BDG-Lab\\Protected:stream",
        L"\\Device\\HarddiskVolumeShadowCopy3\\BDG-Lab\\Protected", L"\\Device\\HarddiskVolume3\\Users\\a\\Cookies", L""})
        check(!root(invalid), "reject non-lab/ambiguous root");
    check(!root(std::wstring(512, L'x')), "reject overlength root");
    BDG_COMMAND command{BDG_VERSION, sizeof(BDG_COMMAND), BDG_CMD_STATUS, 0, 0};
    check(BdgValidCommand(&command) != 0, "valid status");
    command.ProcessHandle = 1;
    check(!BdgValidCommand(&command), "unexpected handle");
    command.Command = BDG_CMD_TRUST_PROCESS;
    check(BdgValidCommand(&command) != 0, "valid trust");
    command.ProcessHandle = 0;
    check(!BdgValidCommand(&command), "empty trust handle");
    command.Command = BDG_CMD_GET_EVENT;
    command.Version++;
    check(!BdgValidCommand(&command), "version mismatch");
    command.Version = BDG_VERSION;
    command.Size--;
    check(!BdgValidCommand(&command), "size mismatch");
    command.Size = sizeof(command);
    command.Reserved = 1;
    check(!BdgValidCommand(&command), "reserved bits");
    command.Reserved = 0;
    command.Command = 99;
    check(!BdgValidCommand(&command), "unknown command");
    std::cout << checks << " policy assertions passed (not a driver runtime test)\n";
}
