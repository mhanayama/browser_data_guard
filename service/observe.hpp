#pragma once
#include "win_util.hpp"
#include <functional>

namespace bdg {
void observeFiles(const std::wstring& policy, const std::wstring& log, HANDLE stop,
                  DWORD seconds, const std::function<void()>& ready);
}
