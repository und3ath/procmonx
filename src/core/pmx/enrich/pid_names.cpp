#include "pmx/enrich/pid_names.h"

#include <windows.h>

namespace pmx {

namespace {
constexpr uint64_t kRetryInterval = 10'000'000ull;  // 1 s in FILETIME units

uint64_t fileTimeNow() {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

uint64_t toU64(const FILETIME& ft) {
  return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}
}  // namespace

PidNameCache::~PidNameCache() {
  for (auto& [pid, e] : map_) release(e);
}

void PidNameCache::release(Entry& e) {
  if (e.handle) {
    CloseHandle(static_cast<HANDLE>(e.handle));
    e.handle = nullptr;
  }
}

bool PidNameCache::resolve(uint32_t pid, Entry& e) {
  e = Entry{};
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                         pid);
  // A process object can outlive its process briefly (other handles still
  // open): OpenProcess then succeeds on a dead process whose image name no
  // longer resolves. That is not a new owner of the PID - treat as unresolved.
  if (h && WaitForSingleObject(h, 0) != WAIT_TIMEOUT) {
    CloseHandle(h);
    h = nullptr;
  }
  if (!h) {
    e.name = L"PID " + std::to_wstring(pid);
    return false;
  }
  wchar_t buf[MAX_PATH];
  DWORD n = MAX_PATH;
  if (QueryFullProcessImageNameW(h, 0, buf, &n) && n) {
    std::wstring full(buf, n);
    const size_t s = full.find_last_of(L"\\/");
    e.name = s == std::wstring::npos ? full : full.substr(s + 1);
  } else {
    e.name = L"PID " + std::to_wstring(pid);
  }
  e.handle = h;  // keep it: pins the PID and signals exit
  e.resolved = true;
  return true;
}

void PidNameCache::noteExitIfDone(Entry& e) {
  if (!e.handle ||
      WaitForSingleObject(static_cast<HANDLE>(e.handle), 0) == WAIT_TIMEOUT)
    return;
  FILETIME c, x, k, u;
  e.exitTime = GetProcessTimes(static_cast<HANDLE>(e.handle), &c, &x, &k, &u)
                   ? toU64(x)
                   : fileTimeNow();
  release(e);
}

void PidNameCache::sweep() {
  for (auto& [pid, e] : map_) noteExitIfDone(e);
}

const std::wstring& PidNameCache::lookup(uint32_t pid, uint64_t eventTime) {
  static const std::wstring kIdle = L"Idle", kSystem = L"System";
  if (pid == 0) return kIdle;
  if (pid == 4) return kSystem;
  const uint64_t t = eventTime ? eventTime : fileTimeNow();
  const uint64_t now = GetTickCount64();
  if (now - lastSweep_ >= 10000) {
    lastSweep_ = now;
    sweep();
  }

  auto it = map_.find(pid);
  if (it == map_.end()) {
    Entry e;
    if (!resolve(pid, e)) e.retryAfter = t + kRetryInterval;
    return map_.emplace(pid, std::move(e)).first->second.name;
  }
  Entry& e = it->second;

  // Still running: the handle pins the PID, so the name is valid. Exited:
  // remember when, then drop the handle so the PID can be reused.
  noteExitIfDone(e);
  if (e.handle) return e.name;

  // Late event from the instance we cached (stamped before it exited).
  if (e.exitTime && t <= e.exitTime) return e.name;
  // Unresolvable before, and too soon to retry.
  if (!e.exitTime && !e.resolved && t < e.retryAfter) return e.name;

  // The PID may belong to a new process now: re-resolve.
  Entry fresh;
  if (resolve(pid, fresh)) {
    e = std::move(fresh);
  } else if (!e.resolved) {
    e.retryAfter = t + kRetryInterval;  // still nothing there; back off
  } else {
    // Old instance gone and nothing new holds the PID: keep its name (the
    // event is most likely a straggler), but retry later.
    e.retryAfter = t + kRetryInterval;
    e.resolved = false;
    e.exitTime = 0;
  }
  return e.name;
}

}  // namespace pmx
