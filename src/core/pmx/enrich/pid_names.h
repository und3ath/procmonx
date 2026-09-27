#pragma once
// PID -> image base name for sources that only carry an OS pid (ETW network
// events). The driver's ProcessTable is keyed by Procmon's process index, so it
// can't serve these.
//
// Staleness: Windows reuses PIDs. Each cached entry holds a handle to the
// process, which (a) pins the PID - it cannot be reused while any handle to the
// process object is open - and (b) tells us when the process exited. Once it
// has exited, an event stamped before the exit still belongs to the old
// instance (ETW delivers late); an event stamped after it re-resolves the PID.
// Single-threaded: use one instance per consuming thread.

#include <cstdint>
#include <string>
#include <unordered_map>

namespace pmx {

class PidNameCache {
 public:
  PidNameCache() = default;
  PidNameCache(const PidNameCache&) = delete;
  PidNameCache& operator=(const PidNameCache&) = delete;
  ~PidNameCache();

  // Name for `pid` as of `eventTime` (FILETIME, 100ns UTC; 0 = "now").
  // Falls back to "Idle"/"System" for 0/4, else "PID N" when unresolvable.
  const std::wstring& lookup(uint32_t pid, uint64_t eventTime);

  size_t size() const noexcept { return map_.size(); }

 private:
  struct Entry {
    std::wstring name;
    void* handle = nullptr;    // HANDLE (QUERY_LIMITED | SYNCHRONIZE), or null
    uint64_t exitTime = 0;     // FILETIME once the process is known to have exited
    uint64_t retryAfter = 0;   // unresolved: don't retry OpenProcess before this
    bool resolved = false;     // name came from the live process (not a fallback)
  };
  // Open + name the process currently holding `pid`. Returns false if none can
  // be opened; `e` then carries only the fallback name.
  static bool resolve(uint32_t pid, Entry& e);
  static void release(Entry& e);

  std::unordered_map<uint32_t, Entry> map_;
};

}  // namespace pmx
