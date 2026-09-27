#pragma once
// Resolves an event's process index (EventRecordHeader::processIndex) to real
// process info. Populated from Process-rundown/create events the driver emits.

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "pmx/driver/port_client.h"

namespace pmx {

struct ProcInfo {
  uint32_t pid = 0;
  uint32_t parentIndex = 0;
  uint32_t parentId = 0;
  uint32_t sessionId = 0;
  uint64_t createTime = 0;
  std::wstring image;    // full image path
  std::wstring name;     // basename of image
  std::wstring cmdline;  // command line (best-effort)
  std::wstring user;     // token user "DOMAIN\\name" (best-effort; "" if unknown)
  std::wstring integrity;  // Untrusted/Low/Medium/High/System/Protected ("" if unk)
};

class ProcessTable {
 public:
  // Feed every record; process-rundown/create records update the table, others
  // are ignored. Returns true if this record was a process record consumed.
  bool consume(const RawRecord& r);

  // Resolve an index to process info, or nullptr if unknown yet.
  const ProcInfo* find(uint32_t index) const {
    auto it = byIndex_.find(index);
    return it == byIndex_.end() ? nullptr : &it->second;
  }

  size_t size() const { return byIndex_.size(); }

  // Define an entry directly (e.g. from a .pml file's process table, which
  // already carries the final per-process info).
  void define(uint32_t index, ProcInfo pi) { byIndex_[index] = std::move(pi); }

 private:
  // Resolve a token's user + integrity for `pid` (once per process). SID->name
  // results are cached in sidCache_ so shared SIDs (SYSTEM, the logged-in user)
  // hit LSA only once.
  void resolveToken(uint32_t pid, std::wstring& user, std::wstring& integrity);

  std::unordered_map<uint32_t, ProcInfo> byIndex_;
  std::unordered_map<std::wstring, std::wstring> sidCache_;  // sidString -> name
};

}  // namespace pmx
