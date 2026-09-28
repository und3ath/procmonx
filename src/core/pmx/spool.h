#pragma once
// External-sort spool: buffers decoded events in RAM up to a byte budget, then
// spills a sorted run to a temp file and clears the buffer. drain() replays
// every event in (timestamp, sequence) order via a k-way merge of the spilled
// runs plus whatever is still buffered - so a long `pmx live` capture doesn't
// need to hold every decoded Event (with all its owned wstrings) in memory
// just to sort and write it once at the end.

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <system_error>
#include <vector>

#include "pmx/event.h"

namespace pmx {

struct SpoolOptions {
  size_t bufferBytes = size_t{256} << 20;  // RAM budget before a run spills
  std::wstring dir;                         // temp dir for run files; empty = GetTempPathW
};

class EventSpool {
 public:
  explicit EventSpool(SpoolOptions opt);
  ~EventSpool();
  EventSpool(const EventSpool&) = delete;
  EventSpool& operator=(const EventSpool&) = delete;

  // `tag` is caller-defined (pmx uses bit0 = "passed the live filters") and is
  // handed back unchanged from drain().
  std::error_code add(const Event& ev, uint8_t tag);

  uint64_t count() const { return count_; }
  size_t runs() const { return runFiles_.size(); }
  uint64_t spilledBytes() const { return spilledBytes_; }

  // Fired synchronously from add() when a run spills to disk.
  std::function<void(size_t runIndex, uint64_t eventsInRun)> onSpill;

  // Delivers every event in (timestamp, sequence) order; ties keep arrival
  // order (matches a std::stable_sort of the original insertion sequence).
  // `sink` returning false stops the drain early - already-written output
  // stays valid, just short. Call once.
  std::error_code drain(const std::function<bool(const Event&, uint8_t tag)>& sink);

 private:
  // In-RAM record: [u32 recLen][u8 tag][appendEventRecord bytes], recLen =
  // 1 (tag) + record bytes. `offset` points at the u32 length prefix.
  struct Key {
    uint64_t ts;
    uint32_t seq;
    uint64_t offset;
  };
  struct RunFile {
    HANDLE handle = INVALID_HANDLE_VALUE;  // FILE_FLAG_DELETE_ON_CLOSE: closing == deleting
    uint64_t events = 0;
  };

  std::error_code spill();

  SpoolOptions opt_;
  std::string buf_;
  std::vector<Key> keys_;  // arrival order
  uint64_t count_ = 0;
  std::vector<RunFile> runFiles_;
  uint64_t spilledBytes_ = 0;
};

}  // namespace pmx
