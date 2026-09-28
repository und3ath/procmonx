#pragma once
// External-sort spool: buffers decoded events in RAM up to a byte budget, then
// spills a sorted run to a temp file and clears the buffer. drain() replays
// every event in (timestamp, sequence) order via a k-way merge of the spilled
// runs plus whatever is still buffered - so a long `pmx live` capture doesn't
// need to hold every decoded Event (with all its owned wstrings) in memory
// just to sort and write it once at the end.
//
// Spilling is double-buffered and happens on a background worker thread: when
// the active buffer fills, add() hands it off to the worker and keeps writing
// into a second buffer, so a `pmx live` capture (whose add() runs inside the
// same lock as the driver/ETW threads) doesn't stall for the whole
// stable_sort + file write. If the worker is still writing the previous run
// when the next buffer fills, add() blocks until it's done (memory never
// exceeds two buffers' worth).

#include <windows.h>

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "pmx/event.h"

namespace pmx {

struct SpoolOptions {
  // Total RAM budget; split across two buffers so capture continues while a
  // run is written (each buffer spills at bufferBytes/2).
  size_t bufferBytes = size_t{256} << 20;
  std::wstring dir;                         // temp dir for run files; empty = GetTempPathW
};

class EventSpool {
 public:
  explicit EventSpool(SpoolOptions opt);
  ~EventSpool();
  EventSpool(const EventSpool&) = delete;
  EventSpool& operator=(const EventSpool&) = delete;

  // `tag` is caller-defined (pmx uses bit0 = "passed the live filters") and is
  // handed back unchanged from drain(). Returns a sticky error if a previous
  // background spill failed (see below).
  std::error_code add(const Event& ev, uint8_t tag);

  uint64_t count() const;
  // Number of runs spilled so far; may include one currently being written
  // by the background worker (its handle isn't usable until that finishes -
  // drain() waits for it, so drain() always sees every run complete).
  size_t runs() const;
  uint64_t spilledBytes() const;

  // Fired from add()'s thread at handoff time (i.e. when the active buffer
  // fills and is handed to the worker), not from the worker thread - so
  // callers can print/log from their own thread without extra locking.
  std::function<void(size_t runIndex, uint64_t eventsInRun)> onSpill;

  // Delivers every event in (timestamp, sequence) order; ties keep arrival
  // order (matches a std::stable_sort of the original insertion sequence).
  // Waits for any in-flight background spill first. If a spill failed, the
  // other events are still delivered and that error is returned at the end.
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
  struct Buffer {
    std::string buf;
    std::vector<Key> keys;  // arrival order
  };
  struct SpillResult {
    HANDLE handle = INVALID_HANDLE_VALUE;
    uint64_t events = 0;
    uint64_t bytes = 0;
  };

  // Hands the active buffer to the worker (waiting for it to be free first)
  // and switches add() onto the other buffer. Fires onSpill.
  std::error_code handoff();
  // Runs on worker_: waits for handoff() to post work, sorts + writes it,
  // records the result, and loops. Exits once shutdown_ is set and idle.
  void workerMain();
  // stable_sort + write b's records to a fresh run file. Touches no shared
  // state, so it runs on the worker thread without the lock.
  std::error_code spillBuffer(Buffer& b, size_t runIndex, SpillResult& out) const;

  SpoolOptions opt_;
  size_t halfBudget_;

  Buffer buffers_[2];
  int activeIdx_ = 0;  // only touched by the add()-calling thread

  mutable std::mutex mx_;
  std::condition_variable cv_;
  std::thread worker_;
  bool workerStarted_ = false;
  bool workReady_ = false;  // a buffer is waiting for the worker to start on
  bool busy_ = false;       // worker owns buffers_[workBufIdx_] right now
  bool shutdown_ = false;
  int workBufIdx_ = -1;
  size_t workRunIndex_ = 0;

  uint64_t count_ = 0;  // add()-thread only
  std::vector<RunFile> runFiles_;  // size grows in handoff(); elements filled by worker
  uint64_t spilledBytes_ = 0;
  std::error_code stickyErr_;  // first spill error, if any
};

}  // namespace pmx
