#pragma once
// Request <-> completion pairing.
//
// The driver emits an I/O request as one event (class 1/2/3/6) whose result is
// usually STATUS_PENDING (0x103), then a class-0 "completion" event once the
// operation finishes. The completion carries the final NTSTATUS and the
// IoStatus.Information (bytes transferred, or the CreateFile OpenResult), and its
// `sequence` field equals the originating request's sequence.
//
// This layer buffers pending requests and, when their completion arrives, yields
// a CompletedEvent with the real result + information. Synchronous requests
// (result != STATUS_PENDING) pass straight through.

#include <cstdint>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

#include "pmx/driver/port_client.h"
#include "pmx/driver/protocol.h"

namespace pmx {

// A request event with its completion applied (when one arrived).
struct CompletedEvent {
  proto::EventRecordHeader header;   // the request's header (copy)
  std::vector<uint8_t> detail;       // the request's detail bytes (copy)
  uint32_t finalResult = 0;          // completion NTSTATUS, or the request's own
  uint64_t information = 0;          // IoStatus.Information from the completion
  std::vector<uint8_t> completionDetail;  // full completion detail (kept for RegQueryValue result decode)
  uint64_t completionTime = 0;       // completion timestamp (100ns); 0 if none
  bool completed = false;            // true if a class-0 completion was matched
};

class Pairer {
 public:
  // Pending requests whose completion never arrives (long-lived IRPs such as
  // NotifyChangeDirectory, or completions lost to driver buffer overflow) would
  // otherwise accumulate forever. Past `maxPending`, the OLDEST pending request
  // is evicted unmatched (completed=false) into takeEvicted().
  static constexpr size_t kDefaultMaxPending = size_t{1} << 18;
  explicit Pairer(size_t maxPending = kDefaultMaxPending)
      : maxPending_(maxPending ? maxPending : 1) {}

  // Feed every raw record in stream order. Returns a CompletedEvent to emit when
  // one is ready (a synchronous request, or a request whose completion just
  // arrived), else nullopt (the record was a pending request now buffered, or a
  // completion with no matching request).
  std::optional<CompletedEvent> consume(const RawRecord& r);

  // Requests evicted by the pending cap since the last call (emit them).
  std::vector<CompletedEvent> takeEvicted() {
    std::vector<CompletedEvent> out;
    out.swap(evicted_);
    return out;
  }

  // Emit all still-unmatched pending requests (e.g. at end of capture), each
  // with completed=false and finalResult = the request's own (pending) status.
  std::vector<CompletedEvent> flush();

  size_t pendingCount() const noexcept { return bySeq_.size(); }

 private:
  struct Pending {
    CompletedEvent ev;
    uint64_t arrival;
  };
  void evict(uint32_t seq);

  std::unordered_map<uint32_t, Pending> bySeq_;  // key = request sequence
  // Age order by arrival, not by sequence: the u32 sequence wraps on long
  // captures, after which the smallest sequence is the newest request.
  std::map<uint64_t, uint32_t> byArrival_;
  uint64_t nextArrival_ = 0;
  std::vector<CompletedEvent> evicted_;
  size_t maxPending_;
};

}  // namespace pmx
