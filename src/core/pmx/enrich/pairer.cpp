#include "pmx/enrich/pairer.h"

#include <cstring>

namespace pmx {

void Pairer::evict(uint32_t seq) {
  auto it = bySeq_.find(seq);
  if (it == bySeq_.end()) return;
  byArrival_.erase(it->second.arrival);
  evicted_.push_back(std::move(it->second.ev));
  bySeq_.erase(it);
}

std::optional<CompletedEvent> Pairer::consume(const RawRecord& r) {
  const auto& h = *r.header;

  // Class 0 = completion. Match it to a buffered request by sequence.
  if (h.eventClass == static_cast<uint16_t>(proto::EventClass::System)) {
    auto it = bySeq_.find(h.sequence);
    if (it == bySeq_.end()) return std::nullopt;  // no matching request
    CompletedEvent ev = std::move(it->second.ev);
    byArrival_.erase(it->second.arrival);
    bySeq_.erase(it);
    ev.finalResult = h.result;
    ev.information = 0;
    if (r.detail.size() >= 8)
      std::memcpy(&ev.information, r.detail.data(), 8);
    else if (r.detail.size() >= 4)
      std::memcpy(&ev.information, r.detail.data(), 4);
    ev.completionTime = h.timestamp;
    ev.completed = true;
    if (ev.header.eventClass == static_cast<uint16_t>(proto::EventClass::Registry) &&
        ev.header.operation == 5 && !r.detail.empty())
      ev.completionDetail.assign(r.detail.begin(), r.detail.end());
    return ev;
  }

  // A request event. Copy it (spans point into a transient batch buffer).
  CompletedEvent ev;
  ev.header = h;
  ev.detail.assign(r.detail.begin(), r.detail.end());
  ev.finalResult = h.result;

  // Synchronous completion (already has a final status) — emit immediately.
  if (h.result != proto::kStatusPending) return ev;

  // Pending: buffer until the completion arrives. A stale entry with the same
  // sequence (wraparound / dropped completion) is emitted unmatched, not lost.
  evict(h.sequence);
  const uint64_t arrival = nextArrival_++;
  bySeq_.emplace(h.sequence, Pending{std::move(ev), arrival});
  byArrival_.emplace(arrival, h.sequence);
  while (bySeq_.size() > maxPending_) evict(byArrival_.begin()->second);
  return std::nullopt;
}

std::vector<CompletedEvent> Pairer::flush() {
  std::vector<CompletedEvent> out;
  out.reserve(bySeq_.size());
  for (auto& [arrival, seq] : byArrival_) out.push_back(std::move(bySeq_[seq].ev));
  bySeq_.clear();
  byArrival_.clear();
  return out;
}

}  // namespace pmx
