#include "pmx/enrich/pairer.h"

#include <cstring>

namespace pmx {

std::optional<CompletedEvent> Pairer::consume(const RawRecord& r) {
  const auto& h = *r.header;

  // Class 0 = completion. Match it to a buffered request by sequence.
  if (h.eventClass == static_cast<uint16_t>(proto::EventClass::System)) {
    auto it = bySeq_.find(h.sequence);
    if (it == bySeq_.end()) return std::nullopt;  // no matching request
    CompletedEvent ev = std::move(it->second);
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

  // Pending: buffer until the completion arrives. If a stale entry shares this
  // sequence (wraparound / dropped completion), it is overwritten.
  bySeq_[h.sequence] = std::move(ev);
  while (bySeq_.size() > maxPending_) {
    auto oldest = bySeq_.begin();
    evicted_.push_back(std::move(oldest->second));
    bySeq_.erase(oldest);
  }
  return std::nullopt;
}

std::vector<CompletedEvent> Pairer::flush() {
  std::vector<CompletedEvent> out;
  out.reserve(bySeq_.size());
  for (auto& [seq, ev] : bySeq_) out.push_back(std::move(ev));
  bySeq_.clear();
  return out;
}

}  // namespace pmx
