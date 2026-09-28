#include "pmx/enrich/pairer.h"

#include <cstring>
#include <vector>

#include "test_util.h"

namespace {
using namespace pmx;

// Build a RawRecord backed by a caller-owned header + detail buffer.
RawRecord makeRec(proto::EventRecordHeader& h, uint16_t cls, uint16_t op,
                  uint32_t seq, uint32_t result,
                  const std::vector<uint8_t>& detail) {
  h = {};
  h.eventClass = cls;
  h.operation = op;
  h.sequence = seq;
  h.result = result;
  h.frameCount = 0;
  h.detailSize = static_cast<uint32_t>(detail.size());
  RawRecord r;
  r.header = &h;
  r.stack = {};
  r.detail = std::span<const uint8_t>(detail.data(), detail.size());
  return r;
}
}  // namespace

int test_pairer() {
  int before = g_failures;
  using namespace pmx;

  // 1) Pending request → buffered (no emit) → completion fills result + info.
  {
    Pairer p;
    proto::EventRecordHeader hq{}, hc{};
    std::vector<uint8_t> reqDetail(0x48, 0);  // a CreateFile-ish request
    auto req = makeRec(hq, 3, 20, 1000, proto::kStatusPending, reqDetail);
    CHECK(!p.consume(req).has_value());   // buffered, nothing emitted yet
    CHECK(p.pendingCount() == 1);

    std::vector<uint8_t> compDetail = {2, 0, 0, 0, 0, 0, 0, 0};  // Information=2
    auto comp = makeRec(hc, 0, 0, 1000, 0 /*STATUS_SUCCESS*/, compDetail);
    auto out = p.consume(comp);
    CHECK(out.has_value());
    CHECK(out->completed);
    CHECK(out->finalResult == 0);
    CHECK(out->information == 2);         // FILE_CREATED
    CHECK(out->header.operation == 20);  // it's the *request* that comes back
    CHECK(p.pendingCount() == 0);
  }

  // 2) Synchronous request (non-pending) passes straight through.
  {
    Pairer p;
    proto::EventRecordHeader h{};
    std::vector<uint8_t> d(0x10, 0);
    auto rec = makeRec(h, 3, 22, 2000, 0xC0000034 /*NAME_NOT_FOUND*/, d);
    auto out = p.consume(rec);
    CHECK(out.has_value());
    CHECK(!out->completed);
    CHECK(out->finalResult == 0xC0000034);
    CHECK(p.pendingCount() == 0);
  }

  // 3) Completion with no matching request is dropped.
  {
    Pairer p;
    proto::EventRecordHeader h{};
    std::vector<uint8_t> d(8, 0);
    auto comp = makeRec(h, 0, 0, 9999, 0, d);
    CHECK(!p.consume(comp).has_value());
  }

  // 4) flush() drains still-pending requests as uncompleted.
  {
    Pairer p;
    proto::EventRecordHeader h{};
    std::vector<uint8_t> d(0x10, 0);
    auto req = makeRec(h, 3, 23, 3000, proto::kStatusPending, d);
    p.consume(req);
    auto rest = p.flush();
    CHECK(rest.size() == 1);
    CHECK(!rest[0].completed);
    CHECK(rest[0].finalResult == proto::kStatusPending);
    CHECK(p.pendingCount() == 0);
  }

  // Pending cap: beyond maxPending the OLDEST pending request is evicted
  // unmatched; a later completion for it no longer matches.
  {
    Pairer p(2);
    proto::EventRecordHeader h1{}, h2{}, h3{}, hc{};
    std::vector<uint8_t> d(8, 0);
    CHECK(!p.consume(makeRec(h1, 3, 20, 10, proto::kStatusPending, d)));
    CHECK(!p.consume(makeRec(h2, 3, 20, 11, proto::kStatusPending, d)));
    CHECK(p.takeEvicted().empty());
    CHECK(!p.consume(makeRec(h3, 3, 20, 12, proto::kStatusPending, d)));
    auto ev = p.takeEvicted();
    CHECK(ev.size() == 1);
    if (ev.size() == 1) {
      CHECK(ev[0].header.sequence == 10);
      CHECK(!ev[0].completed);
    }
    CHECK(p.takeEvicted().empty());
    CHECK(p.pendingCount() == 2);
    CHECK(!p.consume(makeRec(hc, 0, 0, 10, 0, d)));  // evicted: no match
    CHECK(p.consume(makeRec(hc, 0, 0, 12, 0, d)).has_value());
  }

  // Sequence wraparound: eviction follows arrival, so after the u32 sequence
  // wraps the pre-wrap (older) request is evicted, not the newer small one.
  {
    Pairer p(2);
    proto::EventRecordHeader h{};
    std::vector<uint8_t> d(8, 0);
    CHECK(!p.consume(makeRec(h, 3, 20, 0xFFFFFFFEu, proto::kStatusPending, d)));
    CHECK(!p.consume(makeRec(h, 3, 20, 0xFFFFFFFFu, proto::kStatusPending, d)));
    CHECK(!p.consume(makeRec(h, 3, 20, 1, proto::kStatusPending, d)));
    auto ev = p.takeEvicted();
    CHECK(ev.size() == 1);
    if (ev.size() == 1) CHECK(ev[0].header.sequence == 0xFFFFFFFEu);
    // A reused sequence emits the stale request instead of dropping it.
    CHECK(!p.consume(makeRec(h, 3, 20, 1, proto::kStatusPending, d)));
    ev = p.takeEvicted();
    CHECK(ev.size() == 1);
    auto rest = p.flush();
    CHECK(rest.size() == 2);
    if (rest.size() == 2) {  // flush in arrival order
      CHECK(rest[0].header.sequence == 0xFFFFFFFFu);
      CHECK(rest[1].header.sequence == 1);
    }
  }
  return g_failures - before;
}
