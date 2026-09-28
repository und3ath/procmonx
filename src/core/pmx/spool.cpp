#include "pmx/spool.h"

#include <algorithm>
#include <cstring>
#include <queue>

#include "pmx/store.h"

namespace pmx {

namespace {
std::error_code errc(int e) { return {e, std::system_category()}; }

bool keyLess(uint64_t ats, uint32_t aseq, uint64_t bts, uint32_t bseq) {
  if (ats != bts) return ats < bts;
  return aseq < bseq;
}

std::wstring defaultTempDir() {
  wchar_t buf[MAX_PATH + 1];
  DWORD n = GetTempPathW(MAX_PATH, buf);
  std::wstring d(buf, n);
  if (!d.empty() && d.back() == L'\\') d.pop_back();
  return d;
}

// Batches WriteFile calls into a 1 MB buffer while spilling a run; unlike
// BufferedFile (file_io.h) it writes into an already-open HANDLE (the caller
// owns open/close, since the handle is kept around for drain() to read back).
class ChunkWriter {
 public:
  void open(HANDLE h) { h_ = h; buf_.reserve(kCap); }
  std::error_code write(const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    while (n) {
      const size_t room = kCap - buf_.size();
      const size_t take = n < room ? n : room;
      buf_.insert(buf_.end(), p, p + take);
      p += take;
      n -= take;
      if (buf_.size() == kCap) {
        if (std::error_code ec = flush()) return ec;
      }
    }
    return {};
  }
  std::error_code flush() {
    if (buf_.empty()) return {};
    size_t done = 0;
    while (done < buf_.size()) {
      const DWORD chunk =
          (DWORD)std::min<size_t>(buf_.size() - done, 0x40000000u);
      DWORD wrote = 0;
      if (!WriteFile(h_, buf_.data() + done, chunk, &wrote, nullptr))
        return errc((int)GetLastError());
      if (wrote == 0) return errc(ERROR_WRITE_FAULT);
      done += wrote;
    }
    buf_.clear();
    return {};
  }

 private:
  static constexpr size_t kCap = size_t{1} << 20;
  HANDLE h_ = nullptr;
  std::vector<uint8_t> buf_;
};

// Sequential buffered reader over one run file for drain()'s k-way merge:
// loadNext() pulls the next [u32 recLen][u8 tag][record] into `payload` and
// parses its (seq, ts) key (record layout: u32 sequence at +0, u64 timestamp
// at +4) without a full decode - readEventRecord only runs when a record
// actually wins the merge and is handed to the sink.
class RunReader {
 public:
  void open(HANDLE h, size_t bufCap) {
    h_ = h;
    chunk_.assign(bufCap, 0);
    pos_ = len_ = 0;
    LARGE_INTEGER zero{};
    SetFilePointerEx(h_, zero, nullptr, FILE_BEGIN);
  }

  // False at clean EOF; `failed` marks a read error or a truncated record.
  bool loadNext() {
    if (!ensure(4)) {
      if (len_ != pos_) failed = true;
      return false;
    }
    uint32_t recLen;
    std::memcpy(&recLen, chunk_.data() + pos_, 4);
    pos_ += 4;
    if (recLen < 13 || !ensure(recLen)) {
      failed = true;
      return false;
    }
    payload.assign(reinterpret_cast<const char*>(chunk_.data() + pos_), recLen);
    pos_ += recLen;
    std::memcpy(&seq, payload.data() + 1, 4);
    std::memcpy(&ts, payload.data() + 5, 8);
    return true;
  }

  std::string payload;  // [u8 tag][record bytes]
  uint64_t ts = 0;
  uint32_t seq = 0;
  bool failed = false;

 private:
  bool ensure(size_t n) {
    if (len_ - pos_ >= n) return true;
    if (pos_) {
      std::memmove(chunk_.data(), chunk_.data() + pos_, len_ - pos_);
      len_ -= pos_;
      pos_ = 0;
    }
    if (chunk_.size() < n) chunk_.resize(n);
    while (len_ - pos_ < n) {
      const DWORD want = (DWORD)std::min(chunk_.size() - len_, size_t{0x40000000});
      DWORD got = 0;
      if (!ReadFile(h_, chunk_.data() + len_, want, &got, nullptr)) {
        failed = true;
        return false;
      }
      if (got == 0) return false;  // EOF
      len_ += got;
    }
    return true;
  }

  HANDLE h_ = nullptr;
  std::vector<uint8_t> chunk_;
  size_t pos_ = 0, len_ = 0;
};

// Decode the record starting at buf[offset] ([u32 recLen][u8 tag][record]).
bool decodeAt(const std::string& buf, uint64_t offset, Event& e, uint8_t& tag) {
  uint32_t recLen;
  std::memcpy(&recLen, buf.data() + offset, 4);
  const char* p = buf.data() + offset + 4;
  tag = static_cast<uint8_t>(p[0]);
  const char* rp = p + 1;
  const char* rend = p + recLen;
  return readEventRecord(rp, rend, kEventRecordVersion, e);
}
}  // namespace

EventSpool::EventSpool(SpoolOptions opt) : opt_(std::move(opt)) {}

EventSpool::~EventSpool() {
  for (auto& rf : runFiles_)
    if (rf.handle != INVALID_HANDLE_VALUE) CloseHandle(rf.handle);
}

std::error_code EventSpool::add(const Event& ev, uint8_t tag) {
  std::string rec;
  appendEventRecord(rec, ev);
  const uint32_t recLen = (uint32_t)(1 + rec.size());
  // Spill before appending, into a buffer reserved once: letting the string
  // double past the budget would peak near 2x the configured RAM.
  const size_t after = buf_.size() + 4 + recLen + (keys_.size() + 1) * sizeof(Key);
  if (!keys_.empty() && after > opt_.bufferBytes)
    if (std::error_code ec = spill()) return ec;
  if (buf_.capacity() < opt_.bufferBytes) buf_.reserve(opt_.bufferBytes);
  const uint64_t offset = buf_.size();
  buf_.append(reinterpret_cast<const char*>(&recLen), 4);
  buf_.push_back(static_cast<char>(tag));
  buf_.append(rec);
  keys_.push_back({ev.timestamp, ev.sequence, offset});
  ++count_;
  return {};
}

std::error_code EventSpool::spill() {
  std::stable_sort(keys_.begin(), keys_.end(), [](const Key& a, const Key& b) {
    return keyLess(a.ts, a.seq, b.ts, b.seq);
  });

  const std::wstring dir = opt_.dir.empty() ? defaultTempDir() : opt_.dir;
  wchar_t path[MAX_PATH];
  swprintf(path, MAX_PATH, L"%s\\pmx-spool-%lu-%zu.tmp", dir.c_str(),
          GetCurrentProcessId(), runFiles_.size());
  HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                        nullptr);
  if (h == INVALID_HANDLE_VALUE) return errc((int)GetLastError());

  ChunkWriter w;
  w.open(h);
  uint64_t bytes = 0;
  for (const Key& k : keys_) {
    uint32_t recLen;
    std::memcpy(&recLen, buf_.data() + k.offset, 4);
    const size_t total = 4 + recLen;
    if (std::error_code ec = w.write(buf_.data() + k.offset, total)) {
      CloseHandle(h);
      return ec;
    }
    bytes += total;
  }
  if (std::error_code ec = w.flush()) {
    CloseHandle(h);
    return ec;
  }

  const size_t idx = runFiles_.size();
  const uint64_t eventsInRun = keys_.size();
  runFiles_.push_back({h, eventsInRun});
  spilledBytes_ += bytes;
  buf_.clear();
  keys_.clear();
  if (onSpill) onSpill(idx, eventsInRun);
  return {};
}

std::error_code EventSpool::drain(
    const std::function<bool(const Event&, uint8_t)>& sink) {
  auto byKey = [](const Key& a, const Key& b) {
    return keyLess(a.ts, a.seq, b.ts, b.seq);
  };

  if (runFiles_.empty()) {
    // Fast path: nothing ever spilled, sort and decode straight from buf_.
    std::stable_sort(keys_.begin(), keys_.end(), byKey);
    for (const Key& k : keys_) {
      Event e;
      uint8_t tag;
      if (!decodeAt(buf_, k.offset, e, tag)) return errc(ERROR_INVALID_DATA);
      if (!sink(e, tag)) return {};
    }
    return {};
  }

  // Sort the in-memory tail too; it merges in as the last (highest-index)
  // source, so equal (ts, seq) keys across sources still come out in arrival
  // order - earlier runs were spilled from earlier-arriving events, and each
  // run (and the tail) is itself stable-sorted.
  std::stable_sort(keys_.begin(), keys_.end(), byKey);

  const size_t nRuns = runFiles_.size();
  std::vector<RunReader> readers(nRuns);
  const size_t perRunCap = std::min<size_t>(
      std::max<size_t>(opt_.bufferBytes / (nRuns + 1), size_t{64} << 10),
      size_t{4} << 20);
  for (size_t i = 0; i < nRuns; ++i) readers[i].open(runFiles_[i].handle, perRunCap);

  struct HeapItem {
    uint64_t ts;
    uint32_t seq;
    size_t src;  // < nRuns: a run reader; == nRuns: the in-memory tail
  };
  struct Greater {  // std::priority_queue + Greater = min-heap idiom
    bool operator()(const HeapItem& a, const HeapItem& b) const {
      if (a.ts != b.ts) return a.ts > b.ts;
      if (a.seq != b.seq) return a.seq > b.seq;
      return a.src > b.src;  // smaller source index = earlier arrival
    }
  };
  std::priority_queue<HeapItem, std::vector<HeapItem>, Greater> heap;

  for (size_t i = 0; i < nRuns; ++i)
    if (readers[i].loadNext()) heap.push({readers[i].ts, readers[i].seq, i});
  const size_t tailSrc = nRuns;
  size_t tailPos = 0;
  if (tailPos < keys_.size())
    heap.push({keys_[tailPos].ts, keys_[tailPos].seq, tailSrc});

  while (!heap.empty()) {
    const HeapItem top = heap.top();
    heap.pop();
    Event e;
    uint8_t tag;
    if (top.src == tailSrc) {
      if (!decodeAt(buf_, keys_[tailPos].offset, e, tag))
        return errc(ERROR_INVALID_DATA);
      ++tailPos;
      const bool more = tailPos < keys_.size();
      if (!sink(e, tag)) return {};
      if (more) heap.push({keys_[tailPos].ts, keys_[tailPos].seq, tailSrc});
    } else {
      RunReader& rr = readers[top.src];
      tag = static_cast<uint8_t>(rr.payload[0]);
      const char* rp = rr.payload.data() + 1;
      const char* rend = rr.payload.data() + rr.payload.size();
      if (!readEventRecord(rp, rend, kEventRecordVersion, e))
        return errc(ERROR_INVALID_DATA);
      const bool more = rr.loadNext();
      if (!sink(e, tag)) return {};
      if (more) heap.push({rr.ts, rr.seq, top.src});
    }
  }
  for (const RunReader& rr : readers)
    if (rr.failed) return errc(ERROR_READ_FAULT);
  return {};
}

}  // namespace pmx
