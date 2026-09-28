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

EventSpool::EventSpool(SpoolOptions opt)
    : opt_(std::move(opt)), halfBudget_(std::max<size_t>(opt_.bufferBytes / 2, 1)) {}

EventSpool::~EventSpool() {
  {
    std::lock_guard<std::mutex> lk(mx_);
    shutdown_ = true;
  }
  cv_.notify_all();
  if (workerStarted_ && worker_.joinable()) worker_.join();
  for (auto& rf : runFiles_)
    if (rf.handle != INVALID_HANDLE_VALUE) CloseHandle(rf.handle);
}

uint64_t EventSpool::count() const { return count_; }

size_t EventSpool::runs() const {
  std::lock_guard<std::mutex> lk(mx_);
  return runFiles_.size();
}

uint64_t EventSpool::spilledBytes() const {
  std::lock_guard<std::mutex> lk(mx_);
  return spilledBytes_;
}

std::error_code EventSpool::add(const Event& ev, uint8_t tag) {
  {
    std::lock_guard<std::mutex> lk(mx_);
    if (stickyErr_) return stickyErr_;
  }

  std::string rec;
  appendEventRecord(rec, ev);
  const uint32_t recLen = (uint32_t)(1 + rec.size());

  Buffer* target = &buffers_[activeIdx_];
  // Spill before appending, into a buffer reserved once: letting the string
  // double past the budget would peak near 2x the configured per-buffer RAM.
  const size_t after =
      target->buf.size() + 4 + recLen + (target->keys.size() + 1) * sizeof(Key);
  if (!target->keys.empty() && after > halfBudget_) {
    if (std::error_code ec = handoff()) return ec;
    target = &buffers_[activeIdx_];
  }
  if (target->buf.capacity() < halfBudget_) target->buf.reserve(halfBudget_);
  const uint64_t offset = target->buf.size();
  target->buf.append(reinterpret_cast<const char*>(&recLen), 4);
  target->buf.push_back(static_cast<char>(tag));
  target->buf.append(rec);
  target->keys.push_back({ev.timestamp, ev.sequence, offset});
  ++count_;
  return {};
}

std::error_code EventSpool::handoff() {
  std::unique_lock<std::mutex> lk(mx_);
  // Backpressure: at most one run write in flight - wait for it.
  cv_.wait(lk, [&] { return !busy_; });
  if (stickyErr_) return stickyErr_;

  if (!workerStarted_) {
    worker_ = std::thread(&EventSpool::workerMain, this);
    workerStarted_ = true;
  }

  const int idx = activeIdx_;
  const size_t runIndex = runFiles_.size();
  const uint64_t eventsInRun = buffers_[idx].keys.size();
  runFiles_.emplace_back();  // placeholder; worker fills it in on completion

  busy_ = true;
  workBufIdx_ = idx;
  workRunIndex_ = runIndex;
  workReady_ = true;
  // The other buffer is idle: either never used, or the worker already
  // finished with it and cleared it before clearing busy_ last time.
  activeIdx_ = 1 - idx;
  lk.unlock();
  cv_.notify_all();

  if (onSpill) onSpill(runIndex, eventsInRun);
  return {};
}

void EventSpool::workerMain() {
  std::unique_lock<std::mutex> lk(mx_);
  for (;;) {
    cv_.wait(lk, [&] { return workReady_ || shutdown_; });
    if (!workReady_) return;  // shutdown_ and nothing queued
    workReady_ = false;
    const int idx = workBufIdx_;
    const size_t runIndex = workRunIndex_;
    lk.unlock();

    SpillResult res;
    std::error_code ec = spillBuffer(buffers_[idx], runIndex, res);

    lk.lock();
    if (ec) {
      if (!stickyErr_) stickyErr_ = ec;
    } else {
      runFiles_[runIndex] = RunFile{res.handle, res.events};
      spilledBytes_ += res.bytes;
    }
    buffers_[idx].buf.clear();
    buffers_[idx].keys.clear();
    busy_ = false;
    cv_.notify_all();
  }
}

std::error_code EventSpool::spillBuffer(Buffer& b, size_t runIndex,
                                        SpillResult& out) const {
  std::stable_sort(b.keys.begin(), b.keys.end(), [](const Key& a, const Key& c) {
    return keyLess(a.ts, a.seq, c.ts, c.seq);
  });

  const std::wstring dir = opt_.dir.empty() ? defaultTempDir() : opt_.dir;
  wchar_t path[MAX_PATH];
  swprintf(path, MAX_PATH, L"%s\\pmx-spool-%lu-%zu.tmp", dir.c_str(),
          GetCurrentProcessId(), runIndex);
  HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                        nullptr);
  if (h == INVALID_HANDLE_VALUE) return errc((int)GetLastError());

  ChunkWriter w;
  w.open(h);
  uint64_t bytes = 0;
  for (const Key& k : b.keys) {
    uint32_t recLen;
    std::memcpy(&recLen, b.buf.data() + k.offset, 4);
    const size_t total = 4 + recLen;
    if (std::error_code ec = w.write(b.buf.data() + k.offset, total)) {
      CloseHandle(h);
      return ec;
    }
    bytes += total;
  }
  if (std::error_code ec = w.flush()) {
    CloseHandle(h);
    return ec;
  }

  out.handle = h;
  out.events = b.keys.size();
  out.bytes = bytes;
  return {};
}

std::error_code EventSpool::drain(
    const std::function<bool(const Event&, uint8_t)>& sink) {
  std::error_code spillErr;
  {
    std::unique_lock<std::mutex> lk(mx_);
    cv_.wait(lk, [&] { return !busy_; });
    spillErr = stickyErr_;
  }
  // A failed run is lost, but everything else is still delivered before the
  // error is returned.
  std::erase_if(runFiles_, [](const RunFile& rf) {
    return rf.handle == INVALID_HANDLE_VALUE;
  });

  auto byKey = [](const Key& a, const Key& b) {
    return keyLess(a.ts, a.seq, b.ts, b.seq);
  };

  Buffer& tail = buffers_[activeIdx_];

  if (runFiles_.empty()) {
    // Fast path: nothing ever spilled, sort and decode straight from tail.buf.
    std::stable_sort(tail.keys.begin(), tail.keys.end(), byKey);
    for (const Key& k : tail.keys) {
      Event e;
      uint8_t tag;
      if (!decodeAt(tail.buf, k.offset, e, tag)) return errc(ERROR_INVALID_DATA);
      if (!sink(e, tag)) return spillErr;
    }
    return spillErr;
  }

  // Sort the in-memory tail too; it merges in as the last (highest-index)
  // source, so equal (ts, seq) keys across sources still come out in arrival
  // order - earlier runs were spilled from earlier-arriving events, and each
  // run (and the tail) is itself stable-sorted.
  std::stable_sort(tail.keys.begin(), tail.keys.end(), byKey);

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
  if (tailPos < tail.keys.size())
    heap.push({tail.keys[tailPos].ts, tail.keys[tailPos].seq, tailSrc});

  while (!heap.empty()) {
    const HeapItem top = heap.top();
    heap.pop();
    Event e;
    uint8_t tag;
    if (top.src == tailSrc) {
      if (!decodeAt(tail.buf, tail.keys[tailPos].offset, e, tag))
        return errc(ERROR_INVALID_DATA);
      ++tailPos;
      const bool more = tailPos < tail.keys.size();
      if (!sink(e, tag)) return spillErr;
      if (more) heap.push({tail.keys[tailPos].ts, tail.keys[tailPos].seq, tailSrc});
    } else {
      RunReader& rr = readers[top.src];
      tag = static_cast<uint8_t>(rr.payload[0]);
      const char* rp = rr.payload.data() + 1;
      const char* rend = rr.payload.data() + rr.payload.size();
      if (!readEventRecord(rp, rend, kEventRecordVersion, e))
        return errc(ERROR_INVALID_DATA);
      const bool more = rr.loadNext();
      if (!sink(e, tag)) return spillErr;
      if (more) heap.push({rr.ts, rr.seq, top.src});
    }
  }
  if (spillErr) return spillErr;
  for (const RunReader& rr : readers)
    if (rr.failed) return errc(ERROR_READ_FAULT);
  return {};
}

}  // namespace pmx
