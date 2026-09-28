// EventSpool: external-sort spill/drain used by `pmx live`/`pmx net` to keep
// events destined for a file out of a big in-RAM vector.
#include "pmx/spool.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "pmx/event.h"
#include "test_util.h"

namespace {
using namespace pmx;

Event makeEvent(uint32_t seq, uint64_t ts, int idx) {
  Event e;
  e.sequence = seq;
  e.timestamp = ts;
  e.pid = (uint32_t)idx;
  e.eventClass = 3;
  e.operation = 20;
  e.opName = "CreateFile";
  e.className = "FileSystem";
  e.processName = L"p" + std::to_wstring(idx) + L".exe";
  e.path = L"\\path\\" + std::to_wstring(idx);
  return e;
}

std::wstring pathFor(int idx) { return L"\\path\\" + std::to_wstring(idx); }
}  // namespace

int test_spool() {
  int before = g_failures;

  // 1) No spill: drained order is (timestamp, sequence); ties keep arrival order.
  {
    SpoolOptions opt;  // default bufferBytes: nothing this small ever spills
    EventSpool sp(opt);
    struct In { uint32_t seq; uint64_t ts; int idx; };
    const std::vector<In> ins = {
        {5, 100, 0}, {1, 50, 1}, {2, 50, 2}, {1, 50, 3}, {9, 200, 4}, {0, 50, 5},
    };
    for (const auto& in : ins)
      CHECK(!sp.add(makeEvent(in.seq, in.ts, in.idx), (uint8_t)(in.idx % 2)));
    CHECK(sp.runs() == 0);
    CHECK(sp.count() == ins.size());

    std::vector<In> expected = ins;
    std::stable_sort(expected.begin(), expected.end(), [](const In& a, const In& b) {
      if (a.ts != b.ts) return a.ts < b.ts;
      return a.seq < b.seq;
    });

    std::vector<int> got;
    std::vector<uint8_t> gotTags;
    std::error_code de = sp.drain([&](const Event& e, uint8_t tag) {
      got.push_back((int)e.pid);
      gotTags.push_back(tag);
      return true;
    });
    CHECK(!de);
    CHECK(got.size() == expected.size());
    if (got.size() == expected.size()) {
      for (size_t i = 0; i < got.size(); ++i) {
        CHECK(got[i] == expected[i].idx);
        CHECK(gotTags[i] == (uint8_t)(expected[i].idx % 2));
      }
    }
  }

  // 2) A tiny buffer forces many spilled runs. Drained output must equal a
  // std::stable_sort of the arrival-order input, tags included, even with
  // shuffled timestamps and duplicate (ts, seq) keys.
  {
    constexpr int N = 5000;
    SpoolOptions opt;
    opt.bufferBytes = 4096;
    EventSpool sp(opt);
    size_t spillCalls = 0;
    sp.onSpill = [&](size_t, uint64_t) { ++spillCalls; };

    struct In { uint32_t seq; uint64_t ts; int idx; uint8_t tag; };
    std::vector<In> ins;
    ins.reserve(N);
    for (int i = 0; i < N; ++i) {
      // Knuth multiplicative hash mod small ranges: pseudo-random but
      // deterministic, with plenty of (ts, seq) collisions.
      const In in{(uint32_t)(i % 47),
                  (uint64_t)(((unsigned)i * 2654435761u) % 100), i,
                  (uint8_t)(i & 1)};
      ins.push_back(in);
      CHECK(!sp.add(makeEvent(in.seq, in.ts, in.idx), in.tag));
    }
    CHECK(sp.runs() > 1);
    CHECK(spillCalls == sp.runs());
    CHECK(sp.count() == (uint64_t)N);

    std::vector<In> expected = ins;
    std::stable_sort(expected.begin(), expected.end(), [](const In& a, const In& b) {
      if (a.ts != b.ts) return a.ts < b.ts;
      return a.seq < b.seq;
    });

    std::vector<int> got;
    std::vector<uint8_t> gotTags;
    std::vector<std::wstring> gotPaths;
    got.reserve(N);
    gotTags.reserve(N);
    gotPaths.reserve(N);
    std::error_code de = sp.drain([&](const Event& e, uint8_t tag) {
      got.push_back((int)e.pid);
      gotTags.push_back(tag);
      gotPaths.push_back(e.path);
      return true;
    });
    CHECK(!de);
    CHECK(got.size() == expected.size());
    if (got.size() == expected.size()) {
      for (size_t i = 0; i < got.size(); ++i) {
        CHECK(got[i] == expected[i].idx);
        CHECK(gotTags[i] == expected[i].tag);
        CHECK(gotPaths[i] == pathFor(expected[i].idx));
      }
    }
  }

  // 3) Early stop: the sink returning false cuts the drain short.
  {
    SpoolOptions opt;
    opt.bufferBytes = 4096;
    EventSpool sp(opt);
    for (int i = 0; i < 500; ++i)
      CHECK(!sp.add(makeEvent((uint32_t)i, (uint64_t)(500 - i), i), 1));
    CHECK(sp.runs() > 0);  // exercise the multi-run merge path too

    int delivered = 0;
    std::error_code de = sp.drain([&](const Event&, uint8_t) {
      ++delivered;
      return delivered < 100;
    });
    CHECK(!de);
    CHECK(delivered == 100);
  }

  // 4) Run files are deleted (FILE_FLAG_DELETE_ON_CLOSE) once the spool goes
  // out of scope, even without ever calling drain().
  {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    const std::wstring dir = std::wstring(tmp) + L"pmx_spool_test";
    CreateDirectoryW(dir.c_str(), nullptr);

    {
      SpoolOptions opt;
      opt.bufferBytes = 4096;
      opt.dir = dir;
      EventSpool sp(opt);
      for (int i = 0; i < 500; ++i)
        CHECK(!sp.add(makeEvent((uint32_t)i, (uint64_t)i, i), 1));
      CHECK(sp.runs() > 0);
    }

    const std::wstring pattern =
        dir + L"\\pmx-spool-" + std::to_wstring(GetCurrentProcessId()) + L"-*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    CHECK(h == INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) FindClose(h);
    RemoveDirectoryW(dir.c_str());
  }

  // 5) Background double-buffered spill under a tiny budget (forces frequent
  // handoffs, including backpressure waits when the worker can't keep up):
  // drained output must still equal a std::stable_sort of the arrival-order
  // input, tags included.
  {
    constexpr int N = 8000;
    SpoolOptions opt;
    opt.bufferBytes = 2048;  // halfBudget_ ~1024: many runs, frequent handoffs
    EventSpool sp(opt);
    size_t spillCalls = 0;
    sp.onSpill = [&](size_t, uint64_t) { ++spillCalls; };

    struct In { uint32_t seq; uint64_t ts; int idx; uint8_t tag; };
    std::vector<In> ins;
    ins.reserve(N);
    for (int i = 0; i < N; ++i) {
      const In in{(uint32_t)(i % 37),
                  (uint64_t)(((unsigned)i * 2654435761u) % 200), i,
                  (uint8_t)(i & 1)};
      ins.push_back(in);
      CHECK(!sp.add(makeEvent(in.seq, in.ts, in.idx), in.tag));
    }
    CHECK(sp.runs() > 1);
    CHECK(spillCalls == sp.runs());
    CHECK(sp.count() == (uint64_t)N);

    std::vector<In> expected = ins;
    std::stable_sort(expected.begin(), expected.end(), [](const In& a, const In& b) {
      if (a.ts != b.ts) return a.ts < b.ts;
      return a.seq < b.seq;
    });

    std::vector<int> got;
    std::vector<uint8_t> gotTags;
    got.reserve(N);
    gotTags.reserve(N);
    std::error_code de = sp.drain([&](const Event& e, uint8_t tag) {
      got.push_back((int)e.pid);
      gotTags.push_back(tag);
      return true;
    });
    CHECK(!de);
    CHECK(got.size() == expected.size());
    if (got.size() == expected.size()) {
      for (size_t i = 0; i < got.size(); ++i) {
        CHECK(got[i] == expected[i].idx);
        CHECK(gotTags[i] == expected[i].tag);
      }
    }
  }

  // 6) add() error propagation: a spool dir that doesn't exist fails inside
  // the background worker at the first handoff. The failure isn't lost - a
  // later add() (once the worker has had a chance to fail) returns it, every
  // add() after that keeps returning it, and drain() still delivers what it
  // holds but returns the error.
  {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    SpoolOptions opt;
    opt.bufferBytes = 4096;
    opt.dir = std::wstring(tmp) + L"pmx_spool_test_missing_dir_xyz";
    EventSpool sp(opt);

    std::error_code firstErr;
    for (int i = 0; i < 2000 && !firstErr; ++i)
      firstErr = sp.add(makeEvent((uint32_t)i, (uint64_t)i, i), 0);
    CHECK(!!firstErr);

    std::error_code ec2 = sp.add(makeEvent(0, 0, 0), 0);
    CHECK(ec2 == firstErr);

    uint64_t delivered = 0;
    std::error_code de = sp.drain([&](const Event&, uint8_t) {
      ++delivered;
      return true;
    });
    CHECK(de == firstErr);
    CHECK(delivered > 0);  // the in-memory buffer isn't thrown away
  }

  // 7) Destructor with a spill still in flight (torn down right after a big
  // batch of adds, before the worker could plausibly have caught up): no
  // crash, and every run file is still cleaned up (FILE_FLAG_DELETE_ON_CLOSE).
  {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    const std::wstring dir = std::wstring(tmp) + L"pmx_spool_test_inflight";
    CreateDirectoryW(dir.c_str(), nullptr);

    {
      SpoolOptions opt;
      opt.bufferBytes = 4096;
      opt.dir = dir;
      EventSpool sp(opt);
      for (int i = 0; i < 4000; ++i)
        CHECK(!sp.add(makeEvent((uint32_t)i, (uint64_t)i, i), 1));
      CHECK(sp.runs() > 0);
      // sp destroyed here - possibly while the worker is still writing the
      // last run.
    }

    const std::wstring pattern =
        dir + L"\\pmx-spool-" + std::to_wstring(GetCurrentProcessId()) + L"-*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    CHECK(h == INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) FindClose(h);
    RemoveDirectoryW(dir.c_str());
  }

  return g_failures - before;
}
