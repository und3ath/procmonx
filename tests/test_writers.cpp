// Streaming writers (PmxlogWriter/CsvWriter/JsonWriter/PmlWriter) pinned
// directly against the saveEvents*/savePml wrappers now built on top of them.
#include "pmx/store.h"

#include <cstdio>
#include <string>
#include <vector>

#include "pmx/file_io.h"
#include "pmx/pml.h"
#include "test_util.h"

namespace {
using namespace pmx;

std::vector<Event> sampleEvents() {
  std::vector<Event> v;

  Event e1;
  e1.sequence = 1;
  e1.timestamp = 1000;
  e1.processIndex = 7;
  e1.pid = 111;
  e1.eventClass = 3;
  e1.operation = 20;
  e1.processName = L"a.exe";
  e1.opName = "CreateFile";
  e1.className = "FileSystem";
  e1.path = L"C:\\a.txt";
  v.push_back(e1);

  Event e2;
  e2.sequence = 2;
  e2.timestamp = 1010;
  e2.processIndex = 7;
  e2.pid = 111;
  e2.eventClass = 2;
  e2.operation = 4;  // RegSetValue
  e2.regType = 4;
  e2.regLength = 4;
  e2.valueData = {0x2A, 0, 0, 0};
  e2.processName = L"a.exe";
  e2.opName = "RegSetValue";
  e2.className = "Registry";
  e2.path = L"HKLM\\Software\\Test";
  v.push_back(e2);

  Event e3;
  e3.sequence = 3;
  e3.timestamp = 1020;
  e3.processIndex = 9;
  e3.pid = 222;
  e3.eventClass = 1;
  e3.operation = 1;  // Process Create
  e3.targetPid = 333;
  e3.targetCmdline = L"child.exe /x";
  e3.processName = L"parent.exe";
  e3.opName = "Process Create";
  e3.className = "Process";
  e3.path = L"C:\\child.exe";
  v.push_back(e3);

  return v;
}

void checkSameFile(const wchar_t* a, const wchar_t* b) {
  std::string sa, sb;
  CHECK(!readWholeFile(a, sa));
  CHECK(!readWholeFile(b, sb));
  CHECK(!sa.empty());
  CHECK(sa == sb);
}
}  // namespace

int test_writers() {
  int before = g_failures;
  const std::vector<Event> events = sampleEvents();

  // PmxlogWriter: round trip via loadEvents, and byte-identical to saveEvents.
  {
    PmxlogWriter w;
    CHECK(!w.open(L"pmx_test_w1.pmxlog"));
    for (const auto& e : events) CHECK(!w.write(e));
    CHECK(!w.close());
    CHECK(w.count() == events.size());

    std::vector<Event> out;
    CHECK(!loadEvents(L"pmx_test_w1.pmxlog", out));
    CHECK(out.size() == events.size());
    if (out.size() == events.size()) {
      for (size_t i = 0; i < events.size(); ++i) {
        CHECK(out[i].sequence == events[i].sequence);
        CHECK(out[i].timestamp == events[i].timestamp);
        CHECK(out[i].path == events[i].path);
      }
    }

    CHECK(!saveEvents(L"pmx_test_w2.pmxlog", events));
    checkSameFile(L"pmx_test_w1.pmxlog", L"pmx_test_w2.pmxlog");
    _wremove(L"pmx_test_w1.pmxlog");
    _wremove(L"pmx_test_w2.pmxlog");
  }

  // CsvWriter byte-identical to saveEventsCsv.
  {
    CsvWriter w;
    CHECK(!w.open(L"pmx_test_w1.csv"));
    for (const auto& e : events) CHECK(!w.write(e));
    CHECK(!w.close());
    CHECK(w.count() == events.size());

    CHECK(!saveEventsCsv(L"pmx_test_w2.csv", events));
    checkSameFile(L"pmx_test_w1.csv", L"pmx_test_w2.csv");
    _wremove(L"pmx_test_w1.csv");
    _wremove(L"pmx_test_w2.csv");
  }

  // JsonWriter byte-identical to saveEventsJson.
  {
    JsonWriter w;
    CHECK(!w.open(L"pmx_test_w1.jsonl"));
    for (const auto& e : events) CHECK(!w.write(e));
    CHECK(!w.close());
    CHECK(w.count() == events.size());

    CHECK(!saveEventsJson(L"pmx_test_w2.jsonl", events));
    checkSameFile(L"pmx_test_w1.jsonl", L"pmx_test_w2.jsonl");
    _wremove(L"pmx_test_w1.jsonl");
    _wremove(L"pmx_test_w2.jsonl");
  }

  // PmlWriter byte-identical to savePml. `events` is already in (timestamp,
  // sequence) order, the order savePml itself stable_sorts to, so streaming
  // them straight through must produce the same bytes.
  {
    PmlWriter w;
    CHECK(!w.open(L"pmx_test_w1.pml"));
    for (const auto& e : events) CHECK(!w.write(e));
    CHECK(!w.close());
    CHECK(w.count() == events.size());

    CHECK(!savePml(L"pmx_test_w2.pml", events));
    checkSameFile(L"pmx_test_w1.pml", L"pmx_test_w2.pml");

    std::vector<Event> rt;
    CHECK(!loadPml(L"pmx_test_w1.pml", rt));
    CHECK(rt.size() == events.size());
    _wremove(L"pmx_test_w1.pml");
    _wremove(L"pmx_test_w2.pml");
  }

  return g_failures - before;
}
