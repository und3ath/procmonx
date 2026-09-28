// Streaming readers (PmxlogReader/PmlReader) and MappedFile, pinned against
// the loadEvents/loadPml wrappers now built on top of them.
#include "pmx/store.h"

#include <cstdio>
#include <cstring>
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

void put32(std::vector<uint8_t>& d, size_t o, uint32_t v) { std::memcpy(d.data() + o, &v, 4); }
void put64(std::vector<uint8_t>& d, size_t o, uint64_t v) { std::memcpy(d.data() + o, &v, 8); }

}  // namespace

int test_readers() {
  int before = g_failures;

  // --- MappedFile on an empty file: open succeeds, size 0, data null. -------
  {
    const wchar_t* path = L"pmx_test_readers_empty.bin";
    FILE* f = _wfopen(path, L"wb");
    if (f) std::fclose(f);
    MappedFile mf;
    CHECK(!mf.open(path));
    CHECK(mf.size() == 0);
    CHECK(mf.data() == nullptr);
    _wremove(path);
  }

  // --- PmxlogReader round trip equals loadEvents. ---------------------------
  {
    const std::vector<Event> events = sampleEvents();
    const wchar_t* path = L"pmx_test_readers.pmxlog";
    CHECK(!saveEvents(path, events));

    std::vector<Event> viaLoad;
    CHECK(!loadEvents(path, viaLoad));

    std::vector<Event> viaReader;
    PmxlogReader r;
    CHECK(!r.open(path));
    Event e;
    while (r.next(e)) viaReader.push_back(e);
    CHECK(!r.error());
    CHECK(r.declaredCount() == events.size());

    CHECK(viaReader.size() == viaLoad.size());
    CHECK(viaReader.size() == events.size());
    if (viaReader.size() == viaLoad.size()) {
      for (size_t i = 0; i < viaLoad.size(); ++i) {
        CHECK(viaReader[i].sequence == viaLoad[i].sequence);
        CHECK(viaReader[i].timestamp == viaLoad[i].timestamp);
        CHECK(viaReader[i].pid == viaLoad[i].pid);
        CHECK(viaReader[i].eventClass == viaLoad[i].eventClass);
        CHECK(viaReader[i].opName == viaLoad[i].opName);
        CHECK(viaReader[i].path == viaLoad[i].path);
      }
    }
    _wremove(path);
  }

  // --- Header count 0 with record bytes following (writer died before
  // patching the count) is recovered: the reader still yields every event
  // instead of stopping immediately. ------------------------------------------
  {
    const std::vector<Event> events = sampleEvents();
    const wchar_t* path = L"pmx_test_readers_recover.pmxlog";
    {
      PmxlogWriter w;
      CHECK(!w.open(path));
      for (const auto& e : events) CHECK(!w.write(e));
      CHECK(!w.close());  // patches the real count in
    }
    // Zero the count field (bytes 8..11) back out, simulating a writer that
    // never got to close()/patch().
    if (FILE* f = _wfopen(path, L"r+b")) {
      std::fseek(f, 8, SEEK_SET);
      const uint32_t zero = 0;
      std::fwrite(&zero, 4, 1, f);
      std::fclose(f);
    }

    PmxlogReader r;
    CHECK(!r.open(path));
    CHECK(r.declaredCount() == 0);  // header still says 0
    std::vector<Event> out;
    Event e;
    while (r.next(e)) out.push_back(e);
    CHECK(!r.error());
    CHECK(out.size() == events.size());  // but every record was still read
    if (out.size() == events.size()) {
      for (size_t i = 0; i < events.size(); ++i)
        CHECK(out[i].path == events[i].path);
    }
    _wremove(path);
  }

  // --- PmlReader yields the same events as loadPml. --------------------------
  {
    const std::vector<Event> events = sampleEvents();
    const wchar_t* path = L"pmx_test_readers.pml";
    CHECK(!savePml(path, events));

    std::vector<Event> viaLoad;
    CHECK(!loadPml(path, viaLoad));

    std::vector<Event> viaReader;
    PmlReader r;
    CHECK(!r.open(path));
    Event e;
    while (r.next(e)) viaReader.push_back(e);
    CHECK(!r.error());

    CHECK(viaReader.size() == viaLoad.size());
    CHECK(viaReader.size() == events.size());
    if (viaReader.size() == viaLoad.size()) {
      for (size_t i = 0; i < viaLoad.size(); ++i) {
        CHECK(viaReader[i].timestamp == viaLoad[i].timestamp);
        CHECK(viaReader[i].eventClass == viaLoad[i].eventClass);
        CHECK(viaReader[i].opName == viaLoad[i].opName);
        CHECK(viaReader[i].path == viaLoad[i].path);
        CHECK(viaReader[i].pid == viaLoad[i].pid);
      }
    }
    _wremove(path);
  }

  // --- A crafted .pml with a huge declared event count but a tiny file must
  // fail cleanly (ERROR_INVALID_DATA), not attempt a huge allocation: the
  // events-offset-array bounds check catches it before any per-event work. ---
  {
    std::vector<uint8_t> d(0x3A8, 0);
    std::memcpy(d.data(), "PML_", 4);
    put32(d, 4, 9);       // version
    put32(d, 8, 1);       // bit0: 64-bit log
    put32(d, 0x234, 0xFFFFFFF0u);  // declared event count: huge
    put64(d, 0x240, 0x380);        // evOff
    put64(d, 0x248, 0x388);        // eoOff
    put64(d, 0x250, 0x390);        // ptOff
    put64(d, 0x258, 0x398);        // stOff
    put64(d, 0x260, 0x3A0);        // icOff
    const wchar_t* path = L"pmx_test_readers_huge.pml";
    if (FILE* f = _wfopen(path, L"wb")) {
      std::fwrite(d.data(), 1, d.size(), f);
      std::fclose(f);
    }

    PmlReader r;
    std::error_code ec = r.open(path);
    CHECK(!!ec);
    CHECK(ec.value() == ERROR_INVALID_DATA);

    std::vector<Event> junk;
    CHECK(!!loadPml(path, junk));
    CHECK(junk.empty());
    _wremove(path);
  }

  return g_failures - before;
}
