// PML write -> read round trip: raw driver records are decoded (as in a live
// capture), written with savePml, read back with loadPml, and the decoded
// columns must survive unchanged.
#include <cstring>
#include <string>
#include <vector>

#include "pmx/decode.h"
#include "pmx/enrich/process_table.h"
#include "pmx/pml.h"
#include "test_util.h"

namespace {
using namespace pmx;

void put16(std::vector<uint8_t>& d, size_t o, uint16_t v) { std::memcpy(d.data() + o, &v, 2); }
void put32(std::vector<uint8_t>& d, size_t o, uint32_t v) { std::memcpy(d.data() + o, &v, 4); }
void put64(std::vector<uint8_t>& d, size_t o, uint64_t v) { std::memcpy(d.data() + o, &v, 8); }
void putW(std::vector<uint8_t>& d, size_t o, const std::wstring& s) {
  std::memcpy(d.data() + o, s.data(), s.size() * 2);
}

CompletedEvent rec(uint16_t cls, uint16_t op, uint64_t ts, std::vector<uint8_t> det,
                   uint32_t result = 0, uint64_t info = 0) {
  CompletedEvent ce;
  ce.header = {};
  ce.header.processIndex = 7;
  ce.header.threadId = 4242;
  ce.header.eventClass = cls;
  ce.header.operation = op;
  ce.header.timestamp = ts;
  ce.header.result = result;
  ce.header.detailSize = (uint32_t)det.size();
  ce.detail = std::move(det);
  ce.finalResult = result;
  ce.information = info;
  ce.completed = true;
  ce.completionTime = ts + 25;
  return ce;
}

// FS record: path prefix @0x40, UTF-16 path @0x44, optional post-path bytes.
std::vector<uint8_t> fsDetail(const std::wstring& path, size_t post = 0) {
  std::vector<uint8_t> d(0x44 + path.size() * 2 + post, 0);
  put16(d, 0x40, (uint16_t)path.size());
  putW(d, 0x44, path);
  return d;
}
}  // namespace

int test_pml() {
  int before = g_failures;

  ProcessTable procs;
  {
    ProcInfo pi;
    pi.pid = 1234;
    pi.name = L"a.exe";
    pi.image = L"C:\\a\\a.exe";
    pi.cmdline = L"a.exe -x";
    pi.user = L"HOST\\me";
    pi.integrity = L"High";
    procs.define(7, pi);
  }

  std::vector<CompletedEvent> recs;
  uint64_t ts = 133700000000000000ull;
  {  // ReadFile: Length @0x10, Offset @0x20
    auto d = fsDetail(L"\\Device\\HarddiskVolume3\\x.txt");
    put32(d, 0x10, 0x1000);
    put64(d, 0x20, 0x200);
    recs.push_back(rec(3, 23, ts += 10, d));
  }
  {  // CreateFile: disp<<24|options @0x18, attrs @0x20, share @0x22, access post-path
    const std::wstring p = L"\\Device\\HarddiskVolume3\\new.bin";
    auto d = fsDetail(p, 16);
    put32(d, 0x18, (2u << 24) | 0x60);  // Create, Synchronous IO Non-Alert | Non-Directory
    put16(d, 0x20, 0x80);
    put16(d, 0x22, 3);
    put32(d, 0x44 + p.size() * 2, 0x120116);  // Generic Write
    recs.push_back(rec(3, 20, ts += 10, d, 0, 2));  // OpenResult: Created
  }
  {  // QueryInformationFile / FileNameInformation sub-op (detail[0] = 9)
    auto d = fsDetail(L"\\Device\\HarddiskVolume3\\q.txt");
    d[0] = 9;
    recs.push_back(rec(3, 25, ts += 10, d));
  }
  {  // RegOpenKey: +0 path wchars, +4 access, path @+8
    const std::wstring p = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test";
    std::vector<uint8_t> d(8 + p.size() * 2, 0);
    put16(d, 0, (uint16_t)p.size());
    put32(d, 4, 0x20019);
    putW(d, 8, p);
    recs.push_back(rec(2, 0, ts += 10, d));
  }
  {  // RegCreateKey + disposition from completion
    const std::wstring p = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Made";
    std::vector<uint8_t> d(8 + p.size() * 2, 0);
    put16(d, 0, (uint16_t)p.size());
    put32(d, 4, 0xF003F);
    putW(d, 8, p);
    recs.push_back(rec(2, 1, ts += 10, d, 0, 1));  // REG_CREATED_NEW_KEY
  }
  {  // RegSetValue REG_DWORD: +0 wchars, +4 type, +8 len, +0xC bytes, path @0x10, data
    const std::wstring p = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test\\Val";
    std::vector<uint8_t> d(0x10 + p.size() * 2 + 4, 0);
    put16(d, 0, (uint16_t)p.size());
    put32(d, 4, 4);
    put32(d, 8, 4);
    put16(d, 0x0C, 4);
    putW(d, 0x10, p);
    put32(d, 0x10 + p.size() * 2, 0x2A);
    recs.push_back(rec(2, 4, ts += 10, d));
  }
  {  // RegQueryValue: path @0x0C, info class 2 @+8; result in completion
    const std::wstring p = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test\\Str";
    std::vector<uint8_t> d(0x0C + p.size() * 2, 0);
    put16(d, 0, (uint16_t)p.size());
    put32(d, 8, 2);
    putW(d, 0x0C, p);
    auto ce = rec(2, 5, ts += 10, d);
    const std::wstring val = L"hello";
    std::vector<uint8_t> comp(12 + val.size() * 2 + 2, 0);
    put32(comp, 4, 1);  // REG_SZ
    put32(comp, 8, (uint32_t)(val.size() * 2 + 2));
    putW(comp, 12, val);
    ce.completionDetail = comp;
    recs.push_back(ce);
  }
  {  // Process Create (op 1): child idx/pid + image + cmdline
    const std::wstring img = L"\\??\\C:\\w\\child.exe", cmd = L"child.exe /q";
    std::vector<uint8_t> d(0x34 + (img.size() + cmd.size()) * 2, 0);
    put32(d, 0, 99);
    put32(d, 4, 5555);
    put16(d, 0x2E, (uint16_t)img.size());
    put16(d, 0x30, (uint16_t)cmd.size());
    putW(d, 0x34, img);
    putW(d, 0x34 + img.size() * 2, cmd);
    recs.push_back(rec(1, 1, ts += 10, d));
  }

  std::vector<Event> in;
  for (const auto& ce : recs) in.push_back(decodeEvent(ce, procs));
  {  // Network (ETW-sourced; built like netEventToEvent)
    Event e;
    e.timestamp = ts += 10;
    e.processIndex = 0x80000000u | 1234;
    e.pid = 1234;
    e.processName = L"net.exe";
    e.eventClass = 5;
    e.operation = 2;  // Send
    e.className = "Network";
    e.opName = "TCP Send";
    e.path = L"10.0.0.1:5000 -> 10.0.0.2:443";
    e.detail = L"Length: 99";
    e.ioLength = 99;
    const uint8_t s[4] = {10, 0, 0, 1}, t[4] = {10, 0, 0, 2};
    std::memcpy(e.netSrcIp, s, 4);
    std::memcpy(e.netDstIp, t, 4);
    e.netSrcPort = 5000;
    e.netDstPort = 443;
    e.netFlags = 7;
    e.completed = true;
    in.push_back(e);
  }

  // Sanity: the decoder produced what we expect before the round trip.
  CHECK(in[0].detail == L"Offset:512 Length:4096");
  CHECK(in[1].detail.find(L"OpenResult:Created") != std::wstring::npos);
  CHECK(in[2].opName == "QueryNameInformationFile");
  CHECK(in[4].detail.find(L"REG_CREATED_NEW_KEY") != std::wstring::npos);
  CHECK(in[5].detail.find(L"Data:0x0000002A") != std::wstring::npos);
  CHECK(in[6].detail.find(L"Data:hello") != std::wstring::npos);
  CHECK(in[7].path == L"C:\\w\\child.exe");

  const wchar_t* path = L"pmx_test_rt.pml";
  CHECK(!savePml(path, in));
  std::vector<Event> out;
  CHECK(!loadPml(path, out));
  CHECK(out.size() == in.size());
  if (out.size() == in.size()) {
    for (size_t i = 0; i < in.size(); ++i) {
      CHECK(out[i].timestamp == in[i].timestamp);
      CHECK(out[i].eventClass == in[i].eventClass);
      CHECK(out[i].operation == in[i].operation);
      CHECK(out[i].opName == in[i].opName);
      CHECK(out[i].path == in[i].path);
      CHECK(out[i].detail == in[i].detail);
      CHECK(out[i].result == in[i].result);
      CHECK(out[i].pid == in[i].pid);
      CHECK(out[i].tid == in[i].tid);
      CHECK(out[i].processName == in[i].processName);
      CHECK(out[i].user == in[i].user);
      CHECK(out[i].integrity == in[i].integrity);
      CHECK(out[i].duration == in[i].duration);
      if (out[i].detail != in[i].detail)
        std::printf("   #%zu detail: '%ls' vs '%ls'\n", i, in[i].detail.c_str(),
                    out[i].detail.c_str());
      if (out[i].path != in[i].path)
        std::printf("   #%zu path: '%ls' vs '%ls'\n", i, in[i].path.c_str(),
                    out[i].path.c_str());
    }
  }
  // Robustness: truncated / garbage input is rejected, not crashed on.
  {
    std::vector<Event> junk;
    FILE* f = _wfopen(path, L"r+b");
    if (f) {
      std::fseek(f, 0x240, SEEK_SET);
      const uint64_t huge = 0x7FFFFFFFFFFFull;
      std::fwrite(&huge, 8, 1, f);  // events offset far past EOF
      std::fclose(f);
    }
    CHECK(!!loadPml(path, junk));
  }
  _wremove(path);

  // A RegQueryValue result larger than the u16 extra-details size must not
  // corrupt the file (the following event still loads).
  {
    std::vector<Event> in(2);
    in[0].eventClass = 2;
    in[0].operation = 5;
    in[0].regType = 3;  // REG_BINARY
    in[0].path = L"\\REGISTRY\\MACHINE\\SOFTWARE\\big";
    in[0].valueData.assign(70000, 0xAB);
    in[0].timestamp = 1;
    in[1].eventClass = 3;
    in[1].operation = 20;
    in[1].path = L"\\Device\\HarddiskVolume3\\after.txt";
    in[1].timestamp = 2;
    CHECK(!savePml(path, in));
    std::vector<Event> out;
    CHECK(!loadPml(path, out));
    CHECK(out.size() == 2);
    if (out.size() == 2) {
      CHECK(out[0].valueData.size() == 0xFFFF - 12);  // capped, not wrapped
      CHECK(out[1].path == in[1].path);
    }
    _wremove(path);
  }

  // Enough events that the writer's offset array spills to its temp file
  // (1 MB of 5-byte entries): every event must still come back, in order.
  {
    const uint32_t n = 250000;
    PmlWriter w;
    CHECK(!w.open(path));
    Event ev;
    ev.eventClass = 4;  // Profiling: smallest framed detail
    ev.operation = 0;
    ev.processIndex = 7;
    ev.pid = 1234;
    ev.processName = L"a.exe";
    for (uint32_t i = 0; i < n; ++i) {
      ev.timestamp = 133700000000000000ull + i;
      ev.tid = i;
      CHECK(!w.write(ev));
    }
    CHECK(!w.close());
    CHECK(w.count() == n);
    PmlReader r;
    CHECK(!r.open(path));
    CHECK(r.declaredCount() == n);
    Event got;
    uint32_t i = 0;
    bool inOrder = true;
    while (r.next(got)) {
      if (got.tid != i) inOrder = false;
      ++i;
    }
    CHECK(!r.error());
    CHECK(i == n);
    CHECK(inOrder);
    _wremove(path);
  }
  return g_failures - before;
}
