#include "pmx/store.h"

#include <string>

#include "pmx/pml.h"

#include <cstdio>
#include <cstring>
#include <vector>

#include "test_util.h"

int test_store() {
  int before = g_failures;
  using namespace pmx;

  std::vector<Event> in;
  {
    Event e;
    e.sequence = 42;
    e.timestamp = 0x01D4FFFFAABBCCDDull;
    e.processIndex = 7;
    e.pid = 1234;
    e.parentPid = 4;
    e.eventClass = 3;
    e.operation = 20;
    e.result = 0xC0000034;
    e.information = 2;
    e.duration = 1234567;
    e.completed = true;
    e.processName = L"claude.exe";
    e.imagePath = L"C:\\Program Files\\claude.exe";
    e.commandLine = L"\"claude.exe\" --flag";
    e.opName = "CreateFile";
    e.className = "FileSystem";
    e.path = L"\\Device\\HarddiskVolume5\\Users\\und3ath\\file.txt";
    e.detail = L"Access:Generic Read Disposition:Open";
    in.push_back(e);

    Event e2;
    e2.sequence = 43;
    e2.pid = 4;
    e2.eventClass = 3;
    e2.operation = 24;
    e2.result = 0;
    e2.processName = L"System";
    e2.opName = "WriteFile";
    e2.className = "FileSystem";
    e2.path = L"\\Device\\HarddiskVolume5\\pagefile.sys";
    e2.detail = L"Offset:0 Length:4096";
    in.push_back(e2);

    Event e3;  // v6: Process Create target (child) fields
    e3.eventClass = 1;
    e3.operation = 1;
    e3.processName = L"cmd.exe";
    e3.opName = "Process Create";
    e3.className = "Process";
    e3.path = L"C:\\Windows\\system32\\conhost.exe";
    e3.targetPid = 5555;
    e3.targetCmdline = L"conhost.exe 0xffffffff -ForceV1";
    in.push_back(e3);

    Event e4;  // v7: FS sub-operation byte
    e4.eventClass = 3;
    e4.operation = 25;
    e4.fsSubOp = 9;
    e4.opName = "QueryNameInformationFile";
    e4.className = "FileSystem";
    in.push_back(e4);
  }

  const wchar_t* path = L"pmx_test_store.pmxlog";
  CHECK(!saveEvents(path, in));

  std::vector<Event> out;
  CHECK(!loadEvents(path, out));
  CHECK(out.size() == in.size());
  if (out.size() == in.size()) {
    for (size_t i = 0; i < in.size(); ++i) {
      CHECK(out[i].sequence == in[i].sequence);
      CHECK(out[i].timestamp == in[i].timestamp);
      CHECK(out[i].pid == in[i].pid);
      CHECK(out[i].eventClass == in[i].eventClass);
      CHECK(out[i].operation == in[i].operation);
      CHECK(out[i].result == in[i].result);
      CHECK(out[i].information == in[i].information);
      CHECK(out[i].duration == in[i].duration);
      CHECK(out[i].completed == in[i].completed);
      CHECK(out[i].processName == in[i].processName);
      CHECK(out[i].imagePath == in[i].imagePath);
      CHECK(out[i].commandLine == in[i].commandLine);
      CHECK(out[i].opName == in[i].opName);
      CHECK(out[i].className == in[i].className);
      CHECK(out[i].path == in[i].path);
      CHECK(out[i].detail == in[i].detail);
      CHECK(out[i].targetPid == in[i].targetPid);
      CHECK(out[i].targetCmdline == in[i].targetCmdline);
      CHECK(out[i].fsSubOp == in[i].fsSubOp);
    }
  }

  // A corrupt header claiming ~4G events must fail cleanly (no huge reserve).
  {
    std::vector<uint8_t> bad(16, 0);
    const uint32_t hdr[4] = {0x31584D50u, 6u, 0xFFFFFFF0u, 0u};
    std::memcpy(bad.data(), hdr, sizeof hdr);
    FILE* f = _wfopen(path, L"wb");
    if (f) {
      std::fwrite(bad.data(), 1, bad.size(), f);
      std::fclose(f);
    }
    std::vector<Event> junk;
    CHECK(!!loadEvents(path, junk));  // truncated -> ERROR_INVALID_DATA
    CHECK(junk.empty());
  }

  _wremove(path);

  // JSON Lines: escaping + fields.
  {
    Event e;
    e.timestamp = 0x01D4FFFFAABBCCDDull;
    e.pid = 42;
    e.processName = L"a\"b.exe";
    e.path = L"C:\\x\ny";
    e.className = "FileSystem";
    e.opName = "CreateFile";
    e.result = 0xC0000034;
    e.duration = 15;
    const std::string j = eventToJson(e);
    CHECK(j.find("\"process\":\"a\\\"b.exe\"") != std::string::npos);
    CHECK(j.find("\"path\":\"C:\\\\x\\ny\"") != std::string::npos);
    CHECK(j.find("\"result\":\"NAME_NOT_FOUND\"") != std::string::npos);
    CHECK(j.find("\"status\":\"0xC0000034\"") != std::string::npos);
    CHECK(j.find("\"pid\":42") != std::string::npos);
    CHECK(j.find("\"duration\":0.0000015") != std::string::npos);
    CHECK(j.find('\n') == std::string::npos);  // one line
    CHECK(j.front() == '{' && j.back() == '}');
  }

  //  PML: invariants Procmon's loader enforces - rejected as
  // "corrupt" otherwise: process indexes strictly ascending, byte +96 of each
  // process struct == 1, every non-empty string's size includes a final NUL.
  {
    std::vector<Event> pe;
    uint64_t ts = 400;
    for (uint32_t idx : {9u, 3u, 0x80000004u, 5u}) {  // deliberately unsorted
      Event e;
      e.timestamp = ts -= 100;  // also reverse-chronological
      e.processIndex = idx;
      e.pid = idx & 0xFFFF;
      e.processName = L"p" + std::to_wstring(idx) + L".exe";
      e.eventClass = 3;
      e.operation = 20;
      e.path = L"C:\\x";
      pe.push_back(e);
    }
    const wchar_t* pml = L"pmx_test_store.pml";
    CHECK(!savePml(pml, pe));
    std::vector<uint8_t> d;
    if (FILE* f = _wfopen(pml, L"rb")) {
      uint8_t buf[4096];
      size_t n;
      while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) d.insert(d.end(), buf, buf + n);
      std::fclose(f);
    }
    auto rd32 = [&](size_t o) { uint32_t v; std::memcpy(&v, d.data() + o, 4); return v; };
    auto rd64 = [&](size_t o) { uint64_t v; std::memcpy(&v, d.data() + o, 8); return v; };
    CHECK(d.size() > 0x3A8);
    if (d.size() > 0x3A8) {
      const size_t pt = (size_t)rd64(0x250), st = (size_t)rd64(0x258);
      const uint32_t np = rd32(pt);
      CHECK(np == 4);
      for (uint32_t i = 0; i < np; ++i) {
        if (i) CHECK(rd32(pt + 4 + 4 * i) > rd32(pt + 4 + 4 * (i - 1)));
        const size_t s = pt + rd32(pt + 4 + 4 * np + 4 * i);
        CHECK(d[s + 96] == 1);
        CHECK(rd32(s) == rd32(pt + 4 + 4 * i));
      }
      // Events written in chronological order (else blank rows in Procmon).
      const size_t eo = (size_t)rd64(0x248);
      const uint32_t ne = rd32(0x234);
      CHECK(ne == 4);
      for (uint32_t i = 1; i < ne; ++i) {
        const size_t a = rd32(eo + 5 * (i - 1)), b = rd32(eo + 5 * i);
        CHECK(rd64(b + 0x1C) >= rd64(a + 0x1C));
      }
      const uint32_t ns = rd32(st);
      for (uint32_t i = 0; i < ns; ++i) {
        const size_t so = st + rd32(st + 4 + 4 * i);
        const uint32_t len = rd32(so);
        if (len) {
          CHECK(len % 2 == 0);
          CHECK(d[so + 4 + len - 2] == 0 && d[so + 4 + len - 1] == 0);
        }
      }
    }
    _wremove(pml);
  }
  return g_failures - before;
}
