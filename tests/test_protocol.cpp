#include "pmx/driver/protocol.h"

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "pmx/decode.h"
#include "pmx/enrich/process_table.h"
#include "test_util.h"

namespace {
//  Synthetic Process Defined/Create detail blob (layout per ).
std::vector<uint8_t> makeProcessDetail(uint32_t idx, uint32_t pid,
                                       const std::wstring& img,
                                       const std::wstring& cmd,
                                       uint8_t sidLen) {
  std::vector<uint8_t> d(0x34 + sidLen + (img.size() + cmd.size()) * 2 + 6, 0xCC);
  std::memset(d.data(), 0, 0x34 + sidLen);
  std::memcpy(d.data() + 0x00, &idx, 4);
  std::memcpy(d.data() + 0x04, &pid, 4);
  d[0x2C] = sidLen;
  d[0x2D] = 0;
  uint16_t ic = static_cast<uint16_t>(img.size());
  uint16_t cc = static_cast<uint16_t>(cmd.size());
  std::memcpy(d.data() + 0x2E, &ic, 2);
  std::memcpy(d.data() + 0x30, &cc, 2);
  std::memcpy(d.data() + 0x34 + sidLen, img.data(), img.size() * 2);
  std::memcpy(d.data() + 0x34 + sidLen + img.size() * 2, cmd.data(),
              cmd.size() * 2);
  return d;  // trailing 0xCC bytes = allocator padding a greedy scan would eat
}
}  // namespace

int test_protocol() {
  int before = g_failures;
  using namespace pmx::proto;
  CHECK(sizeof(SetCaptureMsg) == 8);
  CHECK(sizeof(SetIntervalMsg) == 12);
  CHECK(sizeof(EventRecordHeader) == 0x34);

  // Record-size formula: header + 8*frames + detail.
  EventRecordHeader h{};
  h.frameCount = 5;
  h.detailSize = 40;
  CHECK(recordSize(h) == 0x34 + 8 * 5 + 40);

  //  Confirmed offsets from the walker.
  CHECK(offsetof(EventRecordHeader, eventClass) == 0x08);
  CHECK(offsetof(EventRecordHeader, frameCount) == 0x28);
  CHECK(offsetof(EventRecordHeader, detailSize) == 0x2C);

  // Interval encoding.
  SetIntervalMsg m{static_cast<uint32_t>(Op::SetInterval), kIntervalUnitsPerSec / 10};
  CHECK(m.interval == 1'000'000);

  // Operation-name tables.
  CHECK(std::string_view(operationName(1, 1)) == "Process Create");
  CHECK(std::string_view(operationName(1, 5)) == "Load Image");
  CHECK(std::string_view(operationName(2, 0)) == "RegOpenKey");
  CHECK(std::string_view(operationName(2, 4)) == "RegSetValue");
  CHECK(std::string_view(operationName(3, 20)) == "CreateFile");
  CHECK(std::string_view(operationName(3, 24)) == "WriteFile");
  CHECK(std::string_view(operationName(3, 26)) == "SetInformationFile");
  CHECK(std::string_view(operationName(6, 20)) == "CreateFile");  // class 6 == FS
  CHECK(std::string_view(operationName(4, 0)) == "Thread Profiling");
  CHECK(std::string_view(operationName(3, 999)) == "?");
  CHECK(std::string_view(operationName(0, 0)) == "?");

  // FileSystem sub-operation refinement (discriminator = detail[0]).
  CHECK(std::string_view(fileSubOpName(26, 13)) == "SetDispositionInformationFile");
  CHECK(std::string_view(fileSubOpName(26, 10)) == "SetRenameInformationFile");
  CHECK(std::string_view(fileSubOpName(25, 18)) == "QueryAllInformationFile");
  CHECK(std::string_view(fileSubOpName(25, 9)) == "QueryNameInformationFile");
  CHECK(std::string_view(fileSubOpName(25, 5)) == "QueryStandardInformationFile");
  CHECK(std::string_view(fileSubOpName(30, 3)) == "QuerySizeInformationVolume");
  CHECK(std::string_view(fileSubOpName(37, 1)) == "LockFile");
  CHECK(std::string_view(fileSubOpName(47, 0)) == "StartDevice");
  CHECK(fileSubOpName(26, 99) == nullptr);      // unknown class -> fallback
  CHECK(fileSubOpName(20, 0) == nullptr);       // CreateFile has no sub-table
  // fileOpNameEx: refine when known, else top-level friendly name.
  CHECK(std::string_view(fileOpNameEx(26, 13)) == "SetDispositionInformationFile");
  CHECK(std::string_view(fileOpNameEx(26, 99)) == "SetInformationFile");
  CHECK(std::string_view(fileOpNameEx(20, 0)) == "CreateFile");
  //  Driver capture mask per class (bits from ); process bit
  // always present (names depend on it).
  CHECK(kCaptureDefault == 0x7);
  CHECK(captureFlagsForClass(3) == 0x3);
  CHECK(captureFlagsForClass(6) == 0x3);
  CHECK(captureFlagsForClass(2) == 0x5);
  CHECK(captureFlagsForClass(1) == 0x1);
  CHECK(captureFlagsForClass(5) == 0x1);
  CHECK(captureFlagsForClass(0) == 0x7);
  // Registry is registered iff (flags & 0xC) == 0x4.
  CHECK(((captureFlagsForClass(2) & 0xC) == 0x4));
  // Inverse lookup (recovers the sub-op byte for pre-v7 .pmxlog files).
  CHECK(fileSubOpFromName(25, "QueryNameInformationFile") == 9);
  CHECK(fileSubOpFromName(32, "QueryDirectory") == 1);
  CHECK(fileSubOpFromName(25, "QueryInformationFile") == 0);

  // Read/Write numeric fields: Length @ detail+0x10 (u32), Offset @ +0x20 (u64).
  {
    uint8_t d[0x28] = {};
    uint32_t len = 0x1000;
    uint64_t off = 0x0000000123456789ull;
    std::memcpy(d + 0x10, &len, 4);
    std::memcpy(d + 0x20, &off, 8);
    FileRwDetail rw{};
    CHECK(parseFileRw(23, d, sizeof d, rw));  // ReadFile
    CHECK(rw.length == 0x1000);
    CHECK(rw.offset == 0x0000000123456789ull);
    CHECK(parseFileRw(24, d, sizeof d, rw));  // WriteFile
    CHECK(!parseFileRw(20, d, sizeof d, rw));  // not a R/W op
    CHECK(!parseFileRw(23, d, 0x20, rw));      // too short
  }
  // Exact FS path from the +0x40 length prefix.
  {
    uint8_t d[0x44 + 10] = {};
    const wchar_t name[] = L"\\Dev";  // 4 chars
    uint16_t pfx = 4;
    std::memcpy(d + 0x40, &pfx, 2);
    std::memcpy(d + 0x44, name, 4 * sizeof(wchar_t));
    const wchar_t* p = nullptr;
    size_t plen = 0;
    CHECK(fsPath(d, sizeof d, p, plen));
    CHECK(plen == 4);
    CHECK(std::wstring_view(p, plen) == L"\\Dev");
    uint16_t big = 9999;  // longer than buffer -> reject
    std::memcpy(d + 0x40, &big, 2);
    CHECK(!fsPath(d, sizeof d, p, plen));
  }
  // CreateFile: Options = low 24 bits @ +0x18; Desired Access at post-path.
  {
    uint8_t d[0x50] = {};
    uint32_t packed = 0xAB000064u;  // top byte 0xAB, options 0x000064
    std::memcpy(d + 0x18, &packed, 4);
    uint16_t pfx = 2;               // 2 chars, unit 2 -> 4 path bytes
    std::memcpy(d + 0x40, &pfx, 2);
    uint32_t acc = 0x00120089u;     // ACCESS_MASK
    std::memcpy(d + 0x44 + 4, &acc, 4);  // at path-end (0x48)
    FileCreateDetail cr{};
    CHECK(parseFileCreate(20, d, sizeof d, cr));
    CHECK(cr.createOptions == 0x000064u);
    CHECK(cr.disposition == 0xAB);
    CHECK(cr.hasDesiredAccess);
    CHECK(cr.desiredAccess == 0x00120089u);
    CHECK(!parseFileCreate(23, d, sizeof d, cr));  // wrong op
  }
  // Registry value detail: Type @ +0x04, Length @ +0x08.
  {
    uint8_t d[0x10] = {};
    uint32_t type = 4;      // REG_DWORD
    uint32_t len = 4;
    std::memcpy(d + 0x04, &type, 4);
    std::memcpy(d + 0x08, &len, 4);
    RegValueDetail rv{};
    CHECK(parseRegValue(4, d, sizeof d, rv));   // RegSetValue
    CHECK(rv.type == 4);
    CHECK(rv.length == 4);
    CHECK(parseRegValue(5, d, sizeof d, rv));   // RegQueryValue
    CHECK(!parseRegValue(0, d, sizeof d, rv));  // RegOpenKey — no value detail
  }
  // Process Defined/Create strings: SID blob len d[0x2C]+d[0x2D], image count
  // @0x2E, cmdline count @0x30, image @0x34+sidLen, cmdline contiguous after.
  {
    const std::wstring img = L"\\??\\C:\\x\\a.exe";
    const std::wstring cmd = L"a.exe -v";
    std::vector<uint8_t> d = makeProcessDetail(7, 1234, img, cmd, /*sid*/ 5);
    ProcessStrings ps;
    CHECK(parseProcessStrings(d.data(), d.size(), ps));
    CHECK(std::wstring_view(ps.image, ps.imageLen) == img);
    CHECK(ps.cmdline && std::wstring_view(ps.cmdline, ps.cmdlineLen) == cmd);
    CHECK(win32ImagePath(ps.image, ps.imageLen) == L"C:\\x\\a.exe");
    CHECK(win32ImagePath(L"C:\\y", 4) == L"C:\\y");
    CHECK(!parseProcessStrings(d.data(), 0x34 + 5 + 2, ps));  // truncated image
  }
  // ProcessTable learns processes from BOTH op0 (rundown) and op1 (Process
  // Create, emitted in the creator's context but describing the child), and
  // decodeEvent renders Path = image (not image+cmdline merged).
  {
    std::vector<uint8_t> det =
        makeProcessDetail(/*childIdx*/ 42, /*pid*/ 0, L"\\??\\C:\\g\\git.exe",
                          L"git.exe status", 3);
    EventRecordHeader hh{};
    hh.processIndex = 9;  // creator
    hh.eventClass = 1;
    hh.operation = 1;     // Process Create
    hh.detailSize = static_cast<uint32_t>(det.size());
    pmx::RawRecord rr{&hh, {}, {det.data(), det.size()}};
    pmx::ProcessTable procs;
    CHECK(procs.consume(rr));
    const pmx::ProcInfo* child = procs.find(42);
    CHECK(child && child->name == L"git.exe");
    CHECK(child && child->image == L"C:\\g\\git.exe");
    CHECK(child && child->cmdline == L"git.exe status");
    CHECK(procs.find(9) == nullptr);  // creator not overwritten

    pmx::CompletedEvent ce;
    ce.header = hh;
    ce.detail = det;
    pmx::Event ev = pmx::decodeEvent(ce, procs);
    CHECK(ev.path == L"C:\\g\\git.exe");
    CHECK(ev.detail == L"PID: 0, Command line: git.exe status");
  }
  return g_failures - before;
}
