// Process Monitor .pml reader.
//
// Layout (format v9, x64; see docs + tools/check_pml.py for Procmon's own
// loader rules): 0x3A8-byte header -> events -> events offset array (5-byte
// entries, 40-bit offsets) -> process table -> strings -> icons -> hosts/ports.
// Per-event detail is the raw DRIVER detail record, so classes 1/2/3/4/6 are
// rebuilt into a CompletedEvent and decoded by decodeEvent exactly like a live
// capture. Completion data Procmon keeps in the event's "extra details" blob
// (CreateFile OpenResult, RegCreateKey disposition, RegQueryValue result) is
// mapped back onto the CompletedEvent. The file is untrusted: every read is
// bounds-checked.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstring>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "pmx/decode.h"
#include "pmx/driver/protocol.h"
#include "pmx/enrich/process_table.h"
#include "pmx/file_io.h"
#include "pmx/pml.h"

namespace pmx {

namespace {

std::error_code errc(int e) { return {e, std::system_category()}; }

// Bounds-checked little-endian view over the file bytes.
struct View {
  const uint8_t* p;
  size_t n;
  bool has(uint64_t off, uint64_t len) const {
    return off <= n && len <= n - off;
  }
  uint16_t u16(uint64_t o) const { uint16_t v; std::memcpy(&v, p + o, 2); return v; }
  uint32_t u32(uint64_t o) const { uint32_t v; std::memcpy(&v, p + o, 4); return v; }
  uint64_t u64(uint64_t o) const { uint64_t v; std::memcpy(&v, p + o, 8); return v; }
};

// UTF-16 string of `bytes` at `off`, trailing NULs stripped.
std::wstring wstr(const View& v, uint64_t off, uint64_t bytes) {
  std::wstring s(reinterpret_cast<const wchar_t*>(v.p + off), bytes / 2);
  while (!s.empty() && s.back() == L'\0') s.pop_back();
  return s;
}

std::wstring basename(const std::wstring& p) {
  const size_t s = p.find_last_of(L"\\/");
  return s == std::wstring::npos ? p : p.substr(s + 1);
}

std::wstring ipString(const uint8_t* ip, bool v4) {
  wchar_t buf[64] = L"";
  if (v4) {
    in_addr a;
    std::memcpy(&a, ip, 4);
    InetNtopW(AF_INET, &a, buf, 64);
  } else {
    in6_addr a;
    std::memcpy(&a, ip, 16);
    InetNtopW(AF_INET6, &a, buf, 64);
  }
  return buf;
}

// Procmon's NetworkOperation enum (as written by savePml / Procmon).
const char* netOpName(uint16_t op) {
  static const char* const k[] = {"Unknown",    "Other",    "Send",
                                   "Receive",    "Accept",   "Connect",
                                   "Disconnect", "Reconnect", "Retransmit",
                                   "TCPCopy"};
  return op < 10 ? k[op] : "Unknown";
}

}  // namespace

std::error_code loadPml(const wchar_t* path, std::vector<Event>& out) {
  std::string buf;
  if (std::error_code ec = readWholeFile(path, buf)) return ec;
  const View v{reinterpret_cast<const uint8_t*>(buf.data()), buf.size()};
  const auto bad = [] { return errc(ERROR_INVALID_DATA); };

  // --- Header ---------------------------------------------------------------
  if (!v.has(0, 0x3A8) || std::memcmp(v.p, "PML_", 4) != 0) return bad();
  const uint32_t version = v.u32(4);
  if (version < 4 || version > 9) return errc(ERROR_NOT_SUPPORTED);
  if (!(v.u32(8) & 1)) return errc(ERROR_NOT_SUPPORTED);  // 32-bit log
  const uint32_t count = v.u32(0x234);
  const uint64_t evOff = v.u64(0x240), eoOff = v.u64(0x248),
                 ptOff = v.u64(0x250), stOff = v.u64(0x258),
                 icOff = v.u64(0x260);
  const uint64_t hpOff = version >= 7 ? v.u64(0x3A0) : 0;
  if (!evOff || !eoOff || !ptOff || !stOff || !icOff) return bad();
  if (!(evOff <= eoOff && eoOff <= ptOff && ptOff < stOff && stOff < icOff &&
        icOff <= v.n))
    return bad();
  if (!v.has(eoOff, 5ull * count)) return bad();

  // --- Strings ----------------------------------------------------------------
  std::vector<std::wstring> strings;
  {
    const uint64_t size = icOff - stOff;
    if (!v.has(stOff, 4)) return bad();
    const uint32_t n = v.u32(stOff);
    if (n > (size - 4) / 4) return bad();
    strings.resize(n);
    for (uint32_t i = 0; i < n; ++i) {
      const uint64_t rel = v.u32(stOff + 4 + 4ull * i);
      if (rel + 4 > size) return bad();
      const uint32_t len = v.u32(stOff + rel);
      if (len > size - rel - 4) return bad();
      strings[i] = wstr(v, stOff + rel + 4, len);
    }
  }
  const auto str = [&](uint32_t i) -> std::wstring {
    return i < strings.size() ? strings[i] : std::wstring();
  };

  // --- Process table -> ProcessTable -------------------------------------------
  ProcessTable procs;
  {
    const uint64_t size = stOff - ptOff;
    if (!v.has(ptOff, 4)) return bad();
    const uint32_t n = v.u32(ptOff);
    if (n > (size - 4) / 8) return bad();
    for (uint32_t i = 0; i < n; ++i) {
      const uint64_t rel = v.u32(ptOff + 4 + 4ull * n + 4ull * i);
      if (rel + 0x6C > size) return bad();
      const uint64_t b = ptOff + rel;
      ProcInfo pi;
      pi.pid = v.u32(b + 0x04);
      pi.parentId = v.u32(b + 0x08);
      pi.parentIndex = v.u32(b + 0x0C);
      pi.sessionId = v.u32(b + 0x18);
      pi.createTime = v.u64(b + 0x20);
      pi.integrity = str(v.u32(b + 0x38));
      pi.user = str(v.u32(b + 0x3C));
      pi.name = str(v.u32(b + 0x40));
      pi.image = str(v.u32(b + 0x44));
      pi.cmdline = str(v.u32(b + 0x48));
      if (pi.name.empty()) pi.name = basename(pi.image);
      procs.define(v.u32(b), std::move(pi));
    }
  }

  // --- Hosts / ports (resolved names Procmon shows in network paths) ------------
  std::map<std::string, std::wstring> hosts;           // 16-byte ip -> name
  std::map<std::pair<uint16_t, bool>, std::wstring> ports;
  if (hpOff && v.has(hpOff, 4)) {
    uint64_t p = hpOff;
    const uint32_t nh = v.u32(p);
    p += 4;
    bool ok = true;
    for (uint32_t i = 0; ok && i < nh; ++i) {
      if (!v.has(p, 20)) { ok = false; break; }
      std::string key(reinterpret_cast<const char*>(v.p + p), 16);
      const uint32_t len = v.u32(p + 16);
      p += 20;
      if (!v.has(p, len)) { ok = false; break; }
      hosts[key] = wstr(v, p, len);
      p += len;
    }
    if (ok && v.has(p, 4)) {
      const uint32_t np = v.u32(p);
      p += 4;
      for (uint32_t i = 0; i < np; ++i) {
        if (!v.has(p, 8)) break;
        const uint16_t port = v.u16(p);
        const bool tcp = v.u16(p + 2) != 0;
        const uint32_t len = v.u32(p + 4);
        p += 8;
        if (!v.has(p, len)) break;
        ports[{port, tcp}] = wstr(v, p, len);
        p += len;
      }
    }
  }

  // --- Events -------------------------------------------------------------------
  out.reserve(out.size() + count);
  for (uint32_t i = 0; i < count; ++i) {
    const uint64_t e = eoOff + 5ull * i;
    const uint64_t off = v.u32(e) | (static_cast<uint64_t>(v.p[e + 4]) << 32);
    if (off < evOff || !v.has(off, 0x34) || off + 0x34 > eoOff) return bad();
    const uint32_t cls = v.u32(off + 0x08);
    const uint16_t op = v.u16(off + 0x0C);
    const uint64_t duration = v.u64(off + 0x14);
    const uint64_t ts = v.u64(off + 0x1C);
    const uint32_t result = v.u32(off + 0x24);
    const uint16_t frames = v.u16(off + 0x28);
    const uint32_t dsz = v.u32(off + 0x2C);
    const uint32_t extraOff = v.u32(off + 0x30);
    const uint64_t det = off + 0x34 + 8ull * frames;
    if (!v.has(det, dsz)) return bad();
    if (cls == 0) continue;  // completion records carry no displayable event

    // Extra details: [u16 size][bytes] at event start + extraOff.
    const uint8_t* extra = nullptr;
    uint16_t extraLen = 0;
    if (extraOff && v.has(off + extraOff, 2)) {
      const uint16_t l = v.u16(off + extraOff);
      if (v.has(off + extraOff + 2, l)) {
        extra = v.p + off + extraOff + 2;
        extraLen = l;
      }
    }

    CompletedEvent ce;
    ce.header = {};
    ce.header.processIndex = v.u32(off);
    ce.header.threadId = v.u32(off + 0x04);
    ce.header.eventClass = static_cast<uint16_t>(cls);
    ce.header.operation = op;
    ce.header.sequence = i;  // PML keeps no driver sequence; file order
    ce.header.timestamp = ts;
    ce.header.result = result;
    ce.header.detailSize = dsz;
    ce.detail.assign(v.p + det, v.p + det + dsz);
    ce.finalResult = result;
    ce.completed = result != proto::kStatusPending;
    ce.completionTime = ts + duration;
    if (extra) {
      if ((cls == 3 || cls == 6) && op == 20 && extraLen >= 4) {
        uint32_t openResult;  // CreateFile: IoStatus.Information
        std::memcpy(&openResult, extra, 4);
        ce.information = openResult;
      } else if (cls == 2 && (op == 0 || op == 1) && extraLen >= 8) {
        uint32_t disp;  // {u32 granted access; u32 disposition}
        std::memcpy(&disp, extra + 4, 4);
        ce.information = disp;
      } else if (cls == 2 && op == 5 && dsz >= 12) {
        // RegQueryValue result, per the KeyValueInformationClass at detail+8.
        uint32_t infoClass;
        std::memcpy(&infoClass, ce.detail.data() + 8, 4);
        if (infoClass == 2) {  // Partial: {TitleIndex, Type, DataLength, Data}
          ce.completionDetail.assign(extra, extra + extraLen);
        } else if (infoClass == 1 && extraLen >= 20) {
          // Full: {TitleIndex, Type, DataOffset, DataLength, NameLength, Name}
          // -> rebuild as Partial so decodeEvent's parser applies.
          uint32_t type, dataOff, dataLen;
          std::memcpy(&type, extra + 4, 4);
          std::memcpy(&dataOff, extra + 8, 4);
          std::memcpy(&dataLen, extra + 12, 4);
          std::vector<uint8_t> part(12, 0);
          std::memcpy(part.data() + 4, &type, 4);
          std::memcpy(part.data() + 8, &dataLen, 4);
          if (dataOff <= extraLen) {
            const uint32_t avail = extraLen - dataOff;
            part.insert(part.end(), extra + dataOff,
                        extra + dataOff + (dataLen < avail ? dataLen : avail));
          }
          ce.completionDetail = std::move(part);
        }
      }
    }

    Event ev = decodeEvent(ce, procs);
    ev.duration = duration;

    if (cls == 5) {
      // Network record: u16 flags (bit0 src v4, bit1 dst v4, bit2 tcp), u16,
      // u32 length, 16B src ip, 16B dst ip, u16 sport, u16 dport, multi-sz.
      ev.path.clear();
      ev.detail.clear();
      if (dsz >= 44) {
        const uint8_t* d = ce.detail.data();
        const uint16_t flags = v.u16(det);
        const bool tcp = (flags & 4) != 0;
        uint32_t len;
        std::memcpy(&len, d + 4, 4);
        std::memcpy(ev.netSrcIp, d + 8, 16);
        std::memcpy(ev.netDstIp, d + 24, 16);
        ev.netSrcPort = v.u16(det + 40);
        ev.netDstPort = v.u16(det + 42);
        ev.netFlags = static_cast<uint8_t>(flags & 7);
        ev.ioLength = len;
        auto endpoint = [&](const uint8_t* ip, bool v4, uint16_t port) {
          auto h = hosts.find(std::string(reinterpret_cast<const char*>(ip), 16));
          std::wstring s = h != hosts.end() ? h->second : ipString(ip, v4);
          auto pn = ports.find({port, tcp});
          return s + L":" + (pn != ports.end() ? pn->second : std::to_wstring(port));
        };
        ev.path = endpoint(ev.netSrcIp, flags & 1, ev.netSrcPort) + L" -> " +
                  endpoint(ev.netDstIp, (flags & 2) != 0, ev.netDstPort);
        ev.detail = L"Length: " + std::to_wstring(len);
        ev.opName = std::string(tcp ? "TCP " : "UDP ") + netOpName(op);
      }
    }
    out.push_back(std::move(ev));
  }
  return {};
}

}  // namespace pmx
