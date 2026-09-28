#include "pmx/store.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "pmx/driver/protocol.h"
#include "pmx/file_io.h"
#include "pmx/filter.h"  // statusName

namespace pmx {

namespace {
constexpr uint32_t kMagic = 0x31584D50;  // "PMX1"
constexpr uint32_t kVersion = 7;

std::error_code errc(int e) { return {e, std::system_category()}; }

std::string wToUtf8(const std::wstring& s) {
  if (s.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0,
                              nullptr, nullptr);
  std::string o(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), o.data(), n, nullptr,
                      nullptr);
  return o;
}
std::wstring utf8ToW(const char* p, size_t len) {
  if (!len) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, p, (int)len, nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, p, (int)len, w.data(), n);
  return w;
}

// Little-endian POD append helpers.
void putU32(std::string& b, uint32_t v) { b.append((const char*)&v, 4); }
void putU64(std::string& b, uint64_t v) { b.append((const char*)&v, 8); }
void putStrW(std::string& b, const std::wstring& s) {
  std::string u = wToUtf8(s);
  putU32(b, (uint32_t)u.size());
  b.append(u);
}
void putStrA(std::string& b, const std::string& s) {
  putU32(b, (uint32_t)s.size());
  b.append(s);
}
void putBytes(std::string& b, const std::vector<uint8_t>& v) {
  putU32(b, (uint32_t)v.size());
  b.append((const char*)v.data(), v.size());
}

struct Reader {
  const char* p;
  const char* end;
  bool ok = true;
  uint32_t u32() {
    if (p + 4 > end) { ok = false; return 0; }
    uint32_t v;
    std::memcpy(&v, p, 4);
    p += 4;
    return v;
  }
  uint64_t u64() {
    if (p + 8 > end) { ok = false; return 0; }
    uint64_t v;
    std::memcpy(&v, p, 8);
    p += 8;
    return v;
  }
  std::wstring strW() {
    uint32_t n = u32();
    if (!ok || p + n > end) { ok = false; return {}; }
    std::wstring w = utf8ToW(p, n);
    p += n;
    return w;
  }
  std::string strA() {
    uint32_t n = u32();
    if (!ok || p + n > end) { ok = false; return {}; }
    std::string s(p, n);
    p += n;
    return s;
  }
  std::vector<uint8_t> bytes() {
    uint32_t n = u32();
    if (!ok || p + n > end) { ok = false; return {}; }
    std::vector<uint8_t> v(p, p + n);
    p += n;
    return v;
  }
  void raw(void* dst, uint32_t n) {
    if (!ok || p + n > end) { ok = false; return; }
    std::memcpy(dst, p, n);
    p += n;
  }
};
}  // namespace

void appendEventRecord(std::string& b, const Event& e) {
  putU32(b, e.sequence);
  putU64(b, e.timestamp);
  putU32(b, e.processIndex);
  putU32(b, e.pid);
  putU32(b, e.parentPid);
  putU32(b, e.eventClass);
  putU32(b, e.operation);
  putU32(b, e.result);
  putU64(b, e.information);
  putU64(b, e.duration);
  putU32(b, e.completed ? 1u : 0u);
  putStrW(b, e.processName);
  putStrW(b, e.imagePath);
  putStrW(b, e.commandLine);
  putStrW(b, e.user);
  putStrW(b, e.integrity);
  putStrA(b, e.opName);
  putStrA(b, e.className);
  putStrW(b, e.path);
  putStrW(b, e.detail);
  putU32(b, e.desiredAccess);
  putU32(b, e.regType);
  putU32(b, e.regLength);
  putBytes(b, e.valueData);
  putU32(b, e.fsDisposition);
  putU32(b, e.fsOptions);
  putU32(b, e.fsAllocation);
  putU32(b, e.fsAttributes);
  putU32(b, e.fsShareMode);
  putU64(b, e.ioOffset);
  putU32(b, e.ioLength);
  putU32(b, e.tid);
  b.append(reinterpret_cast<const char*>(e.netSrcIp), 16);
  b.append(reinterpret_cast<const char*>(e.netDstIp), 16);
  putU32(b, e.netSrcPort);
  putU32(b, e.netDstPort);
  putU32(b, e.netFlags);
  putU32(b, e.targetPid);
  putStrW(b, e.targetCmdline);
  putU32(b, e.fsSubOp);
}

bool readEventRecord(const char*& p, const char* end, uint32_t version, Event& e) {
  e = Event{};  // older versions leave later fields unset; callers reuse `e`
  Reader r{p, end};
  e.sequence = r.u32();
  e.timestamp = r.u64();
  e.processIndex = r.u32();
  e.pid = r.u32();
  e.parentPid = r.u32();
  e.eventClass = (uint16_t)r.u32();
  e.operation = (uint16_t)r.u32();
  e.result = r.u32();
  e.information = r.u64();
  e.duration = r.u64();
  e.completed = r.u32() != 0;
  e.processName = r.strW();
  e.imagePath = r.strW();
  e.commandLine = r.strW();
  e.user = r.strW();
  e.integrity = r.strW();
  e.opName = r.strA();
  e.className = r.strA();
  e.path = r.strW();
  e.detail = r.strW();
  if (version >= 2) {
    e.desiredAccess = r.u32();
    e.regType = r.u32();
    e.regLength = r.u32();
    e.valueData = r.bytes();
  }
  if (version >= 3) {
    e.fsDisposition = r.u32();
    e.fsOptions = r.u32();
    e.fsAllocation = r.u32();
    e.fsAttributes = (uint16_t)r.u32();
    e.fsShareMode = (uint16_t)r.u32();
    e.ioOffset = r.u64();
    e.ioLength = r.u32();
  }
  if (version >= 4) e.tid = r.u32();
  if (version >= 5) {
    r.raw(e.netSrcIp, 16);
    r.raw(e.netDstIp, 16);
    e.netSrcPort = (uint16_t)r.u32();
    e.netDstPort = (uint16_t)r.u32();
    e.netFlags = (uint8_t)r.u32();
  }
  if (version >= 6) {
    e.targetPid = r.u32();
    e.targetCmdline = r.strW();
  }
  if (version >= 7) {
    e.fsSubOp = (uint8_t)r.u32();
  } else if (e.eventClass == 3 || e.eventClass == 6) {
    // Pre-v7 logs didn't keep the raw byte: recover it from the refined op
    // name decode produced (e.g. "QueryNameInformationFile" -> 9).
    e.fsSubOp = proto::fileSubOpFromName(e.operation, e.opName.c_str());
  }
  p = r.p;
  return r.ok;
}

std::error_code PmxlogWriter::open(const wchar_t* path) {
  if (std::error_code ec = file_.open(path)) return ec;
  count_ = 0;
  uint32_t hdr[4] = {kMagic, kVersion, 0, 0};
  return file_.write(hdr, sizeof hdr);
}

std::error_code PmxlogWriter::write(const Event& e) {
  if (count_ >= UINT32_MAX) return errc(ERROR_FILE_TOO_LARGE);
  std::string rec;
  appendEventRecord(rec, e);
  if (std::error_code ec = file_.write(rec.data(), rec.size())) return ec;
  ++count_;
  return {};
}

std::error_code PmxlogWriter::close() {
  uint32_t count32 = (uint32_t)count_;
  if (std::error_code ec = file_.patch(8, &count32, 4)) return ec;
  return file_.close();
}

std::error_code saveEvents(const wchar_t* path, std::span<const Event> events) {
  PmxlogWriter w;
  if (std::error_code ec = w.open(path)) return ec;
  for (const Event& e : events) {
    if (std::error_code ec = w.write(e)) {
      w.close();
      return ec;
    }
  }
  return w.close();
}

namespace {
void csvField(std::string& out, const std::string& s) {
  out.push_back('"');
  // Captured names are attacker-chosen: a leading = + - @ (or tab/CR) would
  // run as a formula when the CSV is opened in a spreadsheet.
  if (!s.empty() && s[0] && std::strchr("=+-@\t\r", s[0])) out.push_back('\'');
  for (char c : s) {
    if (c == '"') out.push_back('"');  // double the quote
    out.push_back(c);
  }
  out.push_back('"');
}
std::string timeOfDay(uint64_t filetime) {
  FILETIME ft{static_cast<DWORD>(filetime), static_cast<DWORD>(filetime >> 32)};
  FILETIME lft{};
  SYSTEMTIME st{};
  FileTimeToLocalFileTime(&ft, &lft);
  FileTimeToSystemTime(&lft, &st);
  // 100ns fraction within the second (7 digits, Procmon-style).
  uint32_t frac = static_cast<uint32_t>(filetime % 10000000ull);
  char b[32];
  std::snprintf(b, sizeof b, "%02u:%02u:%02u.%07u", st.wHour, st.wMinute,
                st.wSecond, frac);
  return b;
}
}  // namespace

namespace {
constexpr char kCsvHeader[] =
    "\"Time of Day\",\"Process Name\",\"PID\",\"User\",\"Integrity\","
    "\"Operation\",\"Path\",\"Result\",\"Detail\",\"Duration\"\r\n";

void appendCsvRow(std::string& b, const Event& e) {
  csvField(b, timeOfDay(e.timestamp));
  b.push_back(',');
  csvField(b, wToUtf8(e.processName));
  b.push_back(',');
  csvField(b, std::to_string(e.pid));
  b.push_back(',');
  csvField(b, wToUtf8(e.user));
  b.push_back(',');
  csvField(b, wToUtf8(e.integrity));
  b.push_back(',');
  csvField(b, e.opName);
  b.push_back(',');
  csvField(b, wToUtf8(e.path));
  b.push_back(',');
  csvField(b, statusName(e.result));
  b.push_back(',');
  csvField(b, wToUtf8(e.detail));
  b.push_back(',');
  char dur[32] = "";
  if (e.duration)
    std::snprintf(dur, sizeof dur, "%.7f", (double)e.duration / 1e7);
  csvField(b, dur);
  b.append("\r\n");
}
}  // namespace

std::error_code CsvWriter::open(const wchar_t* path) {
  if (std::error_code ec = file_.open(path)) return ec;
  count_ = 0;
  return file_.write(kCsvHeader, sizeof(kCsvHeader) - 1);
}

std::error_code CsvWriter::write(const Event& e) {
  std::string row;
  appendCsvRow(row, e);
  if (std::error_code ec = file_.write(row.data(), row.size())) return ec;
  ++count_;
  return {};
}

std::error_code CsvWriter::close() { return file_.close(); }

std::error_code saveEventsCsv(const wchar_t* path,
                              std::span<const Event> events) {
  CsvWriter w;
  if (std::error_code ec = w.open(path)) return ec;
  for (const Event& e : events) {
    if (std::error_code ec = w.write(e)) {
      w.close();
      return ec;
    }
  }
  return w.close();
}

namespace {
// JSON string literal from UTF-8 (RFC 8259 escaping; control chars as \u00XX).
void jsonStr(std::string& out, const std::string& s) {
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char b[8];
          std::snprintf(b, sizeof b, "\\u%04x", c);
          out += b;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
}

// ISO-8601 UTC with the full 100ns FILETIME precision.
std::string isoUtc(uint64_t filetime) {
  FILETIME ft{static_cast<DWORD>(filetime), static_cast<DWORD>(filetime >> 32)};
  SYSTEMTIME st{};
  FileTimeToSystemTime(&ft, &st);
  char b[40];
  std::snprintf(b, sizeof b, "%04u-%02u-%02uT%02u:%02u:%02u.%07uZ", st.wYear,
                st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                static_cast<unsigned>(filetime % 10000000ull));
  return b;
}
}  // namespace

std::string eventToJson(const Event& e) {
  std::string o = "{";
  auto key = [&](const char* k) {
    if (o.size() > 1) o.push_back(',');
    o.push_back('"');
    o += k;
    o += "\":";
  };
  auto s = [&](const char* k, const std::string& v) { key(k); jsonStr(o, v); };
  auto w = [&](const char* k, const std::wstring& v) { key(k); jsonStr(o, wToUtf8(v)); };
  auto n = [&](const char* k, uint64_t v) { key(k); o += std::to_string(v); };
  s("time", isoUtc(e.timestamp));
  n("ts", e.timestamp);
  s("class", e.className);
  s("op", e.opName);
  w("process", e.processName);
  n("pid", e.pid);
  n("tid", e.tid);
  n("ppid", e.parentPid);
  w("user", e.user);
  w("integrity", e.integrity);
  w("path", e.path);
  s("result", statusName(e.result));
  char st[16];
  std::snprintf(st, sizeof st, "0x%08X", e.result);
  s("status", st);
  w("detail", e.detail);
  key("duration");
  char d[32];
  std::snprintf(d, sizeof d, "%.7f", static_cast<double>(e.duration) / 1e7);
  o += d;
  w("image", e.imagePath);
  w("cmdline", e.commandLine);
  o.push_back('}');
  return o;
}

std::error_code JsonWriter::open(const wchar_t* path) {
  count_ = 0;
  return file_.open(path);
}

std::error_code JsonWriter::write(const Event& e) {
  std::string line = eventToJson(e);
  line += '\n';
  if (std::error_code ec = file_.write(line.data(), line.size())) return ec;
  ++count_;
  return {};
}

std::error_code JsonWriter::close() { return file_.close(); }

std::error_code saveEventsJson(const wchar_t* path,
                               std::span<const Event> events) {
  JsonWriter w;
  if (std::error_code ec = w.open(path)) return ec;
  for (const Event& e : events) {
    if (std::error_code ec = w.write(e)) {
      w.close();
      return ec;
    }
  }
  return w.close();
}

std::error_code PmxlogReader::open(const wchar_t* path) {
  if (std::error_code ec = file_.open(path)) return ec;
  const char* p = reinterpret_cast<const char*>(file_.data());
  const char* end = p + file_.size();
  Reader r{p, end};
  if (r.u32() != kMagic) return errc(ERROR_INVALID_DATA);
  version_ = r.u32();
  if (!r.ok || version_ < 1 || version_ > kVersion) return errc(ERROR_INVALID_DATA);
  declaredCount_ = r.u32();
  r.u32();  // reserved
  if (!r.ok) return errc(ERROR_INVALID_DATA);
  p_ = r.p;
  end_ = end;
  recordsRead_ = 0;
  return {};
}

bool PmxlogReader::next(Event& e) {
  if (err_) return false;
  if (declaredCount_ > 0) {
    // Trust the header count exactly, like the old whole-file loader: stop
    // cleanly once it's satisfied, but a short file still fails as truncated
    // (readEventRecord bounds-checks) rather than silently under-reading.
    if (recordsRead_ >= declaredCount_) return false;
  } else if (p_ >= end_) {
    // count==0 with no data following is a genuinely empty log; count==0 with
    // data following (see class comment) is handled below by reading on.
    return false;
  }
  if (!readEventRecord(p_, end_, version_, e)) {
    err_ = errc(ERROR_INVALID_DATA);
    return false;
  }
  ++recordsRead_;
  return true;
}

std::error_code loadEvents(const wchar_t* path, std::vector<Event>& out) {
  PmxlogReader r;
  if (std::error_code ec = r.open(path)) return ec;
  Event e;
  while (r.next(e)) out.push_back(std::move(e));
  return r.error();
}

}  // namespace pmx
