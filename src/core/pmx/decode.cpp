#include "pmx/decode.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>

#include "pmx/driver/flags.h"
#include "pmx/driver/protocol.h"

namespace pmx {

namespace {
std::wstring widen(const std::string& s) {
  return std::wstring(s.begin(), s.end());  // ASCII-only detail text
}

// Render captured registry value data by type: strings as text, DWORD/QWORD as
// hex, everything else as a capped hex-byte dump. Empty when no data captured.
std::wstring regValuePreview(const proto::RegValueDetail& rv) {
  if (!rv.data || !rv.dataBytes) return {};
  const uint8_t* p = rv.data;
  const uint32_t nb = rv.dataBytes;
  char b[96];
  if (rv.type == 4 && nb >= 4) {  // REG_DWORD
    uint32_t v;
    std::memcpy(&v, p, 4);
    std::snprintf(b, sizeof b, "0x%08X (%u)", v, v);
    return widen(b);
  }
  if (rv.type == 11 && nb >= 8) {  // REG_QWORD
    uint64_t v;
    std::memcpy(&v, p, 8);
    std::snprintf(b, sizeof b, "0x%016llX", static_cast<unsigned long long>(v));
    return widen(b);
  }
  if (rv.type == 1 || rv.type == 2 || rv.type == 7) {  // SZ / EXPAND_SZ / MULTI_SZ
    const auto* w = reinterpret_cast<const wchar_t*>(p);
    size_t wn = nb / 2;
    while (wn && w[wn - 1] == 0) --wn;  // trim trailing NUL(s)
    std::wstring s(w, wn);
    for (auto& c : s)
      if (c == 0) c = L' ';  // MULTI_SZ record separators -> spaces
    if (s.size() > 128) {
      s.resize(128);
      s += L"...";
    }
    return s;
  }
  std::string h;  // REG_BINARY / REG_NONE / other -> hex, capped
  const uint32_t show = nb < 32 ? nb : 32;
  for (uint32_t i = 0; i < show; ++i) {
    char x[4];
    std::snprintf(x, sizeof x, "%02X", p[i]);
    if (i) h += ' ';
    h += x;
  }
  if (nb > show) h += " ...";
  return widen(h);
}

// Anchor-based path extraction for non-FS classes (registry / fallback). FS uses
// the exact length-prefixed field via proto::fsPath.
std::wstring extractPath(std::span<const uint8_t> d) {
  const auto* w = reinterpret_cast<const wchar_t*>(d.data());
  const size_t wn = d.size() / sizeof(wchar_t);
  for (size_t i = 0; i + 1 < wn; ++i) {
    const bool anchor =
        (w[i] == L'\\' && (w[i + 1] == L'D' || w[i + 1] == L'?' ||
                           w[i + 1] == L'R')) ||
        (i + 2 < wn && w[i + 1] == L':' && w[i + 2] == L'\\' &&
         ((w[i] >= L'A' && w[i] <= L'Z') || (w[i] >= L'a' && w[i] <= L'z'))) ||
        (i + 2 < wn && w[i] == L'H' && w[i + 1] == L'K');
    if (!anchor) continue;
    size_t j = i;
    while (j < wn && w[j] >= 0x20 && w[j] < 0xD800) ++j;
    if (j - i >= 4) return std::wstring(w + i, j - i);
  }
  return {};
}
}  // namespace

Event decodeEvent(const CompletedEvent& ce, const ProcessTable& procs) {
  const auto& h = ce.header;
  Event ev;
  ev.sequence = h.sequence;
  ev.timestamp = h.timestamp;
  ev.tid = h.threadId;
  ev.processIndex = h.processIndex;
  ev.eventClass = h.eventClass;
  ev.operation = h.operation;
  ev.result = ce.finalResult;
  ev.information = ce.information;
  ev.completed = ce.completed;
  if (ce.completed && ce.completionTime >= h.timestamp)
    ev.duration = ce.completionTime - h.timestamp;
  ev.className = proto::className(h.eventClass);

  if (const ProcInfo* pi = procs.find(h.processIndex)) {
    ev.pid = pi->pid;
    ev.parentPid = pi->parentId;
    ev.processName = pi->name.empty() ? L"?" : pi->name;
    ev.imagePath = pi->image;
    ev.commandLine = pi->cmdline;
    ev.user = pi->user;
    ev.integrity = pi->integrity;
  } else {
    ev.processName = L"idx#" + std::to_wstring(h.processIndex);
  }

  const uint8_t* d = ce.detail.data();
  const size_t n = ce.detail.size();
  const bool isFs =
      h.eventClass == static_cast<uint16_t>(proto::EventClass::FileSystem) ||
      h.eventClass == static_cast<uint16_t>(proto::EventClass::Class6);
  const bool isReg =
      h.eventClass == static_cast<uint16_t>(proto::EventClass::Registry);
  const uint8_t disc = n ? d[0] : 0;
  if (isFs) ev.fsSubOp = disc;
  ev.opName = isFs ? proto::fileOpNameEx(h.operation, disc)
                   : proto::operationName(h.eventClass, h.operation);

  const bool isProcDef =
      h.eventClass == static_cast<uint16_t>(proto::EventClass::Process) &&
      (h.operation == 0 || h.operation == 1);

  // Object path.
  if (isProcDef) {
    // Process Defined / Create: image + command line are length-prefixed and
    // contiguous (no NUL), so a greedy scan merges them - use the exact fields.
    // Path = the (new) process image; Detail = its PID + command line, as in
    // Procmon.
    proto::ProcessStrings ps;
    if (proto::parseProcessStrings(d, n, ps)) {
      ev.path = proto::win32ImagePath(ps.image, ps.imageLen);
      uint32_t childPid = 0;
      if (n >= sizeof(proto::ProcessDetail))
        childPid = reinterpret_cast<const proto::ProcessDetail*>(d)->processId;
      ev.targetPid = childPid;
      if (ps.cmdline) ev.targetCmdline.assign(ps.cmdline, ps.cmdlineLen);
      ev.detail = L"PID: " + std::to_wstring(childPid);
      if (ps.cmdline) ev.detail += L", Command line: " + ev.targetCmdline;
    }
  } else if (isFs && n) {
    const wchar_t* fp = nullptr;
    size_t fpLen = 0;
    if (proto::fsPath(d, n, fp, fpLen))
      ev.path.assign(fp, fpLen);
    else
      ev.path = extractPath({d, n});
  } else if (n) {
    ev.path = extractPath({d, n});
    if (isReg) {
      // The record declares the exact path length at +0x00; extractPath's greedy
      // scan can run one wchar into allocator padding (RegCloseKey etc.), so clamp.
      const uint16_t pw = proto::regPathWchars(d, n);
      if (pw >= 4 && pw < ev.path.size()) ev.path.resize(pw);
    }
  }

  // Detail column.
  char buf[512] = "";
  if (isFs && n) {
    proto::FileRwDetail rw;
    proto::FileCreateDetail cr;
    if (proto::parseFileRw(h.operation, d, n, rw)) {
      if (rw.offset == UINT64_MAX)
        std::snprintf(buf, sizeof buf, "Offset:end Length:%u", rw.length);
      else
        std::snprintf(buf, sizeof buf, "Offset:%llu Length:%u",
                      static_cast<unsigned long long>(rw.offset), rw.length);
      ev.detail = widen(buf);
      ev.ioOffset = rw.offset;
      ev.ioLength = rw.length;
    } else if (proto::parseFileCreate(h.operation, d, n, cr)) {
      std::string acc = cr.hasDesiredAccess
                            ? proto::accessMaskString(cr.desiredAccess)
                            : std::string("?");
      char alloc[32] = "";
      if ((0x2Du >> (cr.disposition & 7)) & 1)
        std::snprintf(alloc, sizeof alloc, " Alloc:%u", cr.allocationSize);
      char openres[40] = "";
      if (ce.completed && ce.finalResult == 0)
        std::snprintf(openres, sizeof openres, " OpenResult:%s",
                      proto::openResultString(ce.information));
      std::string s = "Access:" + acc +
                      " Disposition:" + proto::createDispositionString(cr.disposition) +
                      " Options:" + proto::createOptionsString(cr.createOptions) +
                      " Attr:" + proto::fileAttributesString(cr.attributes) +
                      " Share:" + proto::shareModeString(cr.shareMode) + alloc +
                      openres;
      ev.detail = widen(s);
      if (cr.hasDesiredAccess) ev.desiredAccess = cr.desiredAccess;
      ev.fsDisposition = cr.disposition;
      ev.fsOptions = cr.createOptions;
      ev.fsAttributes = cr.attributes;
      ev.fsShareMode = cr.shareMode;
      ev.fsAllocation = cr.allocationSize;
    }
  } else if (isReg && n) {
    proto::RegValueDetail rv;
    if (h.operation == 0 || h.operation == 1) {  // RegOpenKey / RegCreateKey
      if (n >= 0x08) {
        uint32_t access;
        std::memcpy(&access, d + 0x04, 4);
        ev.desiredAccess = access;
        std::string s = "Desired Access:" + proto::keyAccessString(access);
        if (h.operation == 1 && ce.completed) {  // Disposition from completion
          const char* disp = proto::regDispositionString(ce.information);
          if (*disp) {
            s += " Disposition:";
            s += disp;
          }
        }
        ev.detail = widen(s);
      }
    } else if (proto::parseRegValue(h.operation, d, n, rv)) {
      // The path field is not null-terminated and the captured data follows it
      // contiguously, so the greedy extractPath above bleeds value bytes into the
      // path ("...\Str" + "hello" -> "...\Strhello"). Re-bound it to the exact
      // nameWchars the record declares.
      if (h.operation == 4 && rv.name)
        ev.path.assign(reinterpret_cast<const wchar_t*>(rv.name), rv.nameWchars);
      // RegSetValue (op 4) carries a valid type + full data at the pre-op, so
      // show Type/Length/Data. RegQueryValue (op 5) has no result at the pre-op
      // (the driver delivers it in a separate post record we don't merge yet),
      // so only surface a type when it actually decodes to a real REG_*.
      std::wstring s;
      if (h.operation == 4) {
        std::snprintf(buf, sizeof buf, "Type:%s Length:%u",
                      proto::regTypeName(rv.type), rv.length);
        s = widen(buf);
        ev.regType = rv.type;
        ev.regLength = rv.length;
        if (rv.data && rv.dataBytes)
          ev.valueData.assign(rv.data, rv.data + rv.dataBytes);
        std::wstring dp = regValuePreview(rv);
        if (!dp.empty()) {
          s += L" Data:";
          s += dp;
        }
      } else {  // op 5 RegQueryValue: result Type/Data live in the completion
        proto::RegQueryResult qr;
        if (!ce.completionDetail.empty() &&
            proto::parseRegQueryResult(ce.completionDetail.data(),
                                       ce.completionDetail.size(), qr) &&
            qr.type < 12) {
          std::snprintf(buf, sizeof buf, "Type:%s Length:%u",
                        proto::regTypeName(qr.type), qr.length);
          s = widen(buf);
          ev.regType = qr.type;
          ev.regLength = qr.length;
          if (qr.data && qr.dataBytes)
            ev.valueData.assign(qr.data, qr.data + qr.dataBytes);
          proto::RegValueDetail pv{};
          pv.type = qr.type;
          pv.length = qr.length;
          pv.dataBytes = qr.dataBytes;
          pv.data = qr.data;
          std::wstring dp = regValuePreview(pv);
          if (!dp.empty()) {
            s += L" Data:";
            s += dp;
          }
        }
      }
      ev.detail = s;
    }
  }
  return ev;
}

}  // namespace pmx
