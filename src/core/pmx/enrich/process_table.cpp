#include "pmx/enrich/process_table.h"

#include <windows.h>
#include <sddl.h>

#include <cstring>
#include <vector>

#include "pmx/driver/protocol.h"

namespace pmx {

namespace {
const char* integrityFromRid(DWORD rid) {
  if (rid >= 0x5000) return "Protected";
  if (rid >= 0x4000) return "System";
  if (rid >= 0x3000) return "High";
  if (rid >= 0x2100) return "Medium+";
  if (rid >= 0x2000) return "Medium";
  if (rid >= 0x1000) return "Low";
  return "Untrusted";
}


std::wstring basename(const std::wstring& path) {
  const size_t slash = path.find_last_of(L"\\/");
  return slash == std::wstring::npos ? path : path.substr(slash + 1);
}
}  // namespace

// Best-effort: read the process token's user + integrity (once per process).
// The costly LSA SID->name lookup is memoized in sidCache_ across processes.
void ProcessTable::resolveToken(uint32_t pid, std::wstring& user,
                                std::wstring& integrity) {
  if (pid == 0) {  // Idle
    user = L"NT AUTHORITY\\SYSTEM";
    integrity = L"System";
    return;
  }
  HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!proc) return;
  HANDLE tok = nullptr;
  if (OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    if (len) {
      std::vector<uint8_t> buf(len);
      if (GetTokenInformation(tok, TokenUser, buf.data(), len, &len)) {
        PSID sid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(sid, &sidStr)) {
          std::wstring key = sidStr;
          LocalFree(sidStr);
          auto it = sidCache_.find(key);
          if (it != sidCache_.end()) {
            user = it->second;  // cache hit — no LSA call
          } else {
            wchar_t name[256], dom[256];
            DWORD nl = 256, dl = 256;
            SID_NAME_USE use;
            if (LookupAccountSidW(nullptr, sid, name, &nl, dom, &dl, &use))
              user = dl ? std::wstring(dom) + L"\\" + name : std::wstring(name);
            else
              user = key;  // fall back to the SID string
            sidCache_.emplace(std::move(key), user);
          }
        }
      }
    }
    len = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, nullptr, 0, &len);
    if (len) {
      std::vector<uint8_t> buf(len);
      if (GetTokenInformation(tok, TokenIntegrityLevel, buf.data(), len, &len)) {
        PSID sid =
            reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data())->Label.Sid;
        UCHAR* count = GetSidSubAuthorityCount(sid);
        if (count && *count > 0) {
          DWORD rid = *GetSidSubAuthority(sid, *count - 1);
          const char* s = integrityFromRid(rid);
          integrity.assign(s, s + std::strlen(s));
        }
      }
    }
    CloseHandle(tok);
  }
  CloseHandle(proc);
}

bool ProcessTable::consume(const RawRecord& r) {
  const auto& h = *r.header;
  // Process Defined (op 0, rundown of pre-existing processes) AND Process Create
  // (op 1, processes started during capture) share one detail layout and both
  // define a table entry keyed by detail+0. Op 1 is emitted in the CREATOR's
  // context (header index = parent), but its detail describes the new child.
  if (h.eventClass != static_cast<uint16_t>(proto::EventClass::Process) ||
      (h.operation != 0 && h.operation != 1))
    return false;
  if (r.detail.size() < sizeof(proto::ProcessDetail)) return false;

  const auto* pd =
      reinterpret_cast<const proto::ProcessDetail*>(r.detail.data());
  ProcInfo pi;
  pi.pid = pd->processId;
  pi.parentIndex = pd->parentIndex;
  pi.parentId = pd->parentId;
  pi.sessionId = pd->sessionId;
  pi.createTime = pd->createTime;
  resolveToken(pi.pid, pi.user, pi.integrity);  // once per process; SID cached

  proto::ProcessStrings ps;
  if (proto::parseProcessStrings(r.detail.data(), r.detail.size(), ps)) {
    pi.image = proto::win32ImagePath(ps.image, ps.imageLen);
    pi.name = basename(pi.image);
    if (ps.cmdline) pi.cmdline.assign(ps.cmdline, ps.cmdlineLen);
  }

  byIndex_[pd->processIndex] = std::move(pi);
  return true;
}

}  // namespace pmx
