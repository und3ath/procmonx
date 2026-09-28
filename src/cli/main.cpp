// pmx — CLI counterpart to Process Monitor (driver-backed).
//
// M1 surface: attach to the Procmon minifilter port and drain raw events.
//   pmx driver status
//   pmx live [--flags 0xMASK] [--count N] [--rate HZ]

#include <map>
#include <windows.h>
#include <shellapi.h>

#include <conio.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "pmx/decode.h"
#include "pmx/driver/driver_controller.h"
#include "pmx/driver/flags.h"
#include "pmx/driver/port_client.h"
#include "pmx/enrich/pairer.h"
#include "pmx/enrich/pid_names.h"
#include "pmx/enrich/process_table.h"
#include "pmx/etw/net_trace.h"
#include "pmx/filter.h"
#include "pmx/filter_json.h"
#include "pmx/filter_pmc.h"
#include "pmx/pml.h"
#include "pmx/store.h"

#include "cli_common.h"

using namespace pmx::cli;

namespace {

pmx::PortClient* g_client = nullptr;
pmx::NetTrace* g_netTrace = nullptr;
std::atomic<bool> g_stop{false};

// Scope guard for the globals the Ctrl-C handler and output helpers use: on
// every return path of a command, drop pointers to objects about to be
// destroyed (the handler could otherwise touch a dead PortClient/NetTrace) and
// flush/close the --out file.
struct GlobalsGuard {
  GlobalsGuard() = default;
  GlobalsGuard(const GlobalsGuard&) = delete;
  GlobalsGuard& operator=(const GlobalsGuard&) = delete;
  ~GlobalsGuard() {
    g_client = nullptr;
    g_netTrace = nullptr;
    if (g_outFile) {
      std::fclose(g_outFile);
      g_outFile = nullptr;
    }
  }
};

constexpr const wchar_t* kServiceName = L"PROCMON25";

std::wstring exeDir() {
  wchar_t path[MAX_PATH];
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  std::wstring s(path);
  const size_t slash = s.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"." : s.substr(0, slash);
}

// Default driver path: procmon\PROCMON25.SYS next to the exe, else CWD.
std::wstring defaultSysPath() { return exeDir() + L"\\procmon\\PROCMON25.SYS"; }

const wchar_t* argValueW(int argc, wchar_t** argv, const wchar_t* key) {
  for (int i = 0; i + 1 < argc; ++i)
    if (!wcscmp(argv[i], key)) return argv[i + 1];
  return nullptr;
}

// Hidden first argument carrying the caller's working directory into the
// elevated child (UAC-elevated processes do not reliably inherit it, so
// relative --save/--out/--filter-* paths would resolve against System32).
constexpr const wchar_t* kCwdArg = L"--pmx-cwd";

// Quote one argument per the CommandLineToArgvW rules: backslashes are literal
// unless they precede a quote, so double any backslash run before a quote (and
// before the closing quote we add), and escape embedded quotes.
std::wstring quoteArg(const std::wstring& a) {
  if (!a.empty() && a.find_first_of(L" \t\"") == std::wstring::npos) return a;
  std::wstring s = L"\"";
  size_t bs = 0;
  for (wchar_t c : a) {
    if (c == L'\\') {
      ++bs;
    } else if (c == L'"') {
      s.append(bs * 2 + 1, L'\\');
      bs = 0;
    } else {
      s.append(bs, L'\\');
      bs = 0;
    }
    if (c != L'\\') s += c;
  }
  s.append(bs * 2, L'\\');
  s += L'"';
  return s;
}

// Re-quote argv[start..argc) into a single command-line string so the elevated
// relaunch receives the same arguments.
std::wstring joinArgs(int argc, wchar_t** argv, int start) {
  std::wstring s;
  for (int i = start; i < argc; ++i) {
    if (!s.empty()) s += L' ';
    s += quoteArg(argv[i]);
  }
  return s;
}

// Hidden `--pmx-nopause`: forwards --no-pause to the elevated child.
constexpr const wchar_t* kNoPauseArg = L"--pmx-nopause";

// Relaunch this exe elevated (UAC prompt) with the given args; wait and return
// the child's exit code. The child runs in its own elevated console window,
// which stays open at the end (press a key) unless --no-pause.
int relaunchElevated(const std::wstring& args) {
  wchar_t self[MAX_PATH];
  GetModuleFileNameW(nullptr, self, MAX_PATH);
  wchar_t cwd[MAX_PATH] = L"";
  GetCurrentDirectoryW(MAX_PATH, cwd);

  std::wstring params = std::wstring(kCwdArg) + L" " + quoteArg(cwd);
  if (g_noPause) params += std::wstring(L" ") + kNoPauseArg;
  params += L" " + args;

  SHELLEXECUTEINFOW sei{sizeof(sei)};
  sei.fMask = SEE_MASK_NOCLOSEPROCESS;
  sei.lpVerb = L"runas";
  sei.lpFile = self;
  sei.lpParameters = params.c_str();
  sei.lpDirectory = cwd;
  sei.nShow = SW_SHOWNORMAL;
  if (!ShellExecuteExW(&sei)) {
    const DWORD e = GetLastError();
    errf(e == ERROR_CANCELLED ? "elevate: UAC prompt declined\n"
                              : "elevate: ShellExecuteEx failed [%lu]\n",
         e);
    return 1;
  }
  errf("(running in the elevated window%s)\n",
       g_noPause ? "" : "; press a key there to close it when done");
  DWORD code = 0;
  if (sei.hProcess) {
    WaitForSingleObject(sei.hProcess, INFINITE);
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
  }
  return static_cast<int>(code);
}

// Keep the elevated child's window open so its output can be read.
void pauseBeforeExit(int rc) {
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  if (in == INVALID_HANDLE_VALUE || !GetConsoleMode(in, &mode)) return;
  std::fflush(stdout);
  std::fprintf(stderr, "\n[pmx] finished (exit %d). Press any key to close...",
               rc);
  FlushConsoleInputBuffer(in);
  _getch();
}

// Auto-elevate: if this process is not elevated, relaunch the identical command
// through a UAC prompt and exit with the child's code (never returns here). If
// already elevated, returns and the caller proceeds. `argv`/`argc` are the full
// process args; argv[1..] is replayed verbatim.
void ensureElevated(int argc, wchar_t** argv) {
  if (pmx::DriverController::isElevated()) return;
  errf("(needs admin -> requesting elevation via UAC)\n");
  std::exit(relaunchElevated(joinArgs(argc, argv, 1)));
}

BOOL WINAPI ctrlHandler(DWORD type) {
  if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
    // First Ctrl-C: stop capturing, let the spool drain to the output files.
    // A second one (g_stop already set - the drain is what's taking a while)
    // aborts that drain early; finalizeSpool still closes the files, just short.
    if (g_stop) {
      g_abortWrite = true;
    } else {
      g_stop = true;
      if (g_client) g_client->cancel();
      if (g_netTrace) g_netTrace->stop();
    }
    return TRUE;
  }
  return FALSE;
}


int cmdDriverStatus() {
  if (!pmx::DriverController::isElevated()) {
    errf(
                 "driver status needs elevation. Try: pmx elevate driver status\n");
    return 5;
  }
  std::error_code ec;
  auto filters = pmx::DriverController::loadedFilters(ec);
  if (ec) {
    printError("FilterFindFirst", ec);
    return 1;
  }
  outf("Loaded minifilters (%zu):\n", filters.size());
  for (const auto& f : filters) {
    outf("  %-24ls  frame=%u instances=%u\n", f.name.c_str(), f.frameId,
                f.instances);
  }

  pmx::PortClient client;
  ec = client.connectAuto();
  if (ec) {
    outf("\nProcessMonitor port: not connectable [%d] %s\n", ec.value(),
                ec.message().c_str());
    outf("(driver not loaded, or run elevated)\n");
    return 2;
  }
  outf("\nConnected: \\ProcessMonitor%dPort\n", client.portVersion());
  return 0;
}

// Dump up to `n` bytes of a detail blob as hex + interpret the leader; also
// try to render a trailing UTF-16 run as a path. Used to validate the decode
// against live events.
// Extract the NT object path from a detail blob. Anchored on a well-known
// prefix (\Device, \??\, or a DOS drive) rather than "longest printable run",
// which otherwise grabs the stray leading bytes before the path.
// Convert a wide string (len wchars, or -1 for NUL-terminated) to UTF-8. Narrow
// printf("%ls") routes through the C locale (ASCII only) and silently aborts the
// whole line on the first non-convertible wchar — hence garbled/merged output on
// non-ASCII paths. We convert explicitly and print with %s instead.
// --capture LIST -> driver capture mask. Comma list of proc (Process +
// Profiling), fs (File System + IPC), reg (Registry), or all. The process bit
// is always kept: it also produces the process rundown the ProcessTable needs
// to name every other event.
bool parseCaptureList(const wchar_t* list, uint32_t& flags) {
  flags = pmx::proto::kCaptureProcess;
  std::wstring s(list);
  size_t pos = 0;
  while (pos <= s.size()) {
    size_t comma = s.find(L',', pos);
    if (comma == std::wstring::npos) comma = s.size();
    std::wstring t = s.substr(pos, comma - pos);
    for (auto& c : t) c = static_cast<wchar_t>(towlower(c));
    if (t == L"proc" || t == L"process" || t == L"profiling")
      ;  // always on
    else if (t == L"fs" || t == L"file" || t == L"filesystem" || t == L"ipc")
      flags |= pmx::proto::kCaptureFileSystem;
    else if (t == L"reg" || t == L"registry")
      flags |= pmx::proto::kCaptureRegistry;
    else if (t == L"all")
      flags |= pmx::proto::kCaptureDefault;
    else
      return false;
    pos = comma + 1;
  }
  return true;
}

std::wstring_view extractPath(std::span<const uint8_t> d) {
  const auto* w = reinterpret_cast<const wchar_t*>(d.data());
  const size_t wn = d.size() / sizeof(wchar_t);
  for (size_t i = 0; i + 1 < wn; ++i) {
    const bool anchor =
        // \Device\... , \??\... , \REGISTRY\...
        (w[i] == L'\\' && (w[i + 1] == L'D' || w[i + 1] == L'?' ||
                           w[i + 1] == L'R')) ||
        // X:\ drive-letter path
        (i + 2 < wn && w[i + 1] == L':' && w[i + 2] == L'\\' &&
         ((w[i] >= L'A' && w[i] <= L'Z') || (w[i] >= L'a' && w[i] <= L'z'))) ||
        // HKLM\ / HKCU\ / HKCR\ / HKU\ registry hive prefixes
        (i + 2 < wn && w[i] == L'H' && w[i + 1] == L'K');
    if (!anchor) continue;
    size_t j = i;
    while (j < wn && w[j] >= 0x20 && w[j] < 0xD800) ++j;
    if (j - i >= 4) return {w + i, j - i};
  }
  return {};
}

void dumpDetail(std::span<const uint8_t> d, size_t n, bool isProcess) {
  const size_t m = d.size() < n ? d.size() : n;
  // Routed through outf so --out tees it and --silent suppresses it.
  outf("      detail[%zu]:", d.size());
  for (size_t i = 0; i < m; ++i) {
    if (i % 16 == 0) outf("\n        %04zx: ", i);
    outf("%02x ", d[i]);
  }
  outf("\n");
  if (isProcess && d.size() >= sizeof(pmx::proto::ProcessDetail)) {
    const auto* L = reinterpret_cast<const pmx::proto::ProcessDetail*>(d.data());
    outf("      procdetail: idx=%u pid=%u ppid=%u sess=%u ctime=%llu\n",
         L->processIndex, L->processId, L->parentId, L->sessionId,
         (unsigned long long)L->createTime);
  }
  std::wstring_view p = extractPath(d);
  if (!p.empty()) {
    std::string pu = toUtf8(p.data(), (int)p.size());
    outf("      path: %s\n", pu.c_str());
  }
}

// Print one decoded event as a table row (shared by `live` and `open`).
void printRow(long long n, const pmx::Event& ev) {
  SYSTEMTIME st{};
  FILETIME ft{static_cast<DWORD>(ev.timestamp),
              static_cast<DWORD>(ev.timestamp >> 32)};
  FILETIME lft{};
  FileTimeToLocalFileTime(&ft, &lft);
  FileTimeToSystemTime(&lft, &st);
  // Pass explicit lengths: toUtf8(s, -1) would keep the terminating NUL inside
  // the std::string, and %s then stops there (dropping "(pid)[integrity]").
  std::string who =
      toUtf8(ev.processName.data(), static_cast<int>(ev.processName.size())) +
      "(" + std::to_string(ev.pid) + ")";
  if (!ev.integrity.empty())
    who += "[" +
           toUtf8(ev.integrity.data(), static_cast<int>(ev.integrity.size())) +
           "]";
  std::string pathU = toUtf8(ev.path.data(), static_cast<int>(ev.path.size()));
  std::string detU = toUtf8(ev.detail.data(), static_cast<int>(ev.detail.size()));
  std::string res = pmx::statusName(ev.result);
  char dur[24] = "";
  if (ev.duration)
    std::snprintf(dur, sizeof dur, " %.6fs", (double)ev.duration / 1e7);
  const char* fmt =
      "#%-6lld %02u:%02u:%02u.%03u  %-34s %-10s %-30s %-16s %s%s%s%s\n";
  int need = std::snprintf(nullptr, 0, fmt, n, st.wHour, st.wMinute, st.wSecond,
                           st.wMilliseconds, who.c_str(), ev.className.c_str(),
                           ev.opName.c_str(), res.c_str(), pathU.c_str(),
                           detU.empty() ? "" : "  ", detU.c_str(), dur);
  if (need < 0) return;
  std::string line(static_cast<size_t>(need) + 1, '\0');
  std::snprintf(line.data(), line.size(), fmt, n, st.wHour, st.wMinute,
                st.wSecond, st.wMilliseconds, who.c_str(), ev.className.c_str(),
                ev.opName.c_str(), res.c_str(), pathU.c_str(),
                detU.empty() ? "" : "  ", detU.c_str(), dur);
  line.resize(static_cast<size_t>(need));
  writeOut(line.data(), line.size());
}

int cmdFilters(int argc, wchar_t** argv) {
  if (argc < 1) {
    outf("filters: pmx filters FILE|DIR...  (.reg|.pmc|.json)\n");
    return 1;
  }
  auto printSet = [](const pmx::FilterSet& fs) {
    outf("%zu rule(s), match=%s:\n", fs.rules().size(),
                pmx::includeModeName(fs.includeMode()));
    for (const auto& r : fs.rules()) {
      std::wstring line = pmx::ruleToString(r);
      std::string u = toUtf8(line.c_str(), -1);
      outf("  [%s] %s\n",
                  r.action == pmx::Action::Include ? "include" : "exclude",
                  u.c_str());
    }
  };

  SetConsoleOutputCP(CP_UTF8);
  if (argc == 1) {
    DWORD attr = GetFileAttributesW(argv[0]);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
      pmx::FilterSet fs;
      std::error_code ec = loadFilterConfig(argv[0], fs);
      if (ec) { printError("filters", ec); return 2; }
      printSet(fs);
      return 0;
    }
  }
  // Several files and/or a directory: each config is its own lens; show them
  // separately so per-lens include/exclude logic is visible (not flattened).
  pmx::FilterGroup group;
  for (int i = 0; i < argc; ++i) {
    DWORD attr = GetFileAttributesW(argv[i]);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
      std::error_code ec = loadFilterDir(argv[i], group);
      if (ec) { printError("filters", ec); return 2; }
    } else {
      pmx::FilterSet fs;
      std::error_code ec = loadFilterConfig(argv[i], fs);
      if (ec) { printError("filters", ec); return 2; }
      group.addSet(std::move(fs));
    }
  }
  outf("%zu lens(es), combined with --groups (default any = OR'd):\n",
              group.size());
  for (const auto& fs : group.sets()) {
    outf("--\n");
    printSet(fs);
  }
  return 0;
}

// Resolve an ETW network event's OS pid to its image name. ETW carries a pid
// but no name, and the driver's process table is keyed by Procmon index, so
// resolve directly. PidNameCache handles PID reuse (see pid_names.h). Only
// called from one thread per command (the network thread in `live`, the main
// thread in `net`), so a single unlocked instance is safe.
const std::wstring& procNameForPid(uint32_t pid, uint64_t eventTime) {
  static pmx::PidNameCache cache;
  return cache.lookup(pid, eventTime);
}

constexpr uint32_t kNetProcIndexBase = 0x80000000u;

// Convert a captured ETW network event into the shared Event model (class 5).
pmx::Event netEventToEvent(const pmx::NetEvent& nev) {
  pmx::Event ev;
  ev.timestamp = nev.timestamp;
  ev.pid = nev.pid;
  // ETW carries no Procmon process index. Synthesize one per PID in a range the
  // driver's small sequential indexes never reach, so the PML process table
  // (keyed by index) gives each network PID its own process record instead of
  // lumping every network event under index 0.
  ev.processIndex = kNetProcIndexBase | nev.pid;
  ev.eventClass = 5;  // Network
  // Map the raw ETW opcode (10 Send.. IPv6 = base+16) to Procmon's
  // NetworkOperation enum used in the PML (2 Send,3 Receive,4 Accept,5 Connect,
  // 6 Disconnect,7 Reconnect,8 Retransmit,9 TCPCopy; else 1 Other).
  {
    int base = nev.opcode >= 26 ? nev.opcode - 16 : nev.opcode;
    switch (base) {
      case 10: ev.operation = 2; break;   // Send
      case 11: ev.operation = 3; break;   // Receive
      case 12: ev.operation = 5; break;   // Connect
      case 13: ev.operation = 6; break;   // Disconnect
      case 14: ev.operation = 8; break;   // Retransmit
      case 15: ev.operation = 4; break;   // Accept
      case 16: ev.operation = 7; break;   // Reconnect
      case 18: ev.operation = 9; break;   // TCPCopy
      default: ev.operation = 1; break;   // Other (incl. Fail)
    }
  }
  ev.result = 0;
  ev.completed = true;
  ev.ioLength = nev.length;
  std::memcpy(ev.netSrcIp, nev.srcIp, 16);
  std::memcpy(ev.netDstIp, nev.dstIp, 16);
  ev.netSrcPort = nev.srcPort;
  ev.netDstPort = nev.dstPort;
  ev.netFlags = (uint8_t)((nev.isIpv6 ? 0 : 0x1) |  // src ipv4
                          (nev.isIpv6 ? 0 : 0x2) |  // dst ipv4
                          (nev.isTcp ? 0x4 : 0));
  ev.processName = procNameForPid(nev.pid, nev.timestamp);
  ev.className = "Network";
  ev.opName = nev.opName;
  std::string p = nev.localAddr + " -> " + nev.remoteAddr;
  ev.path.assign(p.begin(), p.end());
  char db[32];
  std::snprintf(db, sizeof db, "Length: %u", nev.length);
  ev.detail.assign(db, db + std::strlen(db));
  return ev;
}

// Summary key for `pmx summary --by K`.
enum class SummaryBy { Path, Proc, Pid, Op, Result, Class };

std::optional<SummaryBy> parseSummaryBy(const wchar_t* s) {
  if (!_wcsicmp(s, L"path")) return SummaryBy::Path;
  if (!_wcsicmp(s, L"proc") || !_wcsicmp(s, L"process")) return SummaryBy::Proc;
  if (!_wcsicmp(s, L"pid")) return SummaryBy::Pid;
  if (!_wcsicmp(s, L"op") || !_wcsicmp(s, L"operation")) return SummaryBy::Op;
  if (!_wcsicmp(s, L"result")) return SummaryBy::Result;
  if (!_wcsicmp(s, L"class")) return SummaryBy::Class;
  return std::nullopt;
}

std::wstring summaryKey(const pmx::Event& ev, SummaryBy by) {
  auto w = [](const std::string& s) { return std::wstring(s.begin(), s.end()); };
  switch (by) {
    case SummaryBy::Path: return ev.path.empty() ? L"(no path)" : ev.path;
    case SummaryBy::Proc: return ev.processName;
    case SummaryBy::Pid:
      return ev.processName + L" (" + std::to_wstring(ev.pid) + L")";
    case SummaryBy::Op: return w(ev.opName);
    case SummaryBy::Result: return w(pmx::statusName(ev.result));
    case SummaryBy::Class: return w(ev.className);
  }
  return {};
}

// NT_ERROR severity, minus FAST_IO_DISALLOWED (0xC01C0004: the filter manager
// just retries the operation as an IRP; Procmon hides it by default). What
// --failed selects and what `summary` counts as failed.
constexpr uint32_t kFastIoDisallowed = 0xC01C0004u;
bool isFailure(uint32_t status) {
  return status >= 0xC0000000u && status != kFastIoDisallowed;
}

// Print a count table of `events` grouped by `by`, most frequent first.
void printSummary(const std::vector<pmx::Event>& events, SummaryBy by,
                  long long top) {
  struct Agg { uint64_t count = 0, failed = 0; };
  std::unordered_map<std::wstring, Agg> m;
  uint64_t failedTotal = 0;
  for (const auto& ev : events) {
    Agg& a = m[summaryKey(ev, by)];
    ++a.count;
    if (isFailure(ev.result)) {
      ++a.failed;
      ++failedTotal;
    }
  }
  std::vector<std::pair<std::wstring, Agg>> rows(m.begin(), m.end());
  std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
    return a.second.count != b.second.count ? a.second.count > b.second.count
                                            : a.first < b.first;
  });
  const double total = events.empty() ? 1.0 : (double)events.size();
  outf("%10s %6s %8s  %s\n", "count", "%", "failed", "key");
  long long shown = 0;
  for (const auto& [key, a] : rows) {
    if (top > 0 && shown++ >= top) break;
    const std::string k = toUtf8(key.data(), static_cast<int>(key.size()));
    outf("%10llu %5.1f%% %8llu  %s\n", (unsigned long long)a.count,
         100.0 * a.count / total, (unsigned long long)a.failed, k.c_str());
  }
  outf("%zu distinct, %zu events, %llu failed%s\n", rows.size(), events.size(),
       (unsigned long long)failedTotal,
       top > 0 && (long long)rows.size() > top ? " (use --top 0 for all)" : "");
}

// `open` and `summary` share loading + filtering. summary=true prints the
// grouped table (--by/--top) instead of rows.
int cmdOpenOrSummary(int argc, wchar_t** argv, bool summary) {
  if (argc < 1) {
    if (summary)
      outf("summary: pmx summary FILE.(pmxlog|pml) [--by path|proc|pid|op|result|class]\n"
           "         [--top N] [filters as for open]\n");
    else
      outf("open: pmx open FILE.(pmxlog|pml) [-f RULE] [-x RULE] "
           "[--filter-file cfg]... [--filter-dir DIR] [--match procmon|any] "
           "[--groups any|all] [--pid N] [--proc NAME] [--failed] [--class C] "
           "[--count N] [--csv F] [--pml F] [--json F|-] [--quiet]\n");
    return 1;
  }
  const wchar_t* path = argv[0];
  int classFilter = -1;
  long long maxCount = -1;
  long long top = 20;
  SummaryBy by = SummaryBy::Path;
  const wchar_t* csvPath = nullptr;
  const wchar_t* pmlPath = nullptr;
  const wchar_t* jsonPath = nullptr;
  bool summaryMode = summary;  // the `summary` command, or open with --summary
  bool quiet = summary;
  FilterCli fc;
  for (int i = 1; i < argc; ++i) {
    if (parseFilterArg(argc, argv, i, fc)) continue;
    if (!wcscmp(argv[i], L"--class") && i + 1 < argc)
      classFilter = static_cast<int>(wcstol(argv[++i], nullptr, 0));
    else if (!wcscmp(argv[i], L"--count") && i + 1 < argc)
      maxCount = wcstoll(argv[++i], nullptr, 0);
    else if (!wcscmp(argv[i], L"--csv") && i + 1 < argc)
      csvPath = argv[++i];
    else if (!wcscmp(argv[i], L"--pml") && i + 1 < argc)
      pmlPath = argv[++i];
    else if (!wcscmp(argv[i], L"--json") && i + 1 < argc)
      jsonPath = argv[++i];
    else if (!wcscmp(argv[i], L"--quiet"))
      quiet = true;
    else if (!wcscmp(argv[i], L"--summary"))
      summaryMode = quiet = true;
    else if (!wcscmp(argv[i], L"--top") && i + 1 < argc)
      top = wcstoll(argv[++i], nullptr, 0);
    else if (!wcscmp(argv[i], L"--by") && i + 1 < argc) {
      auto b = parseSummaryBy(argv[++i]);
      if (!b) {
        errf("bad --by %ls (want path|proc|pid|op|result|class)\n", argv[i]);
        return 2;
      }
      by = *b;
    }
  }
  // --json - streams JSON Lines to stdout in place of the table rows.
  const bool jsonStdout = jsonPath && !wcscmp(jsonPath, L"-");
  if (jsonStdout) quiet = true;
  g_jsonStdout = jsonStdout;

  pmx::FilterSet filters;       // -f/-x rules
  pmx::FilterGroup dirFilters;  // one lens per --filter-file / --filter-dir file
  if (int rc = buildFilters(fc, filters, dirFilters)) return rc;

  // .pml (Procmon's own log, or one pmx wrote) or pmx's native .pmxlog.
  std::vector<pmx::Event> events;
  const wchar_t* dot = wcsrchr(path, L'.');
  const bool isPml = dot && !_wcsicmp(dot, L".pml");
  std::error_code ec =
      isPml ? pmx::loadPml(path, events) : pmx::loadEvents(path, events);
  if (ec) {
    printError("open", ec);
    if (isPml && ec.value() == ERROR_NOT_SUPPORTED)
      errf("(only 64-bit Process Monitor logs, format v4-v9, are supported)\n");
    return 3;
  }

  SetConsoleOutputCP(CP_UTF8);
  std::vector<pmx::Event> shown;
  const bool keep = csvPath || pmlPath || (jsonPath && !jsonStdout) || summaryMode;
  long long n = 0;
  for (const auto& ev : events) {
    if (classFilter >= 0 && ev.eventClass != classFilter) continue;
    if (!filters.matches(ev)) continue;
    if (!dirFilters.matches(ev)) continue;
    if (!quiet) printRow(n, ev);
    if (jsonStdout) writeJsonRow(ev);
    if (keep) shown.push_back(ev);
    if (++n == maxCount) break;
  }
  if (summaryMode) {
    printSummary(shown, by, top);
    return 0;
  }
  statusf("Shown %lld of %zu events.\n", n, events.size());
  if (jsonPath && !jsonStdout) {
    std::error_code je = pmx::saveEventsJson(jsonPath, shown);
    if (je) { printError("json", je); return 4; }
    statusf("Wrote %zu events to %ls\n", shown.size(), jsonPath);
  }
  if (csvPath) {
    std::error_code ce = pmx::saveEventsCsv(csvPath, shown);
    if (ce) { printError("csv", ce); return 4; }
    statusf("Wrote %zu events to %ls\n", shown.size(), csvPath);
  }
  if (pmlPath) {
    std::error_code pe = pmx::savePml(pmlPath, shown);
    if (pe) { printError("pml", pe); return 4; }
    statusf("Wrote %zu events to %ls\n", shown.size(), pmlPath);
  }
  return 0;
}

int cmdLive(int argc, wchar_t** argv) {
  // SetCapture flags (proto::CaptureFlags): the driver's only kernel-side
  // selection - 0x1 Process/Profiling (+ process info), 0x2 File System/IPC,
  // 0x4 Registry. Resolved after parsing: --flags (raw) > --capture LIST >
  // derived from --class when nothing else needs the other classes > 0x7.
  const wchar_t* rawFlags = nullptr;    // --flags 0xMASK
  const wchar_t* captureList = nullptr; // --capture fs,reg,proc|all
  uint32_t rate = 0;
  long long maxCount = -1;
  size_t hexBytes = 0;      // --hex N: dump N detail bytes per record
  int classFilter = -1;     // --class N: only print this event class
  const wchar_t* outPath = nullptr;  // --out FILE: write capture to a file
  bool noPair = false;               // --raw: don't pair request/completion
  FilterCli fc;                         // -f/-x/--filter-file/--filter-dir/...
  const wchar_t* savePath = nullptr;    // --save FILE: write .pmxlog capture
  const wchar_t* csvPath = nullptr;     // --csv FILE: write CSV capture
  const wchar_t* pmlPath = nullptr;     // --pml FILE: write Procmon .pml capture
  const wchar_t* jsonPath = nullptr;    // --json FILE|-: JSON Lines (filtered view)
  bool statsOnly = false;               // --stats: raw per-class record histogram
  bool withNet = false;                 // --net: also capture ETW network events
  const wchar_t* configPath = nullptr;  // --config FILE
  long long bufferMbArg = -1;           // --buffer-mb N
  const wchar_t* spoolDirArg = nullptr; // --spool-dir DIR
  bool unfiltered = false;              // --unfiltered: --save/--pml keep the raw capture

  for (int i = 0; i < argc; ++i) {
    if (parseFilterArg(argc, argv, i, fc)) continue;
    if (!wcscmp(argv[i], L"--flags") && i + 1 < argc)
      rawFlags = argv[++i];
    else if (!wcscmp(argv[i], L"--capture") && i + 1 < argc)
      captureList = argv[++i];
    else if (!wcscmp(argv[i], L"--rate") && i + 1 < argc)
      rate = static_cast<uint32_t>(wcstoul(argv[++i], nullptr, 0));
    else if (!wcscmp(argv[i], L"--count") && i + 1 < argc)
      maxCount = wcstoll(argv[++i], nullptr, 0);
    else if (!wcscmp(argv[i], L"--class") && i + 1 < argc)
      classFilter = static_cast<int>(wcstol(argv[++i], nullptr, 0));
    else if (!wcscmp(argv[i], L"--hex") && i + 1 < argc)
      hexBytes = static_cast<size_t>(wcstoul(argv[++i], nullptr, 0));
    else if (!wcscmp(argv[i], L"--hex"))
      hexBytes = 96;
    else if (!wcscmp(argv[i], L"--out") && i + 1 < argc)
      outPath = argv[++i];
    else if (!wcscmp(argv[i], L"--raw"))
      noPair = true;
    else if (!wcscmp(argv[i], L"--net"))
      withNet = true;
    else if (!wcscmp(argv[i], L"--silent"))
      g_silent = true;
    else if (!wcscmp(argv[i], L"--save") && i + 1 < argc)
      savePath = argv[++i];
    else if (!wcscmp(argv[i], L"--csv") && i + 1 < argc)
      csvPath = argv[++i];
    else if (!wcscmp(argv[i], L"--pml") && i + 1 < argc)
      pmlPath = argv[++i];
    else if (!wcscmp(argv[i], L"--json") && i + 1 < argc)
      jsonPath = argv[++i];
    else if (!wcscmp(argv[i], L"--stats"))
      statsOnly = true;
    else if (!wcscmp(argv[i], L"--config") && i + 1 < argc)
      configPath = argv[++i];
    else if (!wcscmp(argv[i], L"--buffer-mb") && i + 1 < argc)
      bufferMbArg = wcstoll(argv[++i], nullptr, 0);
    else if (!wcscmp(argv[i], L"--spool-dir") && i + 1 < argc)
      spoolDirArg = argv[++i];
    else if (!wcscmp(argv[i], L"--unfiltered"))
      unfiltered = true;
  }

  PmxConfig pmxConfig;
  if (int rc = loadPmxConfig(configPath, pmxConfig)) return rc;
  if (bufferMbArg >= 0) pmxConfig.bufferMb = bufferMbArg < 16 ? 16 : (size_t)bufferMbArg;
  if (spoolDirArg) pmxConfig.spoolDir = spoolDirArg;

  // Build the filters: every --filter-file / --filter-dir config is its own
  // independent lens (combined per --groups, default OR), and the CLI -f/-x
  // rules form one FilterSet applied alongside. An event must pass both.
  pmx::FilterSet filters;
  pmx::FilterGroup dirFilters;
  if (int rc = buildFilters(fc, filters, dirFilters)) return rc;

  // Kernel-side class selection. Every output is the filtered view, so --class
  // narrows the driver unless --unfiltered keeps the raw capture in
  // --save/--pml. --capture narrows it explicitly.
  const bool keepAll = unfiltered && (savePath || pmlPath);
  uint32_t flags = pmx::proto::kCaptureDefault;
  if (rawFlags) {
    flags = static_cast<uint32_t>(wcstoul(rawFlags, nullptr, 0));
  } else if (captureList) {
    if (!parseCaptureList(captureList, flags)) {
      errf("bad --capture %ls (want a comma list of proc, fs, reg, or all)\n",
           captureList);
      return 2;
    }
  } else if (classFilter >= 0 && !keepAll) {
    flags = pmx::proto::captureFlagsForClass(classFilter);
  }
  if (classFilter == 5 && !withNet) {
    withNet = true;  // network events come only from ETW
    errf("(--class 5: enabling --net)\n");
  }
  // User-mode early drop: with --class and nothing saved, records of other
  // classes skip pairing + decoding entirely (completions still pair).
  const bool earlyDrop = classFilter > 0 && !keepAll && !statsOnly;
  // --json - streams records to stdout in place of table rows.
  g_jsonStdout = jsonPath && !wcscmp(jsonPath, L"-");
  const bool jsonFile = jsonPath && !g_jsonStdout;

  // --out mirrors output to a file (tee); the console still shows it unless
  // --silent. (Needed for `pmx elevate live --out …`: the elevated child has its
  // own console that closes on exit, so a file lets the caller read the stream.)
  if (outPath) {
    g_outFile = _wfopen(outPath, L"w");
    if (!g_outFile) {
      errf("live: cannot open --out file\n");
      return 2;
    }
  }

  SetConsoleOutputCP(CP_UTF8);  // render UTF-8 paths correctly

  pmx::PortClient client;
  g_client = &client;
  GlobalsGuard globalsGuard;  // declared after client: clears g_client first
  SetConsoleCtrlHandler(ctrlHandler, TRUE);

  std::error_code ec = client.connectAuto();
  if (ec) {
    printError("connect", ec);
    errf("(is the Procmon driver loaded? run elevated)\n");
    return 2;
  }
  statusf("Connected \\ProcessMonitor%dPort; flags=0x%08X. Ctrl-C to stop.\n",
       client.portVersion(), flags);

  if (rate) client.setInterval(rate);
  ec = client.setCapture(true, flags);
  if (ec) {
    printError("setCapture", ec);
    return 3;
  }

  pmx::ProcessTable procs;
  pmx::Pairer pairer;
  long long n = 0;

  // File outputs go through a RAM-bounded spool (sorted runs spill to disk).
  std::optional<pmx::EventSpool> spool;
  if (savePath || csvPath || jsonFile || pmlPath) {
    pmx::SpoolOptions sopt;
    sopt.bufferBytes = pmxConfig.bufferMb << 20;
    sopt.dir = pmxConfig.spoolDir;
    spool.emplace(sopt);
    spool->onSpill = [](size_t idx, uint64_t cnt) {
      statusf("[pmx] buffer full: spilled run %zu (%llu events) to disk\n",
             idx, (unsigned long long)cnt);
    };
  }
  bool spoolErrorPrinted = false;

  // The driver pump and (with --net) the ETW network thread both feed events;
  // serialize the shared store/print/count under one lock.
  std::mutex emitMx;
  pmx::NetTrace netTrace;
  auto pushEvent = [&](const pmx::Event& ev, const pmx::CompletedEvent* ce) {
    std::lock_guard<std::mutex> lk(emitMx);
    // Hard cap: once the count is met, drop everything (both threads, in-flight
    // driver batches and buffered network events) so --count doesn't overshoot.
    if (maxCount > 0 && n >= maxCount) return;
    const bool pass = (classFilter < 0 || ev.eventClass == classFilter) &&
                      filters.matches(ev) && dirFilters.matches(ev);
    if (!pass && !keepAll) return;
    if (spool) {
      if (std::error_code se = spool->add(ev, pass ? 1 : 0)) {
        if (!spoolErrorPrinted) {
          printError("spool", se);
          spoolErrorPrinted = true;
        }
        g_stop = true;
        client.cancel();
        netTrace.stop();
        return;
      }
    }
    if (!pass) return;

    if (g_jsonStdout)
      writeJsonRow(ev);
    else
      printRow(n, ev);
    if (hexBytes && ce) {
      outf("      seq=%u class=%u op=%u detailBytes=%zu\n", ev.sequence,
           ev.eventClass, ev.operation, ce->detail.size());
      if (!ce->detail.empty())
        dumpDetail(ce->detail, hexBytes,
                   ev.eventClass ==
                       static_cast<uint16_t>(pmx::proto::EventClass::Process));
    }
    if (++n == maxCount) {
      g_stop = true;  // make the pump callback skip the rest of the current batch
      client.cancel();
      netTrace.stop();
    }
  };
  // Decode -> store full (--save) -> filter -> print + store hits (--csv).
  auto emit = [&](const pmx::CompletedEvent& ce) {
    pmx::Event ev = pmx::decodeEvent(ce, procs);
    pushEvent(ev, &ce);
  };

  // --net: run the ETW network consumer on its own thread, folding each network
  // event into the same emit path so driver and network events interleave.
  std::thread netThread;
  if (withNet) {
    g_netTrace = &netTrace;
    netThread = std::thread([&] {
      std::error_code nec = netTrace.run(
          [&](const pmx::NetEvent& nev) { pushEvent(netEventToEvent(nev), nullptr); },
          0);  // until stop()
      if (nec) {
        std::lock_guard<std::mutex> lk(emitMx);
        errf("live: network capture disabled (%s)\n",
                     nec.message().c_str());
      }
    });
  }

  std::map<uint16_t, uint64_t> classHist;  // --stats: raw records per event class
  uint64_t rawTotal = 0;

  ec = client.pumpLoop([&](const pmx::RawRecord& r) {
    if (g_stop) return;
    // Tally the raw event class of EVERY record the driver sends, before any
    // pairing/decode/filter - this shows what the driver actually emits (e.g.
    // whether registry records arrive at all).
    ++rawTotal;
    ++classHist[r.header->eventClass];
    if (statsOnly) {
      if ((long long)rawTotal == maxCount) client.cancel();
      return;
    }
    procs.consume(r);  // keep the index->process map current (all classes)
    if (earlyDrop && r.header->eventClass != 0 &&
        r.header->eventClass != classFilter)
      return;  // never displayed or saved: skip copy/pair/decode
    if (noPair) {
      pmx::CompletedEvent ce;
      ce.header = *r.header;
      ce.detail.assign(r.detail.begin(), r.detail.end());
      ce.finalResult = r.header->result;
      ce.completed = false;
      ce.information = 0;
      emit(ce);
      return;
    }
    // Buffer requests until their class-0 completion arrives, then emit with the
    // real final status + OpenResult/Information.
    if (auto done = pairer.consume(r)) emit(*done);
    for (auto& ev : pairer.takeEvicted()) emit(ev);  // pending cap overflow
  });

  client.setCapture(false, 0);
  // Stop the network thread (if any) and wait for it before draining pending.
  if (withNet) {
    netTrace.stop();
    if (netThread.joinable()) netThread.join();
    g_netTrace = nullptr;
  }
  // Emit any requests whose completion never arrived (still pending at stop).
  if (!noPair)
    for (auto& ce : pairer.flush()) emit(ce);
  if (ec && ec != std::errc::operation_canceled) {
    printError("pump", ec);
    return 4;
  }
  if (statsOnly) {
    outf("Raw record classes (%llu total, pre-decode):\n",
         (unsigned long long)rawTotal);
    for (auto& [cls, cnt] : classHist)
      outf("  class %-3u %-12s %llu\n", cls, pmx::proto::className(cls),
           (unsigned long long)cnt);
    return 0;
  }
  statusf("Captured %lld events.\n", n);
  // Arrival order isn't chronological (the Pairer emits on completion; --net
  // interleaves ETW), so the spool drains sorted by (timestamp, sequence).
  if (spool) {
    LiveOutputPaths paths;
    paths.save = savePath;
    paths.csv = csvPath;
    paths.json = jsonFile ? jsonPath : nullptr;
    paths.pml = pmlPath;
    if (int rc = finalizeSpool(*spool, paths, unfiltered)) return rc;
  }
  if (g_outFile) { std::fclose(g_outFile); g_outFile = nullptr; }
  return 0;
}

int cmdNet(int argc, wchar_t** argv) {
  uint64_t maxCount = 100000;  // 0 == "until Ctrl-C" isn't printf-friendly as a
                                // default duration, so cap it generously.
  const wchar_t* outPath = nullptr;
  const wchar_t* savePath = nullptr;
  const wchar_t* csvPath = nullptr;
  const wchar_t* pmlPath = nullptr;
  const wchar_t* jsonPath = nullptr;
  const wchar_t* configPath = nullptr;
  long long bufferMbArg = -1;
  const wchar_t* spoolDirArg = nullptr;
  for (int i = 0; i < argc; ++i) {
    if (!wcscmp(argv[i], L"--count") && i + 1 < argc)
      maxCount = wcstoull(argv[++i], nullptr, 0);
    else if (!wcscmp(argv[i], L"--json") && i + 1 < argc)
      jsonPath = argv[++i];
    else if (!wcscmp(argv[i], L"--out") && i + 1 < argc)
      outPath = argv[++i];
    else if (!wcscmp(argv[i], L"--save") && i + 1 < argc)
      savePath = argv[++i];
    else if (!wcscmp(argv[i], L"--csv") && i + 1 < argc)
      csvPath = argv[++i];
    else if (!wcscmp(argv[i], L"--pml") && i + 1 < argc)
      pmlPath = argv[++i];
    else if (!wcscmp(argv[i], L"--config") && i + 1 < argc)
      configPath = argv[++i];
    else if (!wcscmp(argv[i], L"--buffer-mb") && i + 1 < argc)
      bufferMbArg = wcstoll(argv[++i], nullptr, 0);
    else if (!wcscmp(argv[i], L"--spool-dir") && i + 1 < argc)
      spoolDirArg = argv[++i];
    else if (!wcscmp(argv[i], L"--silent"))
      g_silent = true;
  }

  PmxConfig pmxConfig;
  if (int rc = loadPmxConfig(configPath, pmxConfig)) return rc;
  if (bufferMbArg >= 0) pmxConfig.bufferMb = bufferMbArg < 16 ? 16 : (size_t)bufferMbArg;
  if (spoolDirArg) pmxConfig.spoolDir = spoolDirArg;

  SetConsoleOutputCP(CP_UTF8);
  g_jsonStdout = jsonPath && !wcscmp(jsonPath, L"-");
  const bool jsonFile = jsonPath && !g_jsonStdout;
  if (outPath) {
    g_outFile = _wfopen(outPath, L"w");
    if (!g_outFile) {
      errf("net: cannot open --out file\n");
      return 2;
    }
  }

  pmx::NetTrace trace;
  g_netTrace = &trace;
  GlobalsGuard globalsGuard;  // declared after trace: clears g_netTrace first
  SetConsoleCtrlHandler(ctrlHandler, TRUE);

  statusf("Starting NT Kernel Logger (network). Ctrl-C to stop.\n");

  // net has no filtering, so every event is tag 1 (the "filtered" view) -
  // every output gets the same events.
  std::optional<pmx::EventSpool> spool;
  if (savePath || csvPath || jsonFile || pmlPath) {
    pmx::SpoolOptions sopt;
    sopt.bufferBytes = pmxConfig.bufferMb << 20;
    sopt.dir = pmxConfig.spoolDir;
    spool.emplace(sopt);
    spool->onSpill = [](size_t idx, uint64_t cnt) {
      statusf("[pmx] buffer full: spilled run %zu (%llu events) to disk\n",
             idx, (unsigned long long)cnt);
    };
  }
  bool spoolErrorPrinted = false;

  long long n = 0;
  std::error_code ec = trace.run(
      [&](const pmx::NetEvent& nev) {
        // Hard cap: ETW delivers buffered events after run() hits the count, so
        // drop anything past maxCount to keep --count exact.
        if (maxCount && (uint64_t)n >= maxCount) return;
        pmx::Event ev = netEventToEvent(nev);
        if (spool) {
          if (std::error_code se = spool->add(ev, 1)) {
            if (!spoolErrorPrinted) {
              printError("spool", se);
              spoolErrorPrinted = true;
            }
            trace.stop();
            return;
          }
        }
        if (g_jsonStdout)
          writeJsonRow(ev);
        else
          printRow(n, ev);
        ++n;
      },
      maxCount);
  if (ec) {
    printError("net", ec);
    if (ec == std::error_code(ERROR_ACCESS_DENIED, std::system_category()))
      errf("(needs admin -> run: pmx elevate net)\n");
    return 3;
  }
  statusf("Captured %lld network events.\n", n);
  if (spool) {
    LiveOutputPaths paths;
    paths.save = savePath;
    paths.csv = csvPath;
    paths.json = jsonFile ? jsonPath : nullptr;
    paths.pml = pmlPath;
    if (int rc = finalizeSpool(*spool, paths, /*unfiltered=*/false)) return rc;
  }
  if (g_outFile) { std::fclose(g_outFile); g_outFile = nullptr; }
  return 0;
}

int cmdDriver(int argc, wchar_t** argv) {
  if (argc < 1) {
    outf("driver: status|load|unload|install|remove\n");
    return 1;
  }
  const std::wstring sub = argv[0];
  const wchar_t* name = argValueW(argc, argv, L"--name");
  if (!name) name = kServiceName;
  const wchar_t* sys = argValueW(argc, argv, L"--sys");
  const std::wstring sysDefault = defaultSysPath();
  if (!sys) sys = sysDefault.c_str();

  if (sub == L"status") return cmdDriverStatus();

  const bool needAdmin = sub == L"load" || sub == L"unload" ||
                         sub == L"install" || sub == L"remove" ||
                         sub == L"attach";
  if (needAdmin && !pmx::DriverController::isElevated()) {
    errf(
                 "driver %ls needs elevation. Try: pmx elevate driver %ls\n",
                 sub.c_str(), sub.c_str());
    return 5;
  }

  std::error_code ec;
  if (sub == L"load") {
    std::wstring filter;
    ec = pmx::DriverController::ensureLoaded(name, sys, &filter);
    if (ec) { printError("driver load", ec); return 3; }
    outf("Loaded %ls, attached to all volumes (sys=%ls)\n",
                filter.c_str(), sys);
    return 0;
  }
  if (sub == L"attach") {
    int attached = 0;
    ec = pmx::DriverController::attachAllVolumes(name, &attached);
    if (ec) { printError("driver attach", ec); return 3; }
    outf("Attached %ls to %d volume(s)\n", name, attached);
    return 0;
  }
  if (sub == L"unload") {
    ec = pmx::DriverController::unload(name);
    if (ec) { printError("driver unload", ec); return 3; }
    outf("Unloaded %ls\n", name);
    return 0;
  }
  if (sub == L"install") {
    ec = pmx::DriverController::installService(name, sys);
    if (ec) { printError("driver install", ec); return 3; }
    outf("Installed service %ls -> %ls\n", name, sys);
    return 0;
  }
  if (sub == L"remove") {
    ec = pmx::DriverController::removeService(name);
    if (ec) { printError("driver remove", ec); return 3; }
    outf("Removed service %ls\n", name);
    return 0;
  }
  outf("driver: unknown subcommand %ls\n", sub.c_str());
  return 1;
}

void usage() {
  outf(
      "pmx - driver-backed Process Monitor\n"
      "  pmx driver status\n"
      "  pmx driver load|unload|install|remove [--name NAME] [--sys PATH]\n"
      "  pmx live [--flags 0xMASK] [--rate HZ] [--count N] [--class C] [--hex N]\n"
      "           [-f RULE] [-x RULE] [--filter-file cfg]... [--filter-dir DIR]\n"
      "           [--match procmon|any] [--groups any|all]\n"
      "           [--pid N] [--proc NAME] [--failed]\n"
      "           [--save FILE] [--csv FILE] [--pml OUT.pml] [--json FILE|-] [--raw] [--net]\n"
      "           [--out FILE] [--silent] [--unfiltered]\n"
      "           [--capture proc,fs,reg|all]\n"
      "           [--config FILE] [--buffer-mb N] [--spool-dir DIR]\n"
      "           classes: 1=Process 2=Registry 3=FileSystem 4=Profiling 5=Network 6=IPC 0=Completion\n"
      "           --capture picks what the DRIVER generates (kernel-side; proc is always\n"
      "           on for process names). --class narrows the driver and every output\n"
      "           (console/--csv/--json/--save/--pml alike are all the filtered view by\n"
      "           default). --unfiltered keeps --save/--pml as the full raw capture;\n"
      "           --csv/--json/console stay filtered either way.\n"
      "           --flags sets the raw mask.\n"
      "           --net also captures ETW network events (TCP/UDP)\n"
      "           --out tees console output to FILE; --silent suppresses the console\n"
      "           events bound for a file are buffered in RAM up to --buffer-mb (or the\n"
      "           config's buffer_mb, default 256) before spilling a sorted run to disk\n"
      "           (--spool-dir, default %%TEMP%%) - keeps a long capture from filling RAM.\n"
      "           Ctrl-C stops the capture and starts writing files; a second Ctrl-C\n"
      "           while that write is in progress aborts it early (files stay valid,\n"
      "           just short).\n"
      "  pmx open FILE.(pmxlog|pml) [-f RULE] [-x RULE] [--filter-file cfg]... [--filter-dir DIR]\n"
      "           [--match procmon|any] [--groups any|all] [--pid N] [--proc NAME] [--failed]\n"
      "           [--class C] [--count N] [--csv OUT.csv] [--pml OUT.pml] [--json FILE|-]\n"
      "           [--summary [--by K] [--top N]] [--quiet]\n"
      "  pmx summary FILE.(pmxlog|pml) [--by path|proc|pid|op|result|class] [--top N]\n"
      "           [filters as for open]      counts per key, most frequent first\n"
      "  pmx filters FILE|DIR...           inspect filter config(s)\n"
      "  pmx net [--count N] [--out F][--silent][--save F][--csv F][--pml F][--json F|-]\n"
      "          [--config FILE] [--buffer-mb N] [--spool-dir DIR]\n"
      "           network only (ETW; admin)\n"
      "  pmx elevate <args...>     relaunch elevated (UAC) explicitly\n"
      "  (driver/live/net auto-elevate via UAC when not already admin; the\n"
      "   elevated window stays open until a key is pressed; add --no-pause to\n"
      "   auto-close it)\n"
      "  config (live/net): --config FILE requires that file to exist and parse; else\n"
      "    <dir of pmx.exe>\\pmx.json is used if present (missing = defaults, malformed\n"
      "    = error). Keys: \"buffer_mb\" (int, clamped >= 16), \"spool_dir\" (string).\n"
      "    --buffer-mb/--spool-dir on the command line override the config file.\n"
      "  filtering (live/open):\n"
      "    --filter-file F (repeatable) / --filter-dir D: each file = an independent\n"
      "      lens with its own includes/excludes; lenses OR'd (--groups any, default)\n"
      "      or AND'd (--groups all)\n"
      "    -f/-x RULE: CLI rule set, AND'd with the lenses\n"
      "    include logic per set: procmon (default: same column OR, columns AND) or\n"
      "      any (all includes OR'd); JSON key \"match\", CLI set via --match\n"
      "    --pid N / --proc NAME (repeatable) / --failed (NTSTATUS error severity,\n"
      "      except FAST_IO_DISALLOWED noise):\n"
      "      shortcuts added to the CLI rule set as includes\n"
      "    --json FILE writes JSON Lines; --json - streams them to stdout instead of rows\n"
      "  filter RULE: \"<Column> <relation> <value>\" e.g. \"Path contains steam\"\n"
      "    columns: ProcessName PID PPID User Integrity Operation Path Result Detail Class ImagePath CommandLine Sequence\n"
      "    relations: is isNot contains excludes beginsWith endsWith lessThan moreThan\n");
}

int run(int argc, wchar_t** argv);

}  // namespace

int wmain(int argc, wchar_t** argv) {
  std::vector<wchar_t*> av(argv, argv + argc);
  // Elevated relaunch: hidden leading args from relaunchElevated - restore the
  // caller's working directory, honour --no-pause - then drop them so the rest
  // of argv is the original command.
  bool elevatedChild = false;
  while (av.size() >= 2) {
    if (!wcscmp(av[1], kCwdArg) && av.size() >= 3) {
      SetCurrentDirectoryW(av[2]);
      elevatedChild = true;
      av.erase(av.begin() + 1, av.begin() + 3);
    } else if (!wcscmp(av[1], kNoPauseArg)) {
      g_noPause = true;
      av.erase(av.begin() + 1);
    } else {
      break;
    }
  }
  // User-facing --no-pause (any position): the auto-elevated window closes as
  // soon as the command ends instead of waiting for a key.
  for (auto it = av.begin() + 1; it != av.end();) {
    if (!wcscmp(*it, L"--no-pause")) {
      g_noPause = true;
      it = av.erase(it);
    } else {
      ++it;
    }
  }

  const int rc = run(static_cast<int>(av.size()), av.data());

  std::fflush(stdout);
  if (elevatedChild && !g_noPause) pauseBeforeExit(rc);
  return rc;
}

namespace {

int run(int argc, wchar_t** argv) {
  if (argc < 2) {
    usage();
    return 1;
  }
  const std::wstring cmd = argv[1];

  if (cmd == L"elevate") return relaunchElevated(joinArgs(argc, argv, 2));
  // Auto-elevate the commands that talk to the driver / comm port. `live` always
  // needs admin; `driver` needs it for everything except read-only `status`.
  // `open`/`filters` are offline and stay unprivileged (they model the low-priv
  // attacker's view of the filesystem/registry).
  if (cmd == L"live") ensureElevated(argc, argv);
  if (cmd == L"net") ensureElevated(argc, argv);
  if (cmd == L"driver" && !(argc >= 3 && !wcscmp(argv[2], L"status")))
    ensureElevated(argc, argv);

  if (cmd == L"driver") return cmdDriver(argc - 2, argv + 2);
  if (cmd == L"live") return cmdLive(argc - 2, argv + 2);
  if (cmd == L"net") return cmdNet(argc - 2, argv + 2);
  if (cmd == L"open") return cmdOpenOrSummary(argc - 2, argv + 2, false);
  if (cmd == L"summary") return cmdOpenOrSummary(argc - 2, argv + 2, true);
  if (cmd == L"filters") return cmdFilters(argc - 2, argv + 2);
  usage();
  return 1;
}

}  // namespace
