#include "cli_common.h"

#include <windows.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>

#include "pmx/file_io.h"
#include "pmx/filter_pmc.h"
#include "pmx/filter_json.h"
#include "pmx/pml.h"
#include "pmx/store.h"

namespace pmx::cli {

std::FILE* g_outFile = nullptr;
bool g_silent = false;
bool g_jsonStdout = false;
bool g_noPause = false;
std::atomic<bool> g_abortWrite{false};
std::atomic<bool> g_writing{false};
std::atomic<uint64_t> g_closeDeadline{0};

void writeOut(const char* s, size_t n) {
  if (!g_silent) std::fwrite(s, 1, n, stdout);
  if (g_outFile) std::fwrite(s, 1, n, g_outFile);
}

namespace {
std::string vformat(const char* fmt, va_list ap) {
  va_list ap2;
  va_copy(ap2, ap);
  const int n = std::vsnprintf(nullptr, 0, fmt, ap2);
  va_end(ap2);
  if (n <= 0) return {};
  std::string s(static_cast<size_t>(n) + 1, '\0');
  std::vsnprintf(s.data(), s.size(), fmt, ap);
  s.resize(static_cast<size_t>(n));
  return s;
}
}  // namespace

void outf(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  const std::string s = vformat(fmt, ap);
  va_end(ap);
  writeOut(s.data(), s.size());
}

void errf(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  const std::string s = vformat(fmt, ap);
  va_end(ap);
  std::fwrite(s.data(), 1, s.size(), stderr);
}

void statusf(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  const std::string s = vformat(fmt, ap);
  va_end(ap);
  if (g_jsonStdout)
    std::fwrite(s.data(), 1, s.size(), stderr);
  else
    writeOut(s.data(), s.size());
}

void writeJsonRow(const pmx::Event& ev) {
  const std::string j = pmx::eventToJson(ev) + "\n";
  writeOut(j.data(), j.size());
}

void printError(const char* what, std::error_code ec) {
  errf("%s: [%d] %s\n", what, ec.value(), ec.message().c_str());
}

void printError(const char* what, std::error_code ec, const std::string& why) {
  if (why.empty())
    printError(what, ec);
  else
    errf("%s: [%d] %s: %s\n", what, ec.value(), ec.message().c_str(), why.c_str());
}

std::string toUtf8(const wchar_t* s, int len) {
  if (!s || len == 0) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, s, len, nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, s, len, out.data(), n, nullptr, nullptr);
  if (len < 0 && !out.empty() && out.back() == '\0') out.pop_back();  // -1 counts the NUL
  return out;
}

std::error_code loadFilterConfig(const wchar_t* path, pmx::FilterSet& out,
                                 std::string* why) {
  const wchar_t* dot = wcsrchr(path, L'.');
  if (dot && (!_wcsicmp(dot, L".reg") || !_wcsicmp(dot, L".pmc")))
    return pmx::loadFilterReg(path, out);
  return pmx::loadFilterJson(path, out, why);
}

std::error_code loadFilterDir(const wchar_t* dir, pmx::FilterGroup& out,
                              std::string* why) {
  std::wstring pattern = std::wstring(dir) + L"\\*";
  WIN32_FIND_DATAW fd{};
  HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE)
    return {static_cast<int>(GetLastError()), std::system_category()};

  std::vector<std::wstring> files;
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    const wchar_t* dot = wcsrchr(fd.cFileName, L'.');
    if (!dot) continue;
    if (_wcsicmp(dot, L".json") && _wcsicmp(dot, L".reg") &&
        _wcsicmp(dot, L".pmc"))
      continue;
    files.push_back(fd.cFileName);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  std::sort(files.begin(), files.end());
  // A missing or broken lens must not silently widen the filter (lenses OR).
  if (files.empty()) {
    if (why) *why = "no .json/.reg/.pmc filter configs in " + toUtf8(dir, -1);
    return {ERROR_FILE_NOT_FOUND, std::system_category()};
  }

  for (const auto& name : files) {
    std::wstring full = std::wstring(dir) + L"\\" + name;
    pmx::FilterSet set;
    std::string reason;
    if (std::error_code ec = loadFilterConfig(full.c_str(), set, &reason)) {
      if (why)
        *why = toUtf8(name.c_str(), -1) + (reason.empty() ? "" : ": " + reason);
      return ec;
    }
    if (set.rules().empty())
      errf("filter %ls: no rules - this lens matches every event\n", name.c_str());
    out.addSet(std::move(set));
    errf("filter-dir: loaded %ls\n", name.c_str());
  }
  return {};
}

bool parseFilterArg(int argc, wchar_t** argv, int& i, FilterCli& fc) {
  const wchar_t* a = argv[i];
  const bool hasVal = i + 1 < argc;
  if ((!wcscmp(a, L"--filter") || !wcscmp(a, L"-f")) && hasVal)
    fc.includes.push_back(argv[++i]);
  else if ((!wcscmp(a, L"--exclude") || !wcscmp(a, L"-x")) && hasVal)
    fc.excludes.push_back(argv[++i]);
  else if (!wcscmp(a, L"--filter-file") && hasVal)
    fc.files.push_back(argv[++i]);
  else if (!wcscmp(a, L"--filter-dir") && hasVal)
    fc.dir = argv[++i];
  else if (!wcscmp(a, L"--match") && hasVal)
    fc.match = argv[++i];
  else if (!wcscmp(a, L"--groups") && hasVal)
    fc.groups = argv[++i];
  else if (!wcscmp(a, L"--pid") && hasVal)
    fc.pids.push_back(argv[++i]);
  else if (!wcscmp(a, L"--proc") && hasVal)
    fc.procs.push_back(argv[++i]);
  else if (!wcscmp(a, L"--failed"))
    fc.failed = true;
  else
    return false;
  return true;
}

int buildFilters(const FilterCli& fc, pmx::FilterSet& cliSet,
                 pmx::FilterGroup& lenses) {
  if (fc.match) {
    auto m = pmx::parseIncludeMode(fc.match);
    if (!m) {
      errf("bad --match %ls (want procmon|any)\n", fc.match);
      return 2;
    }
    cliSet.setIncludeMode(*m);
  }
  if (fc.groups) {
    auto g = pmx::parseGroupMode(fc.groups);
    if (!g) {
      errf("bad --groups %ls (want any|all)\n", fc.groups);
      return 2;
    }
    lenses.setMode(*g);
  }
  if (fc.dir) {
    std::string why;
    std::error_code fe = loadFilterDir(fc.dir, lenses, &why);
    if (fe) {
      printError("filter-dir", fe, why);
      return 2;
    }
  }
  for (const wchar_t* f : fc.files) {
    pmx::FilterSet set;
    std::string why;
    std::error_code fe = loadFilterConfig(f, set, &why);
    if (fe) {
      if (why.empty())
        errf("filter-file %ls: [%d] %s\n", f, fe.value(), fe.message().c_str());
      else
        errf("filter-file %ls: [%d] %s: %s\n", f, fe.value(), fe.message().c_str(),
             why.c_str());
      return 2;
    }
    if (set.rules().empty())
      errf("filter %ls: no rules - this lens matches every event\n", f);
    lenses.addSet(std::move(set));
  }
  for (const auto& s : fc.includes) {
    if (auto r = pmx::parseRule(s, pmx::Action::Include))
      cliSet.add(*r);
    else {
      errf("bad --filter: %ls\n", s.c_str());
      return 2;
    }
  }
  for (const auto& s : fc.excludes) {
    if (auto r = pmx::parseRule(s, pmx::Action::Exclude))
      cliSet.add(*r);
    else {
      errf("bad --exclude: %ls\n", s.c_str());
      return 2;
    }
  }
  // Shortcuts. Under the default procmon match mode, several --pid (or --proc)
  // OR together, and --pid / --proc / --failed AND with each other.
  for (const auto& p : fc.pids) {
    wchar_t* end = nullptr;
    wcstoul(p.c_str(), &end, 0);
    if (p.empty() || *end) {
      errf("bad --pid %ls\n", p.c_str());
      return 2;
    }
    cliSet.add({pmx::Column::Pid, pmx::Relation::Is, p, pmx::Action::Include});
  }
  for (const auto& p : fc.procs)
    cliSet.add({pmx::Column::ProcessName, pmx::Relation::Is, p,
                pmx::Action::Include});
  if (fc.failed) {  // error severity, minus fast-I/O fallbacks
    cliSet.add({pmx::Column::Result, pmx::Relation::MoreThan, L"0xBFFFFFFF",
                pmx::Action::Include});
    cliSet.add({pmx::Column::Result, pmx::Relation::Is, L"FAST_IO_DISALLOWED",
                pmx::Action::Exclude});
  }
  return 0;
}

namespace {
std::wstring exeDir() {
  wchar_t path[MAX_PATH];
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  std::wstring s(path);
  const size_t slash = s.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"." : s.substr(0, slash);
}

std::wstring utf8ToW(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
  return w;
}

// Minimal flat-object JSON scanner for pmx.json: string/number values only,
// unknown keys skipped whole (object/array/string/primitive). Not shared with
// filter_json.cpp's parser - that one is tied to FilterSet-specific plumbing.
struct ConfigJson {
  const char* p;
  const char* end;

  void ws() {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
  }
  bool eat(char c) {
    ws();
    if (p < end && *p == c) { ++p; return true; }
    return false;
  }
  bool str(std::string& out) {
    ws();
    if (p >= end || *p != '"') return false;
    ++p;
    out.clear();
    while (p < end && *p != '"') {
      char c = *p++;
      if (c == '\\' && p < end) {
        char e = *p++;
        out.push_back(e == 'n' ? '\n' : e == 't' ? '\t' : e == 'r' ? '\r' : e);
      } else {
        out.push_back(c);
      }
    }
    if (p >= end) return false;
    ++p;  // closing quote
    return true;
  }
  bool number(long long& out) {
    ws();
    const char* s = p;
    if (p < end && (*p == '-' || *p == '+')) ++p;
    while (p < end && *p >= '0' && *p <= '9') ++p;
    if (p == s || (p == s + 1 && (*s == '-' || *s == '+'))) return false;
    out = std::strtoll(std::string(s, p).c_str(), nullptr, 10);
    return true;
  }
  void skipValue() {
    ws();
    if (p >= end) return;
    if (*p == '"') { std::string t; str(t); return; }
    if (*p == '{' || *p == '[') {
      const char open = *p, close = (open == '{') ? '}' : ']';
      ++p;
      int depth = 1;
      while (p < end && depth) {
        ws();
        if (p >= end) break;
        if (*p == '"') { std::string t; str(t); continue; }
        if (*p == open) ++depth;
        else if (*p == close) --depth;
        ++p;
      }
      return;
    }
    while (p < end && *p != ',' && *p != '}' && *p != ']') ++p;
  }
};
}  // namespace

int loadPmxConfig(const wchar_t* explicitPath, PmxConfig& out) {
  const bool required = explicitPath != nullptr;
  const std::wstring path = required ? explicitPath : exeDir() + L"\\pmx.json";

  std::string buf;
  if (std::error_code ec = pmx::readWholeFile(path.c_str(), buf)) {
    if (!required) return 0;  // no --config, and no pmx.json next to the exe
    errf("config %ls: [%d] %s\n", path.c_str(), ec.value(), ec.message().c_str());
    return 2;
  }
  size_t start = 0;
  if (buf.size() >= 3 && (uint8_t)buf[0] == 0xEF && (uint8_t)buf[1] == 0xBB &&
      (uint8_t)buf[2] == 0xBF)
    start = 3;  // tolerate a UTF-8 BOM

  ConfigJson j{buf.data() + start, buf.data() + buf.size()};
  auto bad = [&] { errf("config %ls: malformed JSON\n", path.c_str()); return 2; };
  if (!j.eat('{')) return bad();
  if (!j.eat('}')) {
    do {
      std::string key;
      if (!j.str(key) || !j.eat(':')) return bad();
      if (key == "buffer_mb") {
        long long n;
        if (!j.number(n)) return bad();
        out.bufferMb = n < 16 ? 16 : (size_t)n;
      } else if (key == "spool_dir") {
        std::string v;
        if (!j.str(v)) return bad();
        out.spoolDir = utf8ToW(v);
      } else {
        j.skipValue();
      }
    } while (j.eat(','));
    if (!j.eat('}')) return bad();
  }
  return 0;
}

int finalizeSpool(pmx::EventSpool& spool, const LiveOutputPaths& paths,
                  bool unfiltered) {
  pmx::PmxlogWriter pmxw;
  pmx::CsvWriter csvw;
  pmx::JsonWriter jsonw;
  pmx::PmlWriter pmlw;

  std::error_code openErr;
  if (paths.save && !openErr) openErr = pmxw.open(paths.save);
  if (paths.csv && !openErr) openErr = csvw.open(paths.csv);
  if (paths.json && !openErr) openErr = jsonw.open(paths.json);
  if (paths.pml && !openErr) openErr = pmlw.open(paths.pml);

  auto closeAll = [&] {
    if (paths.save) pmxw.close();
    if (paths.csv) csvw.close();
    if (paths.json) jsonw.close();
    if (paths.pml) pmlw.close();
  };
  if (openErr) {
    printError("live output", openErr);
    closeAll();
    return 5;
  }

  const uint64_t total = spool.count();
  statusf("Writing %llu events... (Ctrl-C to stop early; files stay valid)\n",
         (unsigned long long)total);
  g_abortWrite = false;
  g_writing = true;

  uint64_t written = 0;
  ULONGLONG lastTick = GetTickCount64();
  const bool showProgress = total >= 50000 || spool.runs() > 0;
  std::error_code writeErr;
  spool.drain([&](const pmx::Event& ev, uint8_t tag) -> bool {
    const bool pass = (tag & 1) != 0;
    if ((pass || unfiltered) && paths.save && !writeErr) writeErr = pmxw.write(ev);
    if ((pass || unfiltered) && paths.pml && !writeErr) writeErr = pmlw.write(ev);
    if (pass && paths.csv && !writeErr) writeErr = csvw.write(ev);
    if (pass && paths.json && !writeErr) writeErr = jsonw.write(ev);
    ++written;
    if (showProgress) {
      const ULONGLONG now = GetTickCount64();
      if (now - lastTick >= 250 || written == total) {
        lastTick = now;
        const unsigned pct = total ? (unsigned)(written * 100 / total) : 100;
        errf("\r[pmx] writing %llu/%llu (%u%%)", (unsigned long long)written,
             (unsigned long long)total, pct);
      }
    }
    if (!g_abortWrite && g_closeDeadline != 0 && GetTickCount64() >= g_closeDeadline)
      g_abortWrite = true;
    return !writeErr && !g_abortWrite;
  });
  g_writing = false;
  if (showProgress) errf("\n");

  if (writeErr) {
    printError("live output", writeErr);
    closeAll();
    return 5;
  }
  if (g_abortWrite && written < total)
    statusf("Stopped early: wrote %llu of %llu events\n",
           (unsigned long long)written, (unsigned long long)total);

  std::error_code closeErr;
  if (paths.save) {
    std::error_code e = pmxw.close();
    if (e) closeErr = e;
    else statusf("Saved %llu events to %ls\n", (unsigned long long)pmxw.count(), paths.save);
  }
  if (paths.csv) {
    std::error_code e = csvw.close();
    if (e) closeErr = e;
    else statusf("Wrote %llu events to %ls\n", (unsigned long long)csvw.count(), paths.csv);
  }
  if (paths.json) {
    std::error_code e = jsonw.close();
    if (e) closeErr = e;
    else statusf("Wrote %llu events to %ls\n", (unsigned long long)jsonw.count(), paths.json);
  }
  if (paths.pml) {
    std::error_code e = pmlw.close();
    if (e) closeErr = e;
    else statusf("Wrote %llu events to %ls\n", (unsigned long long)pmlw.count(), paths.pml);
  }
  if (closeErr) {
    printError("live output", closeErr);
    return 5;
  }
  return 0;
}

}  // namespace pmx::cli
