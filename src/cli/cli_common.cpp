#include "cli_common.h"

#include <windows.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwctype>

#include "pmx/filter_pmc.h"
#include "pmx/filter_json.h"
#include "pmx/store.h"

namespace pmx::cli {

std::FILE* g_outFile = nullptr;
bool g_silent = false;
bool g_jsonStdout = false;
bool g_noPause = false;

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

std::string toUtf8(const wchar_t* s, int len) {
  if (!s || len == 0) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, s, len, nullptr, 0, nullptr, nullptr);
  if (n <= 0) return {};
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, s, len, out.data(), n, nullptr, nullptr);
  if (len < 0 && !out.empty() && out.back() == '\0') out.pop_back();  // -1 counts the NUL
  return out;
}

std::error_code loadFilterConfig(const wchar_t* path, pmx::FilterSet& out) {
  const wchar_t* dot = wcsrchr(path, L'.');
  if (dot && (!_wcsicmp(dot, L".reg") || !_wcsicmp(dot, L".pmc")))
    return pmx::loadFilterReg(path, out);
  return pmx::loadFilterJson(path, out);
}

std::error_code loadFilterDir(const wchar_t* dir, pmx::FilterGroup& out) {
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

  for (const auto& name : files) {
    std::wstring full = std::wstring(dir) + L"\\" + name;
    pmx::FilterSet set;
    std::error_code ec = loadFilterConfig(full.c_str(), set);
    if (ec) {
      errf("filter-dir: skipped %ls (%s)\n", name.c_str(), ec.message().c_str());
    } else {
      out.addSet(std::move(set));
      errf("filter-dir: loaded %ls\n", name.c_str());
    }
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
    std::error_code fe = loadFilterDir(fc.dir, lenses);
    if (fe) {
      printError("filter-dir", fe);
      return 2;
    }
  }
  for (const wchar_t* f : fc.files) {
    pmx::FilterSet set;
    std::error_code fe = loadFilterConfig(f, set);
    if (fe) {
      errf("filter-file %ls: [%d] %s\n", f, fe.value(), fe.message().c_str());
      return 2;
    }
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

}  // namespace pmx::cli
