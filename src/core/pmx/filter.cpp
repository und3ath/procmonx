#include "pmx/filter.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <iterator>

namespace pmx {

namespace {
// Locale-independent simple lowercase for every UTF-16 unit (towlower in the
// C locale only folds ASCII, so "É" never matched "é").
wchar_t fold(wchar_t c) {
  if (c < 0x80) return (c >= L'A' && c <= L'Z') ? c + 32 : c;
  static const std::vector<wchar_t> table = [] {
    std::vector<wchar_t> t(0x10000);
    for (uint32_t i = 0; i < 0x10000; ++i) {
      wchar_t in = static_cast<wchar_t>(i), out = in;
      if (i >= 0x80 && (i < 0xD800 || i > 0xDFFF))
        LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, &in, 1, &out, 1,
                      nullptr, nullptr, 0);
      t[i] = out;
    }
    return t;
  }();
  return table[c];
}

std::wstring lower(std::wstring s) {
  for (auto& c : s) c = fold(c);
  return s;
}

std::wstring trim(std::wstring s) {
  size_t a = s.find_first_not_of(L" \t");
  size_t b = s.find_last_not_of(L" \t");
  if (a == std::wstring::npos) return {};
  return s.substr(a, b - a + 1);
}

bool isNumericColumn(Column c) {
  return c == Column::Pid || c == Column::ParentPid || c == Column::Sequence;
}

std::wstring widenA(const std::string& s) { return {s.begin(), s.end()}; }

uint64_t numericField(const Event& ev, Column c) {
  switch (c) {
    case Column::Pid: return ev.pid;
    case Column::ParentPid: return ev.parentPid;
    case Column::Sequence: return ev.sequence;
    default: return 0;
  }
}

// Parse a whole-string unsigned number (decimal or 0x-hex).
bool parseNumber(const std::wstring& s, uint64_t& out) {
  if (s.empty()) return false;
  try {
    size_t used = 0;
    out = std::stoull(s, &used, 0);
    return used == s.size();
  } catch (...) {
    return false;
  }
}

// Per-character case-folding views over an event field, so the string
// relations below can compare/search without lowercasing (i.e. allocating)
// the field on every rule. `at(i)` returns the folded wchar_t at index i.
struct WFolder {
  const wchar_t* s;
  size_t n;
  wchar_t at(size_t i) const { return fold(s[i]); }
  size_t size() const { return n; }
};
struct AFolder {
  const char* s;
  size_t n;
  wchar_t at(size_t i) const {
    return fold(static_cast<wchar_t>(static_cast<unsigned char>(s[i])));
  }
  size_t size() const { return n; }
};

template <class F>
bool ciEqual(const F& hay, const std::wstring& needle) {
  if (hay.size() != needle.size()) return false;
  for (size_t i = 0; i < hay.size(); ++i)
    if (hay.at(i) != needle[i]) return false;
  return true;
}

template <class F>
bool ciContains(const F& hay, const std::wstring& needle) {
  if (needle.empty()) return true;
  if (needle.size() > hay.size()) return false;
  for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
    bool ok = true;
    for (size_t j = 0; j < needle.size(); ++j)
      if (hay.at(i + j) != needle[j]) { ok = false; break; }
    if (ok) return true;
  }
  return false;
}

template <class F>
bool ciBeginsWith(const F& hay, const std::wstring& needle) {
  if (needle.size() > hay.size()) return false;
  for (size_t j = 0; j < needle.size(); ++j)
    if (hay.at(j) != needle[j]) return false;
  return true;
}

template <class F>
bool ciEndsWith(const F& hay, const std::wstring& needle) {
  if (needle.size() > hay.size()) return false;
  const size_t off = hay.size() - needle.size();
  for (size_t j = 0; j < needle.size(); ++j)
    if (hay.at(off + j) != needle[j]) return false;
  return true;
}

// <0 / 0 / >0, lexicographic over folded chars (same ordering as comparing
// two already-lowered std::wstrings).
template <class F>
int ciCompare(const F& hay, const std::wstring& needle) {
  const size_t n = (hay.size() < needle.size()) ? hay.size() : needle.size();
  for (size_t i = 0; i < n; ++i) {
    const wchar_t a = hay.at(i), b = needle[i];
    if (a != b) return a < b ? -1 : 1;
  }
  if (hay.size() < needle.size()) return -1;
  if (hay.size() > needle.size()) return 1;
  return 0;
}

template <class F>
bool matchByRelation(const F& hay, Relation rel, const std::wstring& rhs) {
  switch (rel) {
    case Relation::Is: return ciEqual(hay, rhs);
    case Relation::IsNot: return !ciEqual(hay, rhs);
    case Relation::Contains: return ciContains(hay, rhs);
    case Relation::Excludes: return !ciContains(hay, rhs);
    case Relation::BeginsWith: return ciBeginsWith(hay, rhs);
    case Relation::EndsWith: return ciEndsWith(hay, rhs);
    case Relation::LessThan: return ciCompare(hay, rhs) < 0;
    case Relation::MoreThan: return ciCompare(hay, rhs) > 0;
    default: return false;
  }
}

bool matchWide(const std::wstring& s, Relation rel, const std::wstring& rhs) {
  return matchByRelation(WFolder{s.data(), s.size()}, rel, rhs);
}
bool matchAscii(const std::string& s, Relation rel, const std::wstring& rhs) {
  return matchByRelation(AFolder{s.data(), s.size()}, rel, rhs);
}
// EventClass: skip spaces on the event side too (rule side already stripped
// them into normValue at compile time). className is a short friendly name
// ("FileSystem", "Registry", ...), so a small stack buffer is enough.
bool matchEventClass(const std::string& s, Relation rel, const std::wstring& rhs) {
  char buf[64];
  size_t n = 0;
  for (char ch : s) {
    if (ch == ' ') continue;
    if (n < sizeof buf) buf[n++] = ch;
  }
  return matchByRelation(AFolder{buf, n}, rel, rhs);
}
// Numeric column vs a string relation (Contains etc.): format into a stack
// buffer instead of std::to_wstring, same decimal text either way.
bool matchNumericAsString(uint64_t v, Relation rel, const std::wstring& rhs) {
  wchar_t buf[24];
  int n = swprintf(buf, std::size(buf), L"%llu", (unsigned long long)v);
  return matchByRelation(WFolder{buf, n > 0 ? (size_t)n : 0}, rel, rhs);
}

// Per-matches() context: statusName(ev.result) is formatted at most once,
// lazily, even though several Result rules may consult it.
struct MatchContext {
  const Event& ev;
  mutable std::string resultName;
  mutable bool resultNameComputed = false;
  const std::string& resultNameStr() const {
    if (!resultNameComputed) {
      resultName = statusName(ev.result);
      resultNameComputed = true;
    }
    return resultName;
  }
};

bool ruleMatches(const MatchContext& ctx, const detail::CompiledRule& c) {
  const Event& ev = ctx.ev;
  // Result orders by its raw NTSTATUS when compared against a number, e.g.
  // "Result moreThan 0xBFFFFFFF" = error severity (what --failed uses). Name
  // relations ("Result is NAME_NOT_FOUND") stay string compares below.
  if (c.resultNumericOrdering)
    return c.relation == Relation::LessThan ? ev.result < c.numberValue
                                             : ev.result > c.numberValue;

  // Numeric columns compare as integers for ordering / equality.
  if (isNumericColumn(c.column) &&
      (c.relation == Relation::Is || c.relation == Relation::IsNot ||
       c.relation == Relation::LessThan || c.relation == Relation::MoreThan)) {
    uint64_t lhs = numericField(ev, c.column);
    if (!c.valueIsNumber)
      return c.relation == Relation::IsNot;  // a number never "is" a non-number
    switch (c.relation) {
      case Relation::Is: return lhs == c.numberValue;
      case Relation::IsNot: return lhs != c.numberValue;
      case Relation::LessThan: return lhs < c.numberValue;
      case Relation::MoreThan: return lhs > c.numberValue;
      default: return false;
    }
  }

  switch (c.column) {
    case Column::ProcessName: return matchWide(ev.processName, c.relation, c.normValue);
    case Column::Path: return matchWide(ev.path, c.relation, c.normValue);
    case Column::Detail: return matchWide(ev.detail, c.relation, c.normValue);
    case Column::ImagePath: return matchWide(ev.imagePath, c.relation, c.normValue);
    case Column::CommandLine: return matchWide(ev.commandLine, c.relation, c.normValue);
    case Column::User: return matchWide(ev.user, c.relation, c.normValue);
    case Column::Integrity: return matchWide(ev.integrity, c.relation, c.normValue);
    case Column::Operation: return matchAscii(ev.opName, c.relation, c.normValue);
    case Column::EventClass: return matchEventClass(ev.className, c.relation, c.normValue);
    case Column::Result: return matchAscii(ctx.resultNameStr(), c.relation, c.normValue);
    case Column::Pid: return matchNumericAsString(ev.pid, c.relation, c.normValue);
    case Column::ParentPid: return matchNumericAsString(ev.parentPid, c.relation, c.normValue);
    case Column::Sequence: return matchNumericAsString(ev.sequence, c.relation, c.normValue);
  }
  return false;
}
}  // namespace

std::optional<Column> parseColumn(const std::wstring& s0) {
  const std::wstring s = lower(trim(s0));
  if (s == L"processname" || s == L"process" || s == L"name" || s == L"proc")
    return Column::ProcessName;
  if (s == L"pid") return Column::Pid;
  if (s == L"ppid" || s == L"parentpid") return Column::ParentPid;
  if (s == L"operation" || s == L"op") return Column::Operation;
  if (s == L"path") return Column::Path;
  if (s == L"result" || s == L"status") return Column::Result;
  if (s == L"detail") return Column::Detail;
  if (s == L"class" || s == L"eventclass") return Column::EventClass;
  if (s == L"imagepath" || s == L"image") return Column::ImagePath;
  if (s == L"commandline" || s == L"cmdline" || s == L"cmd")
    return Column::CommandLine;
  if (s == L"sequence" || s == L"seq") return Column::Sequence;
  if (s == L"user") return Column::User;
  if (s == L"integrity" || s == L"il") return Column::Integrity;
  return std::nullopt;
}

std::optional<Relation> parseRelation(const std::wstring& s0) {
  const std::wstring s = lower(trim(s0));
  if (s == L"is" || s == L"==" || s == L"eq") return Relation::Is;
  if (s == L"isnot" || s == L"is-not" || s == L"!=" || s == L"ne")
    return Relation::IsNot;
  if (s == L"contains" || s == L"has") return Relation::Contains;
  if (s == L"excludes" || s == L"notcontains") return Relation::Excludes;
  if (s == L"beginswith" || s == L"begins-with" || s == L"startswith" ||
      s == L"begins")
    return Relation::BeginsWith;
  if (s == L"endswith" || s == L"ends-with" || s == L"ends")
    return Relation::EndsWith;
  if (s == L"less" || s == L"lessthan" || s == L"<") return Relation::LessThan;
  if (s == L"more" || s == L"morethan" || s == L">" || s == L"greater")
    return Relation::MoreThan;
  return std::nullopt;
}

const char* columnName(Column c) noexcept {
  switch (c) {
    case Column::ProcessName: return "ProcessName";
    case Column::Pid: return "PID";
    case Column::ParentPid: return "ParentPID";
    case Column::Operation: return "Operation";
    case Column::Path: return "Path";
    case Column::Result: return "Result";
    case Column::Detail: return "Detail";
    case Column::EventClass: return "Class";
    case Column::ImagePath: return "ImagePath";
    case Column::CommandLine: return "CommandLine";
    case Column::Sequence: return "Sequence";
    case Column::User: return "User";
    case Column::Integrity: return "Integrity";
  }
  return "?";
}

const char* relationName(Relation r) noexcept {
  switch (r) {
    case Relation::Is: return "is";
    case Relation::IsNot: return "isNot";
    case Relation::Contains: return "contains";
    case Relation::Excludes: return "excludes";
    case Relation::BeginsWith: return "beginsWith";
    case Relation::EndsWith: return "endsWith";
    case Relation::LessThan: return "lessThan";
    case Relation::MoreThan: return "moreThan";
  }
  return "?";
}

std::optional<Rule> parseRule(const std::wstring& text, Action action) {
  const std::wstring t = trim(text);
  size_t p1 = t.find_first_of(L" \t");
  if (p1 == std::wstring::npos) return std::nullopt;
  size_t p2s = t.find_first_not_of(L" \t", p1);
  size_t p2 = t.find_first_of(L" \t", p2s);
  if (p2 == std::wstring::npos) return std::nullopt;
  auto col = parseColumn(t.substr(0, p1));
  auto rel = parseRelation(t.substr(p2s, p2 - p2s));
  if (!col || !rel) return std::nullopt;
  std::wstring value = trim(t.substr(p2));
  return Rule{*col, *rel, value, action};
}

std::wstring ruleToString(const Rule& r) {
  std::wstring out = widenA(columnName(r.column));
  out += L' ';
  out += widenA(relationName(r.relation));
  out += L' ';
  out += r.value;
  return out;
}

void FilterSet::add(Rule r) {
  detail::CompiledRule c;
  c.column = r.column;
  c.relation = r.relation;
  c.action = r.action;
  std::wstring norm = lower(r.value);
  if (r.column == Column::Result) {
    std::replace(norm.begin(), norm.end(), L' ', L'_');
  } else if (r.column == Column::EventClass) {
    std::erase(norm, L' ');
  }
  c.normValue = std::move(norm);
  c.valueIsNumber = parseNumber(r.value, c.numberValue);
  c.resultNumericOrdering =
      r.column == Column::Result &&
      (r.relation == Relation::LessThan || r.relation == Relation::MoreThan) &&
      c.valueIsNumber;
  compiled_.push_back(std::move(c));
  rules_.push_back(std::move(r));
}

bool FilterSet::matches(const Event& ev) const {
  // Any matching Exclude hides the event. PerColumn (Procmon): includes on the
  // SAME column are OR'd, groups on DIFFERENT columns AND'd (e.g. "ProcessName
  // is a.exe" + "Operation is WriteFile" = a.exe's writes).
  // IncludeMode::Any collapses every include into one group (slot 0).
  constexpr size_t kCols = static_cast<size_t>(Column::Integrity) + 1;
  bool hasInclude[kCols] = {};
  bool matchedInclude[kCols] = {};
  MatchContext ctx{ev};
  for (const auto& c : compiled_) {
    const bool m = ruleMatches(ctx, c);
    if (c.action == Action::Exclude) {
      if (m) return false;
    } else {
      const size_t idx =
          mode_ == IncludeMode::Any ? 0 : static_cast<size_t>(c.column);
      hasInclude[idx] = true;
      if (m) matchedInclude[idx] = true;
    }
  }
  for (size_t c = 0; c < kCols; ++c)
    if (hasInclude[c] && !matchedInclude[c]) return false;
  return true;
}

std::optional<IncludeMode> parseIncludeMode(const std::wstring& s0) {
  const std::wstring s = lower(trim(s0));
  if (s == L"procmon" || s == L"column" || s == L"percolumn" ||
      s == L"per-column")
    return IncludeMode::PerColumn;
  if (s == L"any" || s == L"or") return IncludeMode::Any;
  return std::nullopt;
}

std::optional<GroupMode> parseGroupMode(const std::wstring& s0) {
  const std::wstring s = lower(trim(s0));
  if (s == L"any" || s == L"or") return GroupMode::Any;
  if (s == L"all" || s == L"and") return GroupMode::All;
  return std::nullopt;
}

const char* includeModeName(IncludeMode m) noexcept {
  return m == IncludeMode::Any ? "any" : "procmon";
}

const char* groupModeName(GroupMode m) noexcept {
  return m == GroupMode::All ? "all" : "any";
}

std::string statusName(uint32_t s) {
  switch (s) {
    case 0x00000000: return "SUCCESS";
    case 0x00000103: return "PENDING";
    case 0x00000104: return "REPARSE";
    case 0x00000105: return "MORE_ENTRIES";
    case 0x0000010A: return "NOTIFY_CLEANUP";
    case 0x0000010B: return "NOTIFY_ENUM_DIR";
    case 0x0000012A: return "FILE_LOCKED_WITH_ONLY_READERS";
    case 0x00000216: return "OPLOCK_BREAK_IN_PROGRESS";
    case 0x40000016: return "END_OF_FILE";  // (info)
    case 0x80000005: return "BUFFER_OVERFLOW";
    case 0x80000006: return "NO_MORE_FILES";
    case 0xC0000001: return "UNSUCCESSFUL";
    case 0xC0000002: return "NOT_IMPLEMENTED";
    case 0xC0000003: return "INVALID_INFO_CLASS";
    case 0xC0000008: return "INVALID_HANDLE";
    case 0xC000000D: return "INVALID_PARAMETER";
    case 0xC000000F: return "NO_SUCH_FILE";
    case 0xC0000010: return "INVALID_DEVICE_REQUEST";
    case 0xC0000039: return "OBJECT_PATH_INVALID";
    case 0xC000003A: return "PATH_NOT_FOUND";
    case 0xC0000011: return "END_OF_FILE";
    case 0xC0000022: return "ACCESS_DENIED";
    case 0xC0000023: return "BUFFER_TOO_SMALL";
    case 0xC0000034: return "NAME_NOT_FOUND";
    case 0xC0000035: return "NAME_COLLISION";
    case 0xC0000043: return "SHARING_VIOLATION";
    case 0xC0000056: return "DELETE_PENDING";
    case 0xC00000BA: return "FILE_IS_A_DIRECTORY";
    case 0xC0000101: return "DIRECTORY_NOT_EMPTY";
    case 0xC0000103: return "NOT_A_DIRECTORY";
    case 0xC000010A: return "PROCESS_IS_TERMINATING";
    case 0xC0000120: return "CANCELLED";
    case 0xC0000225: return "NOT_FOUND";
    case 0xC0000275: return "NOT_REPARSE_POINT";
    case 0xC0000061: return "PRIVILEGE_NOT_HELD";
    case 0xC00000BB: return "NOT_SUPPORTED";
    case 0xC0000033: return "OBJECT_NAME_INVALID";
    case 0xC01C0004: return "FAST_IO_DISALLOWED";  // filter-manager fallback noise
    default: {
      char b[16];
      std::snprintf(b, sizeof b, "0x%08X", s);
      return b;
    }
  }
}

}  // namespace pmx
