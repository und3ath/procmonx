#include "pmx/filter.h"

#include <algorithm>
#include <cstdio>
#include <cwctype>

namespace pmx {

namespace {
std::wstring lower(std::wstring s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](wchar_t c) { return towlower(c); });
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

// The event's value for a column, as a string (numeric columns use decimal).
std::wstring fieldValue(const Event& ev, Column c) {
  switch (c) {
    case Column::ProcessName: return ev.processName;
    case Column::Pid: return std::to_wstring(ev.pid);
    case Column::ParentPid: return std::to_wstring(ev.parentPid);
    case Column::Operation: return widenA(ev.opName);
    case Column::Path: return ev.path;
    case Column::Result: return widenA(statusName(ev.result));
    case Column::Detail: return ev.detail;
    case Column::EventClass: return widenA(ev.className);
    case Column::ImagePath: return ev.imagePath;
    case Column::CommandLine: return ev.commandLine;
    case Column::Sequence: return std::to_wstring(ev.sequence);
    case Column::User: return ev.user;
    case Column::Integrity: return ev.integrity;
  }
  return {};
}

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

bool ruleMatches(const Event& ev, const Rule& r) {
  // Result orders by its raw NTSTATUS when compared against a number, e.g.
  // "Result moreThan 0xBFFFFFFF" = error severity (what --failed uses). Name
  // relations ("Result is NAME_NOT_FOUND") stay string compares below.
  uint64_t num = 0;
  if (r.column == Column::Result &&
      (r.relation == Relation::LessThan || r.relation == Relation::MoreThan) &&
      parseNumber(r.value, num))
    return r.relation == Relation::LessThan ? ev.result < num : ev.result > num;

  // Numeric columns compare as integers for ordering / equality.
  if (isNumericColumn(r.column) &&
      (r.relation == Relation::Is || r.relation == Relation::IsNot ||
       r.relation == Relation::LessThan || r.relation == Relation::MoreThan)) {
    uint64_t lhs = numericField(ev, r.column);
    uint64_t rhs = 0;
    if (!parseNumber(r.value, rhs))
      return r.relation == Relation::IsNot;  // a number never "is" a non-number
    switch (r.relation) {
      case Relation::Is: return lhs == rhs;
      case Relation::IsNot: return lhs != rhs;
      case Relation::LessThan: return lhs < rhs;
      case Relation::MoreThan: return lhs > rhs;
      default: return false;
    }
  }

  std::wstring lhs = lower(fieldValue(ev, r.column));
  std::wstring rhs = lower(r.value);
  // Accept Procmon's spellings ("NAME NOT FOUND", "File System") for ours.
  if (r.column == Column::Result) {
    std::replace(rhs.begin(), rhs.end(), L' ', L'_');
  } else if (r.column == Column::EventClass) {
    std::erase(lhs, L' ');
    std::erase(rhs, L' ');
  }
  switch (r.relation) {
    case Relation::Is: return lhs == rhs;
    case Relation::IsNot: return lhs != rhs;
    case Relation::Contains: return lhs.find(rhs) != std::wstring::npos;
    case Relation::Excludes: return lhs.find(rhs) == std::wstring::npos;
    case Relation::BeginsWith: return lhs.rfind(rhs, 0) == 0;
    case Relation::EndsWith:
      return rhs.size() <= lhs.size() &&
             lhs.compare(lhs.size() - rhs.size(), rhs.size(), rhs) == 0;
    case Relation::LessThan: return lhs < rhs;
    case Relation::MoreThan: return lhs > rhs;
    default: return false;
  }
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

bool FilterSet::matches(const Event& ev) const {
  // Any matching Exclude hides the event. PerColumn (Procmon): includes on the
  // SAME column are OR'd, groups on DIFFERENT columns AND'd (e.g. "ProcessName
  // is a.exe" + "Operation is WriteFile" = a.exe's writes).
  // IncludeMode::Any collapses every include into one group (slot 0).
  constexpr size_t kCols = static_cast<size_t>(Column::Integrity) + 1;
  bool hasInclude[kCols] = {};
  bool matchedInclude[kCols] = {};
  for (const auto& r : rules_) {
    const bool m = ruleMatches(ev, r);
    if (r.action == Action::Exclude) {
      if (m) return false;
    } else {
      const size_t c =
          mode_ == IncludeMode::Any ? 0 : static_cast<size_t>(r.column);
      hasInclude[c] = true;
      if (m) matchedInclude[c] = true;
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
