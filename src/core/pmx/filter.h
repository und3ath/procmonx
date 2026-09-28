#pragma once
// Procmon-style event filtering.
//
// A FilterSet is an ordered list of rules; each rule is {column, relation,
// value, action(Include|Exclude)}. Evaluation matches Procmon:
//   * if the event matches any Exclude rule  -> hidden;
//   * else, for every column that has Include rules, the event must match at
//     least one of that column's includes (same column OR'd, columns AND'd);
//     IncludeMode::Any instead ORs every include regardless of column;
//   * else shown.
// An empty set shows everything.
//
// Rules come from CLI strings ("Path contains steam", "-x Operation is CloseFile")
// or a JSON config; both parse into the same Rule.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "pmx/event.h"

namespace pmx {

enum class Column {
  ProcessName,
  Pid,
  ParentPid,
  Operation,
  Path,
  Result,
  Detail,
  EventClass,
  ImagePath,
  CommandLine,
  Sequence,
  User,
  Integrity,  // keep last: FilterSet::matches sizes per-column state by it
};

enum class Relation {
  Is,
  IsNot,
  Contains,
  Excludes,
  BeginsWith,
  EndsWith,
  LessThan,
  MoreThan,
};

enum class Action { Include, Exclude };

// How a FilterSet combines its Include rules (Exclude rules always veto).
//   PerColumn (default, Procmon): includes on the same column are OR'd, the
//             per-column groups are AND'd.
//   Any:      the event must match any one include (all includes OR'd).
enum class IncludeMode { PerColumn, Any };

// How a FilterGroup combines its member sets (lenses).
//   Any (default): shown if ANY lens shows it (independent lenses, OR'd).
//   All:           shown only if EVERY lens shows it.
enum class GroupMode { Any, All };

std::optional<IncludeMode> parseIncludeMode(const std::wstring& s);
std::optional<GroupMode> parseGroupMode(const std::wstring& s);
const char* includeModeName(IncludeMode m) noexcept;
const char* groupModeName(GroupMode m) noexcept;

struct Rule {
  Column column;
  Relation relation;
  std::wstring value;
  Action action = Action::Include;
};

// Parse a column / relation token (case-insensitive, with common aliases).
std::optional<Column> parseColumn(const std::wstring& s);
std::optional<Relation> parseRelation(const std::wstring& s);
const char* columnName(Column c) noexcept;
const char* relationName(Relation r) noexcept;

// Parse "<column> <relation> <value...>" into a Rule (value is the remainder,
// may contain spaces). Returns nullopt on a malformed column/relation.
std::optional<Rule> parseRule(const std::wstring& text, Action action);

// Render a rule back to "<column> <relation> <value>" (for saving / display).
std::wstring ruleToString(const Rule& r);

namespace detail {
// Precompiled form of a Rule: value lowercased and column-normalized once (at
// add() time) plus a pre-parsed number, so matching never re-lowercases or
// re-parses per event. See filter.cpp for the matcher that consumes this.
struct CompiledRule {
  Column column;
  Relation relation;
  Action action;
  std::wstring normValue;         // lower(value), Result ' '->'_', EventClass spaces stripped
  bool valueIsNumber = false;     // parseNumber(value) succeeded
  uint64_t numberValue = 0;
  bool resultNumericOrdering = false;  // Result Less/More vs a raw NTSTATUS number
};
}  // namespace detail

class FilterSet {
 public:
  void add(Rule r);
  bool empty() const noexcept { return rules_.empty(); }
  const std::vector<Rule>& rules() const noexcept { return rules_; }
  IncludeMode includeMode() const noexcept { return mode_; }
  void setIncludeMode(IncludeMode m) noexcept { mode_ = m; }

  // True if the event should be shown.
  bool matches(const Event& ev) const;

 private:
  std::vector<Rule> rules_;
  std::vector<detail::CompiledRule> compiled_;
  IncludeMode mode_ = IncludeMode::PerColumn;
};

// A collection of independent FilterSets ("lenses"), one per filter file. Each
// lens keeps its own self-contained include/exclude logic, so one file's
// Exclude rules never suppress another file's Include matches. Lenses are
// combined per GroupMode (default Any = OR'd).
class FilterGroup {
 public:
  void addSet(FilterSet s) { sets_.push_back(std::move(s)); }
  bool empty() const noexcept { return sets_.empty(); }
  size_t size() const noexcept { return sets_.size(); }
  const std::vector<FilterSet>& sets() const noexcept { return sets_; }
  GroupMode mode() const noexcept { return mode_; }
  void setMode(GroupMode m) noexcept { mode_ = m; }

  // True if the event should be shown (empty group shows everything).
  bool matches(const Event& ev) const {
    if (sets_.empty()) return true;
    if (mode_ == GroupMode::All) {
      for (const auto& s : sets_)
        if (!s.matches(ev)) return false;
      return true;
    }
    for (const auto& s : sets_)
      if (s.matches(ev)) return true;
    return false;
  }

 private:
  std::vector<FilterSet> sets_;
  GroupMode mode_ = GroupMode::Any;
};

// Human-readable NTSTATUS name for common codes (for the Result column and
// display). Falls back to "0xXXXXXXXX".
std::string statusName(uint32_t status);

}  // namespace pmx
