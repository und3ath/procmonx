#pragma once
// Load / save a FilterSet as JSON. Schema:
//   { "filters": [
//       { "column": "Path", "relation": "contains", "value": "steam",
//         "action": "include" },
//       { "column": "ProcessName", "relation": "is", "value": "System",
//         "action": "exclude" }
//   ] }
// "action" defaults to "include" if omitted. Column/relation accept the same
// names/aliases as the CLI parser. Uses a small built-in JSON reader (no deps).

#include <string>
#include <system_error>

#include "pmx/filter.h"

namespace pmx {

// `why`, if non-null, receives a short message on failure (e.g. a malformed-
// rule reason naming its 1-based index, or "malformed JSON").
std::error_code loadFilterJson(const wchar_t* path, FilterSet& out,
                               std::string* why = nullptr);
std::error_code saveFilterJson(const wchar_t* path, const FilterSet& fs);

}  // namespace pmx
