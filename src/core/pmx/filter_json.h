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

#include <system_error>

#include "pmx/filter.h"

namespace pmx {

std::error_code loadFilterJson(const wchar_t* path, FilterSet& out);
std::error_code saveFilterJson(const wchar_t* path, const FilterSet& fs);

}  // namespace pmx
