#pragma once
// Import Procmon filter rules.
//
// Process Monitor stores its filter as a "FilterRules" binary blob (in the
// registry and inside a .pmc config). Layout:
//   u8  version (1)
//   u32 rule_count
//   rule_count x {
//     u32 column      (Procmon column code, 0x9cXX)
//     u32 relation    (0 is,1 isNot,2 lessThan,3 moreThan,4 beginsWith,
//                      5 endsWith,6 contains,7 excludes)
//     u8  action      (0 exclude, 1 include)
//     u32 value_bytes (UTF-16, including the terminating null)
//     wchar value[value_bytes/2]
//     u8  reserved[8]
//   }
//
// parseFilterBlob decodes that blob; loadFilterReg pulls the "FilterRules" value
// out of a `reg export` .reg text file and parses it. Rules on columns we don't
// model are skipped and reported.

#include <cstddef>
#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

#include "pmx/filter.h"

namespace pmx {

// Parse a raw FilterRules blob. Returns false if the header is malformed. Each
// rule that can't be imported (unknown column/relation code) is described in
// `skipped`, if given.
bool parseFilterBlob(const uint8_t* data, size_t n, FilterSet& out,
                     std::vector<std::string>* skipped = nullptr);

// Load filter rules from a `reg export` .reg file (finds the FilterRules value).
std::error_code loadFilterReg(const wchar_t* path, FilterSet& out,
                              std::vector<std::string>* skipped = nullptr);

}  // namespace pmx
