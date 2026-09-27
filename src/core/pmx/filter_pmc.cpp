#include "pmx/filter_pmc.h"

#include <windows.h>

#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace pmx {

namespace {
std::error_code errc(int e) { return {e, std::system_category()}; }

// Procmon column code (0x9cXX) -> our Column. Verified against a real export;
// codes we can't confidently map are skipped by the caller.
std::optional<Column> mapColumn(uint32_t c) {
  switch (c) {
    case 0x9c75: return Column::ProcessName;
    case 0x9c76: return Column::Pid;         // default-order inference
    case 0x9c77: return Column::Operation;
    case 0x9c87: return Column::Path;
    case 0x9c92: return Column::EventClass;  // Procmon "Category"
    default: return std::nullopt;
  }
}

std::optional<Relation> mapRelation(uint32_t r) {
  switch (r) {
    case 0: return Relation::Is;
    case 1: return Relation::IsNot;
    case 2: return Relation::LessThan;
    case 3: return Relation::MoreThan;
    case 4: return Relation::BeginsWith;
    case 5: return Relation::EndsWith;
    case 6: return Relation::Contains;
    case 7: return Relation::Excludes;
    default: return std::nullopt;
  }
}
}  // namespace

bool parseFilterBlob(const uint8_t* d, size_t n, FilterSet& out) {
  if (n < 5) return false;
  size_t p = 0;
  /* version */ ++p;
  uint32_t count;
  std::memcpy(&count, d + p, 4);
  p += 4;

  for (uint32_t i = 0; i < count; ++i) {
    if (p + 13 > n) break;  // col+rel+action+len
    uint32_t col, rel, vlen;
    std::memcpy(&col, d + p, 4);
    std::memcpy(&rel, d + p + 4, 4);
    uint8_t action = d[p + 8];
    std::memcpy(&vlen, d + p + 9, 4);
    p += 13;
    if (p + vlen > n) break;

    std::wstring value(reinterpret_cast<const wchar_t*>(d + p), vlen / 2);
    while (!value.empty() && value.back() == L'\0') value.pop_back();
    p += vlen;
    p += 8;  // per-rule trailing reserved

    auto column = mapColumn(col);
    auto relation = mapRelation(rel);
    if (column && relation)
      out.add(Rule{*column, *relation, value,
                   action ? Action::Include : Action::Exclude});
  }
  return true;
}

std::error_code loadFilterReg(const wchar_t* path, FilterSet& out) {
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return errc((int)GetLastError());
  LARGE_INTEGER sz{};
  GetFileSizeEx(h, &sz);
  std::wstring text(static_cast<size_t>(sz.QuadPart) / 2, L'\0');
  DWORD got = 0;
  BOOL ok = ReadFile(h, text.data(), (DWORD)(text.size() * 2), &got, nullptr);
  CloseHandle(h);
  if (!ok) return errc((int)GetLastError());
  text.resize(got / 2);
  if (!text.empty() && text[0] == 0xFEFF) text.erase(0, 1);  // BOM

  size_t k = text.find(L"\"FilterRules\"=hex:");
  if (k == std::wstring::npos) return errc(ERROR_NOT_FOUND);
  k += wcslen(L"\"FilterRules\"=hex:");

  // Collect hex byte tokens ("xx,") until a non-hex/non-separator char.
  std::vector<uint8_t> blob;
  int hi = -1;
  for (size_t i = k; i < text.size(); ++i) {
    wchar_t ch = text[i];
    int v;
    if (ch >= L'0' && ch <= L'9') v = ch - L'0';
    else if (ch >= L'a' && ch <= L'f') v = ch - L'a' + 10;
    else if (ch >= L'A' && ch <= L'F') v = ch - L'A' + 10;
    else if (ch == L',' || ch == L' ' || ch == L'\t' || ch == L'\r' ||
             ch == L'\n' || ch == L'\\')
      continue;  // separators / line continuation
    else
      break;  // end of the value (next key or ])
    if (hi < 0) {
      hi = v;
    } else {
      blob.push_back(static_cast<uint8_t>((hi << 4) | v));
      hi = -1;
    }
  }
  if (blob.empty()) return errc(ERROR_INVALID_DATA);
  parseFilterBlob(blob.data(), blob.size(), out);
  return {};
}

}  // namespace pmx
