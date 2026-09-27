#include "pmx/filter_json.h"

#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

#include "pmx/file_io.h"

namespace pmx {

namespace {
std::error_code errc(int e) { return {e, std::system_category()}; }

std::wstring utf8ToW(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
  return w;
}

std::string wToUtf8(const std::wstring& s) {
  if (s.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0,
                              nullptr, nullptr);
  std::string o(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), o.data(), n, nullptr,
                      nullptr);
  return o;
}

// --- Minimal JSON scanner (objects/arrays/strings; numbers/bools skipped) ----
struct Json {
  const char* p;
  const char* end;
  bool ok = true;

  void ws() {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
  }
  bool eat(char c) {
    ws();
    if (p < end && *p == c) {
      ++p;
      return true;
    }
    return false;
  }
  // Parse a JSON string (assumes current char is the opening quote after ws()).
  bool str(std::string& out) {
    ws();
    if (p >= end || *p != '"') return false;
    ++p;
    out.clear();
    while (p < end && *p != '"') {
      char c = *p++;
      if (c == '\\' && p < end) {
        char e = *p++;
        switch (e) {
          case 'n': out.push_back('\n'); break;
          case 't': out.push_back('\t'); break;
          case 'r': out.push_back('\r'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case '/': out.push_back('/'); break;
          case '\\': out.push_back('\\'); break;
          case '"': out.push_back('"'); break;
          case 'u': {
            if (end - p >= 4) {
              int v = 0;
              for (int i = 0; i < 4; ++i) {
                char h = p[i];
                v <<= 4;
                if (h >= '0' && h <= '9') v |= h - '0';
                else if (h >= 'a' && h <= 'f') v |= h - 'a' + 10;
                else if (h >= 'A' && h <= 'F') v |= h - 'A' + 10;
              }
              p += 4;
              // Encode BMP code point as UTF-8 (surrogates unhandled — rare here).
              wchar_t wc = static_cast<wchar_t>(v);
              out += wToUtf8(std::wstring(1, wc));
            }
            break;
          }
          // Unknown escape (e.g. \U, \P in a Windows path): keep the backslash
          // literally rather than dropping it, so "\Users\Public" survives.
          default:
            out.push_back('\\');
            out.push_back(e);
            break;
        }
      } else {
        out.push_back(c);
      }
    }
    if (p >= end) return false;
    ++p;  // closing quote
    return true;
  }
  // Read a bare primitive (number / true / false / null) as its literal text,
  // so e.g. {"value": 1234} works for numeric columns. False on '{'/'['/'"'.
  bool primitive(std::string& out) {
    ws();
    if (p >= end || *p == '{' || *p == '[' || *p == '"') return false;
    const char* s = p;
    while (p < end && *p != ',' && *p != '}' && *p != ']' && *p != ' ' &&
           *p != '\t' && *p != '\r' && *p != '\n')
      ++p;
    out.assign(s, p);
    return !out.empty();
  }
  // Skip any value (object/array/string/primitive) — used to ignore unknown keys.
  void skipValue() {
    ws();
    if (p >= end) return;
    if (*p == '"') {
      std::string t;
      str(t);
    } else if (*p == '{' || *p == '[') {
      char open = *p, close = (open == '{') ? '}' : ']';
      ++p;
      int depth = 1;
      while (p < end && depth) {
        ws();
        if (p >= end) break;
        if (*p == '"') {
          std::string t;
          str(t);
          continue;
        }
        if (*p == open) ++depth;
        else if (*p == close) --depth;
        ++p;
      }
    } else {
      while (p < end && *p != ',' && *p != '}' && *p != ']') ++p;
    }
  }
};
}  // namespace

std::error_code loadFilterJson(const wchar_t* path, FilterSet& out) {
  std::string buf;
  if (std::error_code ec = readWholeFile(path, buf)) return ec;
  // Tolerate a UTF-8 BOM (Notepad / PowerShell 5 `-Encoding UTF8` write one).
  size_t start = 0;
  if (buf.size() >= 3 && (uint8_t)buf[0] == 0xEF && (uint8_t)buf[1] == 0xBB &&
      (uint8_t)buf[2] == 0xBF)
    start = 3;

  Json j{buf.data() + start, buf.data() + buf.size()};
  if (!j.eat('{')) return errc(ERROR_INVALID_DATA);
  bool foundFilters = false;
  while (true) {
    std::string key;
    if (!j.str(key)) break;
    if (!j.eat(':')) return errc(ERROR_INVALID_DATA);
    if (key == "match") {
      // Include combination mode for this file's lens: "procmon" (default:
      // same column OR'd, columns AND'd) or "any" (all includes OR'd).
      std::string v;
      if (!j.str(v)) return errc(ERROR_INVALID_DATA);
      auto m = parseIncludeMode(utf8ToW(v));
      if (!m) return errc(ERROR_INVALID_DATA);
      out.setIncludeMode(*m);
    } else if (key == "filters") {
      foundFilters = true;
      if (!j.eat('[')) return errc(ERROR_INVALID_DATA);
      if (!j.eat(']')) {  // non-empty array
        do {
          if (!j.eat('{')) return errc(ERROR_INVALID_DATA);
          std::string col, rel, val, act = "include";
          while (true) {
            std::string k;
            if (!j.str(k)) break;
            if (!j.eat(':')) return errc(ERROR_INVALID_DATA);
            std::string v;
            if (!j.str(v) && !j.primitive(v)) {
              j.skipValue();
            } else if (k == "column") {
              col = v;
            } else if (k == "relation") {
              rel = v;
            } else if (k == "value") {
              val = v;
            } else if (k == "action") {
              act = v;
            }
            if (!j.eat(',')) break;
          }
          if (!j.eat('}')) return errc(ERROR_INVALID_DATA);
          auto c = parseColumn(utf8ToW(col));
          auto r = parseRelation(utf8ToW(rel));
          if (c && r) {
            Action a = (act == "exclude" || act == "Exclude") ? Action::Exclude
                                                              : Action::Include;
            out.add(Rule{*c, *r, utf8ToW(val), a});
          }
        } while (j.eat(','));
        if (!j.eat(']')) return errc(ERROR_INVALID_DATA);
      }
    } else {
      j.skipValue();
    }
    if (!j.eat(',')) break;
  }
  if (!foundFilters) return errc(ERROR_INVALID_DATA);
  return {};
}

std::error_code saveFilterJson(const wchar_t* path, const FilterSet& fs) {
  std::string out = "{\n";
  if (fs.includeMode() != IncludeMode::PerColumn) {
    out += "  \"match\": \"";
    out += includeModeName(fs.includeMode());
    out += "\",\n";
  }
  out += "  \"filters\": [\n";
  const auto& rules = fs.rules();
  for (size_t i = 0; i < rules.size(); ++i) {
    const auto& r = rules[i];
    out += "    { \"column\": \"";
    out += columnName(r.column);
    out += "\", \"relation\": \"";
    out += relationName(r.relation);
    out += "\", \"value\": \"";
    // Escape backslashes and quotes in the value.
    for (char c : wToUtf8(r.value)) {
      if (c == '\\' || c == '"') out.push_back('\\');
      out.push_back(c);
    }
    out += "\", \"action\": \"";
    out += (r.action == Action::Exclude) ? "exclude" : "include";
    out += "\" }";
    out += (i + 1 < rules.size()) ? ",\n" : "\n";
  }
  out += "  ]\n}\n";
  return writeWholeFile(path, out.data(), out.size());
}

}  // namespace pmx
