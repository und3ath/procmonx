#pragma once
#include <cstdio>
#include <string>

namespace pmx {

// UTF-8 text safe to print: C0/DEL/C1 control characters (ESC sequences etc.)
// become visible "\xNN" escapes. Captured paths/command lines are chosen by
// the monitored processes and must not drive the analyst's terminal.
inline std::string printable(std::string s) {
  auto ctlLen = [&](size_t i) -> size_t {
    const auto c = static_cast<unsigned char>(s[i]);
    if (c < 0x20 || c == 0x7F) return 1;
    // C1 controls U+0080..U+009F are C2 80..C2 9F in UTF-8 (0x9B = CSI).
    if (c == 0xC2 && i + 1 < s.size()) {
      const auto d = static_cast<unsigned char>(s[i + 1]);
      if (d >= 0x80 && d <= 0x9F) return 2;
    }
    return 0;
  };
  size_t i = 0;
  while (i < s.size() && !ctlLen(i)) ++i;
  if (i == s.size()) return s;
  std::string out(s, 0, i);
  while (i < s.size()) {
    const size_t len = ctlLen(i);
    if (!len) {
      out.push_back(s[i++]);
      continue;
    }
    char b[8];
    std::snprintf(b, sizeof b, "\\x%02X",
                  static_cast<unsigned char>(s[i + len - 1]));
    out += b;
    i += len;
  }
  return out;
}

}  // namespace pmx
