#include "pmx/string_pool.h"

#include <algorithm>
#include <cstring>

namespace pmx {

StringPool::StringPool() {
  refs_.emplace_back(Ref{L"", 0});
  index_.emplace(std::wstring_view{}, 0);
}

const wchar_t* StringPool::store(std::wstring_view s) {
  const size_t need = s.size() + 1;
  if (need > left_) {
    const size_t n = std::max(need, kBlockChars);
    blocks_.push_back(std::make_unique<wchar_t[]>(n));
    cur_ = blocks_.back().get();
    left_ = n;
    bytes_ += n * sizeof(wchar_t);
  }
  wchar_t* p = cur_;
  std::memcpy(p, s.data(), s.size() * sizeof(wchar_t));
  p[s.size()] = L'\0';
  cur_ += need;
  left_ -= need;
  return p;
}

uint32_t StringPool::intern(std::wstring_view s) {
  if (auto it = index_.find(s); it != index_.end()) return it->second;
  const wchar_t* p = store(s);
  const auto id = static_cast<uint32_t>(refs_.emplace_back(Ref{p, static_cast<uint32_t>(s.size())}));
  index_.emplace(std::wstring_view{p, s.size()}, id);
  return id;
}

}  // namespace pmx
