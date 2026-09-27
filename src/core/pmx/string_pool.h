#pragma once
#include <cstdint>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "pmx/append_log.h"

namespace pmx {

// Interned UTF-16 strings. Id 0 is always the empty string.
//
// intern() is writer-only; get() is safe from any thread for ids the reader
// obtained from a published Event (or any id < size()).
class StringPool {
 public:
  StringPool();
  StringPool(const StringPool&) = delete;
  StringPool& operator=(const StringPool&) = delete;

  uint32_t intern(std::wstring_view s);
  std::wstring_view get(uint32_t id) const noexcept {
    const Ref& r = refs_[id];
    return {r.ptr, r.len};
  }
  size_t size() const noexcept { return refs_.size(); }
  size_t bytes() const noexcept { return bytes_; }

 private:
  struct Ref {
    const wchar_t* ptr;
    uint32_t len;
  };
  static constexpr size_t kBlockChars = 1u << 20;

  const wchar_t* store(std::wstring_view s);

  AppendLog<Ref, 16, 1u << 12> refs_;
  std::vector<std::unique_ptr<wchar_t[]>> blocks_;  // writer-only
  wchar_t* cur_ = nullptr;
  size_t left_ = 0;
  size_t bytes_ = 0;
  std::unordered_map<std::wstring_view, uint32_t> index_;  // writer-only
};

}  // namespace pmx
