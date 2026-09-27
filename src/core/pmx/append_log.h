#pragma once
#include <atomic>
#include <cstddef>
#include <memory>
#include <new>
#include <stdexcept>
#include <utility>

namespace pmx {

// Single-writer / multi-reader append-only sequence.
//
// Elements live in fixed-size chunks that never move, so a reference obtained
// by a reader stays valid for the lifetime of the log. The writer constructs an
// element, then publishes it with a release store of the size; readers acquire
// the size and may then read any index below it without locking.
template <class T, unsigned ChunkBits = 16, size_t MaxChunks = 1u << 14>
class AppendLog {
 public:
  static constexpr size_t kChunkSize = size_t{1} << ChunkBits;
  static constexpr size_t kMask = kChunkSize - 1;
  static constexpr size_t kCapacity = kChunkSize * MaxChunks;

  AppendLog() : dir_(std::make_unique<std::atomic<T*>[]>(MaxChunks)) {}
  AppendLog(const AppendLog&) = delete;
  AppendLog& operator=(const AppendLog&) = delete;

  ~AppendLog() {
    const size_t n = size_.load(std::memory_order_relaxed);
    for (size_t i = 0; i < n; ++i) slot(i)->~T();
    for (size_t c = 0; c < MaxChunks; ++c) {
      if (T* p = dir_[c].load(std::memory_order_relaxed))
        ::operator delete(p, std::align_val_t{alignof(T)});
    }
  }

  // Reader side.
  size_t size() const noexcept { return size_.load(std::memory_order_acquire); }
  const T& operator[](size_t i) const noexcept { return *slot(i); }

  // Writer side. Not thread-safe with respect to other writers.
  template <class... Args>
  size_t emplace_back(Args&&... args) {
    const size_t n = size_.load(std::memory_order_relaxed);
    const size_t c = n >> ChunkBits;
    if (c >= MaxChunks) throw std::length_error("AppendLog full");
    T* chunk = dir_[c].load(std::memory_order_relaxed);
    if (!chunk) {
      chunk = static_cast<T*>(
          ::operator new(sizeof(T) * kChunkSize, std::align_val_t{alignof(T)}));
      dir_[c].store(chunk, std::memory_order_relaxed);  // published by size_ below
    }
    new (chunk + (n & kMask)) T(std::forward<Args>(args)...);
    size_.store(n + 1, std::memory_order_release);
    return n;
  }

  // Writer-only mutable access, for fields documented as writer-owned.
  T& mut(size_t i) noexcept { return *slot(i); }

 private:
  T* slot(size_t i) const noexcept {
    return dir_[i >> ChunkBits].load(std::memory_order_relaxed) + (i & kMask);
  }

  std::unique_ptr<std::atomic<T*>[]> dir_;
  std::atomic<size_t> size_{0};
};

}  // namespace pmx
