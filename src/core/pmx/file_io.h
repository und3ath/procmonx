#pragma once
// Whole-file read/write helpers. WriteFile/ReadFile take a DWORD length, so
// large buffers are transferred in chunks and the byte counts are checked (a
// single (DWORD)size() call silently truncates >4 GB and ignores short I/O).

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

namespace pmx {

inline std::error_code writeWholeFile(const wchar_t* path, const void* data,
                                      size_t n) {
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return {static_cast<int>(GetLastError()), std::system_category()};
  std::error_code ec;
  const auto* p = static_cast<const uint8_t*>(data);
  while (n) {
    const DWORD chunk = n > 0x40000000u ? 0x40000000u : static_cast<DWORD>(n);
    DWORD wrote = 0;
    if (!WriteFile(h, p, chunk, &wrote, nullptr)) {
      ec = {static_cast<int>(GetLastError()), std::system_category()};
      break;
    }
    if (wrote == 0) {
      ec = {ERROR_WRITE_FAULT, std::system_category()};
      break;
    }
    p += wrote;
    n -= wrote;
  }
  CloseHandle(h);
  return ec;
}

// Read a whole file into `out` (bytes). Returns an error on open/read failure.
inline std::error_code readWholeFile(const wchar_t* path, std::string& out) {
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return {static_cast<int>(GetLastError()), std::system_category()};
  LARGE_INTEGER sz{};
  std::error_code ec;
  if (!GetFileSizeEx(h, &sz)) {
    ec = {static_cast<int>(GetLastError()), std::system_category()};
    CloseHandle(h);
    return ec;
  }
  out.assign(static_cast<size_t>(sz.QuadPart), '\0');
  size_t got = 0;
  while (got < out.size()) {
    const size_t left = out.size() - got;
    const DWORD chunk = left > 0x40000000u ? 0x40000000u : static_cast<DWORD>(left);
    DWORD rd = 0;
    if (!ReadFile(h, out.data() + got, chunk, &rd, nullptr)) {
      ec = {static_cast<int>(GetLastError()), std::system_category()};
      break;
    }
    if (rd == 0) break;  // file shrank underneath us
    got += rd;
  }
  CloseHandle(h);
  out.resize(got);
  return ec;
}

// Buffered sequential writer: batches writes into a 1 MB buffer so a caller
// streaming many small records (a PMX record, a CSV row, a PML event) doesn't
// pay a WriteFile syscall per record. `patch` lets a writer that only learns a
// header value (a count, an offset) after the fact go back and fix it up
// without re-buffering everything already flushed. First error is sticky:
// once set, every later call is a no-op that returns it.
class BufferedFile {
 public:
  BufferedFile() = default;
  BufferedFile(const BufferedFile&) = delete;
  BufferedFile& operator=(const BufferedFile&) = delete;
  ~BufferedFile() { close(); }

  std::error_code open(const wchar_t* path) {
    h_ = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h_ == INVALID_HANDLE_VALUE) {
      err_ = {static_cast<int>(GetLastError()), std::system_category()};
      return err_;
    }
    buf_.reserve(kBufCap);
    pos_ = 0;
    return {};
  }

  std::error_code write(const void* data, size_t n) {
    if (err_) return err_;
    const auto* p = static_cast<const uint8_t*>(data);
    while (n) {
      const size_t room = kBufCap - buf_.size();
      const size_t take = n < room ? n : room;
      buf_.insert(buf_.end(), p, p + take);
      p += take;
      n -= take;
      pos_ += take;
      if (buf_.size() == kBufCap) {
        if (std::error_code ec = flush()) return ec;
      }
    }
    return {};
  }

  uint64_t tell() const { return pos_; }

  // Overwrite `n` bytes at absolute offset `off` (already-flushed region) and
  // leave the file position at end-of-stream for subsequent write() calls.
  std::error_code patch(uint64_t off, const void* data, size_t n) {
    if (err_) return err_;
    if (std::error_code ec = flush()) return ec;
    if (std::error_code ec = seek(off)) return ec;
    if (std::error_code ec = rawWrite(data, n)) return ec;
    return seek(pos_);
  }

  std::error_code close() {
    if (h_ == INVALID_HANDLE_VALUE) return err_;
    std::error_code fe = flush();
    CloseHandle(h_);
    h_ = INVALID_HANDLE_VALUE;
    return err_ ? err_ : fe;
  }

 private:
  static constexpr size_t kBufCap = size_t{1} << 20;  // 1 MB

  std::error_code seek(uint64_t off) {
    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(off);
    if (!SetFilePointerEx(h_, li, nullptr, FILE_BEGIN)) {
      err_ = {static_cast<int>(GetLastError()), std::system_category()};
      return err_;
    }
    return {};
  }

  std::error_code rawWrite(const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    size_t done = 0;
    while (done < n) {
      const DWORD chunk = static_cast<DWORD>(
          std::min<size_t>(n - done, 0x40000000u));
      DWORD wrote = 0;
      if (!WriteFile(h_, p + done, chunk, &wrote, nullptr)) {
        err_ = {static_cast<int>(GetLastError()), std::system_category()};
        return err_;
      }
      if (wrote == 0) {
        err_ = {ERROR_WRITE_FAULT, std::system_category()};
        return err_;
      }
      done += wrote;
    }
    return {};
  }

  std::error_code flush() {
    if (buf_.empty()) return {};
    std::error_code ec = rawWrite(buf_.data(), buf_.size());
    buf_.clear();
    return ec;
  }

  HANDLE h_ = INVALID_HANDLE_VALUE;
  std::vector<uint8_t> buf_;
  uint64_t pos_ = 0;
  std::error_code err_;
};

}  // namespace pmx
