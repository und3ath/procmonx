#pragma once
// Whole-file read/write helpers. WriteFile/ReadFile take a DWORD length, so
// large buffers are transferred in chunks and the byte counts are checked (a
// single (DWORD)size() call silently truncates >4 GB and ignores short I/O).

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <system_error>

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

}  // namespace pmx
