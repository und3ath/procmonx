#pragma once
#include <cstdint>
#include <memory>
#include <system_error>
#include <vector>
#include "pmx/event.h"
namespace pmx {
// Write events to a Process Monitor .pml file (format version 9, x64). The
// output satisfies Procmon's own loader checks (see tools/check_pml.py).
std::error_code savePml(const wchar_t* path, const std::vector<Event>& events);

// Streaming .pml writer backing savePml: same on-disk format, but events are
// fed one at a time (in chronological order - the caller sorts) instead of
// held in a second in-memory copy of the file. Non-pmlWritable events are
// silently skipped, so count() may be less than the number of write() calls.
class PmlWriter {
 public:
  PmlWriter();
  ~PmlWriter();
  PmlWriter(const PmlWriter&) = delete;
  PmlWriter& operator=(const PmlWriter&) = delete;

  std::error_code open(const wchar_t* path);
  std::error_code write(const Event& e);
  std::error_code close();
  uint64_t count() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Read a Process Monitor .pml file (x64 logs, format v4..v9) - one written by
// Procmon itself or by savePml - appending decoded events to `out`. PML event
// detail is the raw driver detail layout, so events decode through the same
// decodeEvent path as a live capture; network events use the PML network
// record (+ the file's resolved host/port names, as Procmon displays them).
// Returns ERROR_NOT_SUPPORTED for 32-bit logs, ERROR_INVALID_DATA if the file
// is malformed.
std::error_code loadPml(const wchar_t* path, std::vector<Event>& out);

// Streaming .pml reader backing loadPml: open() memory-maps the file and does
// the header/strings/process-table/hosts-ports parsing once; next() then
// decodes one event at a time (skipping class-0 completion records) without
// holding the whole file or the decoded event list in memory. Same error
// codes as loadPml; next() returns false at end of file or on a malformed
// record (then error() is set).
class PmlReader {
 public:
  PmlReader();
  ~PmlReader();
  PmlReader(const PmlReader&) = delete;
  PmlReader& operator=(const PmlReader&) = delete;

  std::error_code open(const wchar_t* path);
  bool next(Event& e);
  std::error_code error() const;
  uint32_t declaredCount() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
