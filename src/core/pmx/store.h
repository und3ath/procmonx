#pragma once
// In-memory event store + native persistence.
//
// The store is just an ordered list of decoded Events. It is written to / read
// from a compact native container ("PMX1") so a capture can be saved and later
// reloaded for offline filtering. Process Monitor .pml interop lives in a
// separate writer/reader (pml.cpp / pml_read.cpp).

#include <cstdint>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "pmx/event.h"
#include "pmx/file_io.h"

namespace pmx {

// Save events to a native .pmxlog file. Overwrites.
std::error_code saveEvents(const wchar_t* path, std::span<const Event> events);

// Load events from a native .pmxlog file (appends to `out`).
std::error_code loadEvents(const wchar_t* path, std::vector<Event>& out);

// Streaming .pmxlog reader backing loadEvents: memory-maps the file and
// decodes one event per next() call, so a caller with more events than fit
// comfortably in RAM (a reopened `live` capture) doesn't need a second
// in-memory copy of the whole file. open() validates magic/version exactly
// as loadEvents does. next() returns false at end of file or on a malformed
// record (then error() is ERROR_INVALID_DATA); a header count of 0 with
// record bytes still following (a writer that died before patching the
// count) is recovered by reading until the data runs out instead of
// stopping immediately.
class PmxlogReader {
 public:
  std::error_code open(const wchar_t* path);
  bool next(Event& e);
  std::error_code error() const { return err_; }
  uint32_t declaredCount() const { return declaredCount_; }

 private:
  MappedFile file_;
  uint32_t version_ = 0;
  uint32_t declaredCount_ = 0;
  uint32_t recordsRead_ = 0;
  const char* p_ = nullptr;
  const char* end_ = nullptr;
  std::error_code err_;
};

// Export events to a CSV file (Excel/grep friendly): Time, Process Name, PID,
// Operation, Path, Result, Detail, Duration.
std::error_code saveEventsCsv(const wchar_t* path, std::span<const Event> events);

// One event as a single-line JSON object (no trailing newline), UTF-8:
// {"time":"2026-09-27T10:39:19.3350293Z","ts":<FILETIME>,"class":"FileSystem",
//  "op":..,"process":..,"pid":..,"tid":..,"ppid":..,"user":..,"integrity":..,
//  "path":..,"result":"NAME_NOT_FOUND","status":"0xC0000034","detail":..,
//  "duration":<seconds>, "image":.., "cmdline":..}
std::string eventToJson(const Event& e);

// Export events as JSON Lines (one eventToJson object per line).
std::error_code saveEventsJson(const wchar_t* path, std::span<const Event> events);

// --- Per-event record encode/decode, shared by the .pmxlog reader/writer and
// the spool's spill files (spool.cpp). Exactly the current (kEventRecordVersion)
// on-disk record: the bytes appendEventRecord emits are what readEventRecord at
// that version reads back. `readEventRecord` advances `p` past the record and
// returns false (without invalidating `e`'s already-set fields) on truncation.
constexpr uint32_t kEventRecordVersion = 7;
void appendEventRecord(std::string& out, const Event& e);
bool readEventRecord(const char*& p, const char* end, uint32_t version, Event& e);

// --- Streaming writers: same open/write/close/count() shape, so a caller with
// more events than fit comfortably in RAM (see EventSpool) can drain them
// straight to disk instead of building a second in-memory copy of the file.
class PmxlogWriter {
 public:
  std::error_code open(const wchar_t* path);
  std::error_code write(const Event& e);
  std::error_code close();
  uint64_t count() const { return count_; }

 private:
  BufferedFile file_;
  uint64_t count_ = 0;
};

class CsvWriter {
 public:
  std::error_code open(const wchar_t* path);
  std::error_code write(const Event& e);
  std::error_code close();
  uint64_t count() const { return count_; }

 private:
  BufferedFile file_;
  uint64_t count_ = 0;
};

class JsonWriter {
 public:
  std::error_code open(const wchar_t* path);
  std::error_code write(const Event& e);
  std::error_code close();
  uint64_t count() const { return count_; }

 private:
  BufferedFile file_;
  uint64_t count_ = 0;
};

}  // namespace pmx
