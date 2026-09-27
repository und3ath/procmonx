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

namespace pmx {

// Save events to a native .pmxlog file. Overwrites.
std::error_code saveEvents(const wchar_t* path, std::span<const Event> events);

// Load events from a native .pmxlog file (appends to `out`).
std::error_code loadEvents(const wchar_t* path, std::vector<Event>& out);

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

}  // namespace pmx
