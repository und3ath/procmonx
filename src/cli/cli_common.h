#pragma once
// Shared CLI infrastructure: console/file output, UTF-8 conversion, error
// reporting, and the filter-argument plumbing used by the live / open / summary
// commands.

#include <atomic>
#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

#include "pmx/event.h"
#include "pmx/filter.h"
#include "pmx/spool.h"

namespace pmx::cli {

// ---- Output -----------------------------------------------------------------
// By default output goes to the console; --out FILE also mirrors it to a file
// (tee), and --silent suppresses the console (file only). With --json - the
// console stream carries JSON Lines only, so status lines go to stderr instead.
extern std::FILE* g_outFile;   // --out target, or null
extern bool g_silent;          // --silent: no console
extern bool g_jsonStdout;      // --json -: stdout is JSON Lines
extern bool g_noPause;         // --no-pause: elevated window closes on exit
// A second Ctrl-C while a live/net capture is draining its spool to the output
// files: stop early instead of waiting for the rest to write out. The files
// stay valid (just short); only meaningful while g_writing is true, so
// finalizeSpool clears it right before setting g_writing. Set by main.cpp's
// ctrlHandler.
extern std::atomic<bool> g_abortWrite;
// True only while finalizeSpool is draining the spool into the output files;
// gates whether a Ctrl-C should set g_abortWrite. Set/cleared by finalizeSpool.
extern std::atomic<bool> g_writing;
// GetTickCount64() deadline set when the console is closing (Windows kills the
// process ~5 s later); the write stops early past it so files still get closed.
// 0 = none.
extern std::atomic<uint64_t> g_closeDeadline;

void writeOut(const char* s, size_t n);
void outf(const char* fmt, ...);        // console/file stream
void errf(const char* fmt, ...);        // stderr (never silenced, not tee'd)
void statusf(const char* fmt, ...);     // outf, or stderr under --json -
void writeJsonRow(const pmx::Event& ev);
void printError(const char* what, std::error_code ec);
// Same, with a why message appended as ": <why>" when non-empty.
void printError(const char* what, std::error_code ec, const std::string& why);

// Convert `len` wchars (or -1 for a NUL-terminated string) to UTF-8. A -1 length
// drops the terminating NUL from the result.
std::string toUtf8(const wchar_t* s, int len);

// ---- Filter arguments -------------------------------------------------------
// Filter options shared by live / open / summary:
//   --filter-file F (repeatable) and --filter-dir D: every config file becomes
//     its own independent lens in one FilterGroup; lenses combine per --groups
//     (any = OR, default; all = AND).
//   -f/-x RULE: CLI rules form one extra FilterSet, applied alongside (AND) the
//     lens group. --match procmon|any sets how that set combines includes.
//   --pid / --proc / --failed: shortcuts compiled into the CLI rule set.
struct FilterCli {
  std::vector<const wchar_t*> files;
  const wchar_t* dir = nullptr;
  std::vector<std::wstring> includes, excludes;
  const wchar_t* match = nullptr;
  const wchar_t* groups = nullptr;
  std::vector<std::wstring> pids;
  std::vector<std::wstring> procs;
  bool failed = false;
};

// Load one filter config, dispatching by extension: .reg / .pmc, else JSON.
// `why`, if non-null, receives a short failure reason for JSON configs (empty
// for .reg/.pmc).
std::error_code loadFilterConfig(const wchar_t* path, pmx::FilterSet& out,
                                 std::string* why = nullptr);

// Load every config in a directory as its own lens (see FilterGroup).
std::error_code loadFilterDir(const wchar_t* dir, pmx::FilterGroup& out);

// Consume argv[i] (and its value) if it is a filter option; advances `i`.
bool parseFilterArg(int argc, wchar_t** argv, int& i, FilterCli& fc);

// Build the CLI rule set + lens group from parsed options. Returns 0, or a
// process exit code after printing the error.
int buildFilters(const FilterCli& fc, pmx::FilterSet& cliSet,
                 pmx::FilterGroup& lenses);

// ---- Config (pmx.json) -------------------------------------------------------
struct PmxConfig {
  size_t bufferMb = 256;   // EventSpool RAM budget before a run spills
  std::wstring spoolDir;   // spill dir; empty = GetTempPathW
};

// Load the RAM-buffer config. `explicitPath` (--config FILE): the file must
// exist and parse; else <dir of pmx.exe>\pmx.json is tried: missing = defaults
// silently, malformed = fatal either way. Returns 0, or a process exit code
// after printing the error.
int loadPmxConfig(const wchar_t* explicitPath, PmxConfig& out);

// ---- live/net spool finalize --------------------------------------------------
// Output file paths for a live/net capture's spool drain; null = not requested.
struct LiveOutputPaths {
  const wchar_t* save = nullptr;  // .pmxlog
  const wchar_t* csv = nullptr;
  const wchar_t* json = nullptr;  // file only - "--json -" streams live instead
  const wchar_t* pml = nullptr;
};

// Drains `spool` into the requested output files: save/pml receive an event if
// (tag & 1) || unfiltered, csv/json only if (tag & 1) - i.e. by default every
// output is the filtered view; --unfiltered keeps save/pml as the full raw
// capture. Prints a "Writing N events" status line, a throttled stderr
// progress line for large/spilled captures, then the per-file "Saved"/"Wrote"
// summary. Returns 0, or a process exit code after printing the error (every
// writer is still closed, even after one fails).
int finalizeSpool(pmx::EventSpool& spool, const LiveOutputPaths& paths,
                  bool unfiltered);

}  // namespace pmx::cli
