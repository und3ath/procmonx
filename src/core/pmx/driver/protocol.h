#pragma once
// Process Monitor minifilter communication-port protocol (version 25).
//
// All multi-byte fields are little-endian; structs
// are packed to match the on-wire form exactly.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace pmx::proto {

// Event class names. "IPC" (class 6) is where named-pipe / mailslot / LPC I/O
// lands - not File System.
inline const char* className(uint16_t c) noexcept {
  switch (c) {
    case 0: return "Completion";
    case 1: return "Process";
    case 2: return "Registry";
    case 3: return "FileSystem";
    case 4: return "Profiling";
    case 5: return "Network";
    case 6: return "IPC";
    default: return "?";
  }
}

// Per-class operation-name tables. The record's `operation` field indexes
// directly into the table for its class.
inline const char* processOpName(uint16_t op) noexcept {
  static const char* const k[] = {
      "Process Defined", "Process Create", "Process Exit", "Thread Create",
      "Thread Exit",     "Load Image",     "Thread Profile", "Process Start",
      "Process Statistics", "System Statistics"};
  return op < 10 ? k[op] : "?";
}

inline const char* registryOpName(uint16_t op) noexcept {
  static const char* const k[] = {
      "RegOpenKey",   "RegCreateKey",  "RegCloseKey",  "RegQueryKey",
      "RegSetValue",  "RegQueryValue", "RegEnumValue", "RegEnumKey",
      "RegSetInfoKey", "RegDeleteKey", "RegDeleteValue", "RegFlushKey",
      "RegLoadKey",   "RegUnloadKey",  "RegRenameKey",
      "RegQueryMultipleValueKey", "RegSetKeySecurity", "RegQueryKeySecurity",
      "RegOpenKey2",  "RegRestoreKey", "RegSaveKey",   "RegReplaceKey"};
  return op < 22 ? k[op] : "?";
}

inline const char* profilingOpName(uint16_t op) noexcept {
  static const char* const k[] = {"Thread Profiling", "Process Profiling",
                                   "Debug Output Profiling"};
  return op < 3 ? k[op] : "?";
}

// FileSystem friendly names (class 3/6), Procmon's internal op enum — NOT raw
// IRP major codes. Index = operation. Entries with sub-operations (e.g.
// QueryInformationFile) resolve a finer name from the first detail byte in
// Procmon; here we return the top-level friendly name. "" = no friendly name
// (Procmon shows the IRP_MJ_* / FASTIO_* form instead).
inline const char* fileOpName(uint16_t op) noexcept {
  static const char* const k[] = {
      "VolumeDismount",                    // 0
      "VolumeMount",                       // 1
      "FASTIO_MDL_WRITE_COMPLETE",         // 2
      "WriteFile",                         // 3  (FASTIO_MDL_WRITE)
      "FASTIO_MDL_READ_COMPLETE",          // 4
      "ReadFile",                          // 5  (FASTIO_MDL_READ)
      "QueryOpen",                         // 6
      "FASTIO_CHECK_IF_POSSIBLE",          // 7
      "IRP_MJ_12",                         // 8
      "IRP_MJ_11",                         // 9
      "IRP_MJ_10",                         // 10
      "IRP_MJ_9",                          // 11
      "IRP_MJ_8",                          // 12
      "FASTIO_NOTIFY_STREAM_FO_CREATION",  // 13
      "FASTIO_RELEASE_FOR_CC_FLUSH",       // 14
      "FASTIO_ACQUIRE_FOR_CC_FLUSH",       // 15
      "FASTIO_RELEASE_FOR_MOD_WRITE",      // 16
      "FASTIO_ACQUIRE_FOR_MOD_WRITE",      // 17
      "FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION",  // 18
      "CreateFileMapping",                 // 19
      "CreateFile",                        // 20  (IRP_MJ_CREATE)
      "CreatePipe",                        // 21  (IRP_MJ_CREATE_NAMED_PIPE)
      "IRP_MJ_CLOSE",                      // 22
      "ReadFile",                          // 23  (IRP_MJ_READ)
      "WriteFile",                         // 24  (IRP_MJ_WRITE)
      "QueryInformationFile",              // 25
      "SetInformationFile",                // 26
      "QueryEAFile",                       // 27
      "SetEAFile",                         // 28
      "FlushBuffersFile",                  // 29
      "QueryVolumeInformation",            // 30
      "SetVolumeInformation",              // 31
      "DirectoryControl",                  // 32
      "FileSystemControl",                 // 33
      "DeviceIoControl",                   // 34
      "InternalDeviceIoControl",           // 35
      "Shutdown",                          // 36
      "LockUnlockFile",                    // 37
      "CloseFile",                         // 38  (IRP_MJ_CLEANUP)
      "CreateMailSlot",                    // 39
      "QuerySecurityFile",                 // 40
      "SetSecurityFile",                   // 41
      "Power",                             // 42
      "SystemControl",                     // 43
      "DeviceChange",                      // 44
      "QueryFileQuota",                    // 45
      "SetFileQuota",                      // 46
      "PlugAndPlay",                       // 47
      "IRP_MJ_MAXIMUM_FUNCTION"};          // 48
  return op < 49 ? k[op] : "?";
}

// Refined FileSystem sub-operation name. Several FS ops carry a sub-operation
// table: the first byte of the detail blob (FileInformationClass,
// FsInformationClass, or the IRP minor function) selects a finer name. Returns
// nullptr when the op has no sub-table or the discriminator is unknown (caller
// falls back to fileOpName).
inline const char* fileSubOpName(uint16_t op, uint8_t disc) noexcept {
  switch (op) {
    case 25:  // QueryInformationFile — key = FILE_INFORMATION_CLASS
      switch (disc) {
        case 4:  return "QueryBasicInformationFile";
        case 5:  return "QueryStandardInformationFile";
        case 6:  return "QueryFileInternalInformationFile";
        case 7:  return "QueryEaInformationFile";
        case 9:  return "QueryNameInformationFile";
        case 14: return "QueryPositionInformationFile";
        case 18: return "QueryAllInformationFile";
        case 22: return "QueryStreamInformationFile";
        case 28: return "QueryCompressionInformationFile";
        case 29: return "QueryId";
        case 31: return "QueryMoveClusterInformationFile";
        case 34: return "QueryNetworkOpenInformationFile";
        case 35: return "QueryAttributeTagFile";
        case 37: return "QueryIdBothDirectory";
        case 39: return "QueryValidDataLength";
        case 40: return "QueryShortNameInformationFile";
        case 43: return "QueryIoPiorityHint";  // Procmon's own spelling
        case 46: return "QueryLinks";
        case 48: return "QueryNormalizedNameInformationFile";
        case 49: return "QueryNetworkPhysicalNameInformationFile";
      }
      return nullptr;
    case 26:  // SetInformationFile — key = FILE_INFORMATION_CLASS
      switch (disc) {
        case 4:  return "SetBasicInformationFile";
        case 10: return "SetRenameInformationFile";
        case 11: return "SetLinkInformationFile";
        case 13: return "SetDispositionInformationFile";
        case 14: return "SetPositionInformationFile";
        case 19: return "SetAllocationInformationFile";
        case 20: return "SetEndOfFileInformationFile";
        case 39: return "SetValidDataLengthInformationFile";
      }
      return nullptr;
    case 30:  // QueryVolumeInformation — key = FS_INFORMATION_CLASS
      switch (disc) {
        case 1: return "QueryInformationVolume";
        case 2: return "QueryLabelInformationVolume";
        case 3: return "QuerySizeInformationVolume";
      }
      return nullptr;
    case 32:  // DirectoryControl — key = IRP minor function
      switch (disc) {
        case 1: return "QueryDirectory";
        case 2: return "NotifyChangeDirectory";
      }
      return nullptr;
    case 37:  // LockUnlockFile — key = IRP minor function
      switch (disc) {
        case 1: return "LockFile";
        case 2: return "UnlockFileSingle";
        case 3: return "UnlockFileAll";
      }
      return nullptr;
    case 47:  // PlugAndPlay — key = IRP minor function
      switch (disc) {
        case 0: return "StartDevice";
        case 1: return "QueryRemoveDevice";
        case 2: return "RemoveDevice";
        case 3: return "CancelRemoveDevice";
        case 4: return "StopDevice";
      }
      return nullptr;
    default:
      return nullptr;
  }
}

// Inverse of fileSubOpName: the discriminator byte whose refined name is
// `name` for `op`, or 0 when none matches (e.g. the name is the base op name).
inline uint8_t fileSubOpFromName(uint16_t op, const char* name) noexcept {
  for (int k = 0; k < 256; ++k) {
    const char* s = fileSubOpName(op, static_cast<uint8_t>(k));
    if (s && std::strcmp(s, name) == 0) return static_cast<uint8_t>(k);
  }
  return 0;
}

// Best operation name for a FileSystem event: the refined sub-op name when the
// detail's discriminator byte resolves one, else the top-level friendly name.
// detail0 is the first byte of the record's detail blob (0 if none).
inline const char* fileOpNameEx(uint16_t op, uint8_t detail0) noexcept {
  const char* sub = fileSubOpName(op, detail0);
  return sub ? sub : fileOpName(op);
}

// ---- FileSystem detail-blob numeric fields -------------------------------
// The FS detail blob (record + 52 + 8*frameCount) has a fixed pre-path region
// then a length-prefixed path at +0x40. Only the exact, table-free fields are
// decoded here.
//
//   +0x08  u32   I/O flags / priority (Read/Write)
//   +0x10  u32   Length            (Read/Write)
//   +0x18  u32   CreateFile packed: low 24 bits = CreateOptions, top byte misc
//   +0x20  u64   Offset            (Read/Write)
//   +0x40  u16   path length prefix (bit15 = flag), path (UTF-16) at +0x44
//   post-path    CreateFile Desired Access (u32) + share/attr/alloc (variable)

// Exact FileSystem path from the length-prefixed field: u16 char count at
// detail+0x40 (low 15 bits; bit15 selects a 1-byte unit, default 2 = UTF-16),
// path bytes at detail+0x44. Applies to class 3/6 (FileSystem) events. Returns
// the UTF-16 path span; false if too short/truncated or the 1-byte-unit variant
// (rare) is present. Validated live (Discord.exe / main.log captures).
inline bool fsPath(const uint8_t* detail, size_t n, const wchar_t*& out,
                   size_t& outLen) noexcept {
  if (n < 0x44) return false;
  uint16_t pfx;
  std::memcpy(&pfx, detail + 0x40, 2);
  const size_t chars = pfx & 0x7FFFu;
  const bool oneByteUnit = (pfx & 0x8000u) != 0;
  if (oneByteUnit) return false;  // ANSI variant — caller falls back
  if (chars == 0 || 0x44 + chars * 2 > n) return false;
  out = reinterpret_cast<const wchar_t*>(detail + 0x44);
  outLen = chars;
  return true;
}

// Read (23) / Write (24) numeric fields. Returns false if op mismatches or the
// detail blob is too short.
struct FileRwDetail {
  uint64_t offset;
  uint32_t length;
};
inline bool parseFileRw(uint16_t op, const uint8_t* detail, size_t n,
                        FileRwDetail& out) noexcept {
  if ((op != 23 && op != 24) || n < 0x28) return false;
  uint32_t len;
  uint64_t off;
  std::memcpy(&len, detail + 0x10, 4);
  std::memcpy(&off, detail + 0x20, 8);
  out.length = len;
  out.offset = off;
  return true;
}

// CreateFile (20) fixed pre-path fields. CreateOptions is the low 24 bits of the
// dword at detail+0x18. Desired Access sits at the start of the post-path blob
// (detail+0x44 + pathBytes); pathBytes derives from the +0x40 length prefix.
struct FileCreateDetail {
  uint32_t createOptions;   // FILE_* create options (low 24 bits of +0x18)
  uint8_t disposition;      // CreateDisposition (top byte of +0x18): 0..5
  uint16_t attributes;      // FILE_ATTRIBUTE_* mask (u16 @ +0x20)
  uint16_t shareMode;       // FILE_SHARE_* mask   (u16 @ +0x22)
  uint32_t allocationSize;  // AllocationSize      (u32 @ +0x38)
  uint32_t desiredAccess;   // ACCESS_MASK (post-path); 0 if not present
  bool hasDesiredAccess;
};
inline bool parseFileCreate(uint16_t op, const uint8_t* detail, size_t n,
                            FileCreateDetail& out) noexcept {
  if (op != 20 || n < 0x44) return false;
  uint32_t packed;
  std::memcpy(&packed, detail + 0x18, 4);
  out.createOptions = packed & 0x00FFFFFFu;
  out.disposition = static_cast<uint8_t>(packed >> 24);
  std::memcpy(&out.attributes, detail + 0x20, 2);
  std::memcpy(&out.shareMode, detail + 0x22, 2);
  std::memcpy(&out.allocationSize, detail + 0x38, 4);
  out.desiredAccess = 0;
  out.hasDesiredAccess = false;
  // Path: u16 at +0x40, low 15 bits = char count. Chars are 2-byte UTF-16 by
  // default; bit15 set switches to a 1-byte unit.
  uint16_t pfx;
  std::memcpy(&pfx, detail + 0x40, 2);
  const uint32_t chars = pfx & 0x7FFFu;
  const uint32_t unit = (pfx & 0x8000u) ? 1u : 2u;
  const size_t pathBytes = static_cast<size_t>(chars) * unit;
  const size_t accOff = 0x44 + pathBytes;
  if (accOff + 4 <= n) {
    uint32_t acc;
    std::memcpy(&acc, detail + accOff, 4);
    out.desiredAccess = acc;
    out.hasDesiredAccess = true;
  }
  return true;
}

// ---- Registry value detail-blob fields ------------------------------------
// The registry value record (RegSetValue / RegQueryValue) lays the detail out
// as:
//   +0x00  u16  value-name length in wchars
//   +0x04  u32  REG value type (0..11)          (see regTypeName)
//   +0x08  u32  full value data length in bytes
//   +0x0C  u16  data bytes actually captured    (capped: 16 for DWORD/QWORD,
//                                                 2048 for SZ/binary, ...)
//   +0x10       full object path (UTF-16, nameWchars*2 bytes) - the key path with
//               the value name as its last component; NOT null-terminated, so the
//               captured data begins immediately after and must be bounded by
//               nameWchars (a greedy printable scan bleeds data into the path)
//   +0x10 + nameWchars*2   captured data bytes
// RegSetValue (op 4) fills type + data at the pre-op (the caller supplied them),
// so they decode directly. RegQueryValue (op 5) has NO valid type/data at the
// pre-op - the result is delivered by a separate post record - so callers must
// treat type/data as valid only when `type` is a real REG_* (< 12).
struct RegValueDetail {
  uint32_t type;          // REG_* (see regTypeName)
  uint32_t length;        // full value data length in bytes
  uint16_t nameWchars;    // full path length in UTF-16 code units
  uint16_t dataBytes;     // captured (possibly truncated) data byte count
  const uint8_t* name;    // -> full object path within `detail` (nameWchars long)
  const uint8_t* data;    // -> captured data within `detail`, or nullptr
};
inline bool parseRegValue(uint16_t op, const uint8_t* detail, size_t n,
                          RegValueDetail& out) noexcept {
  if ((op != 4 && op != 5) || n < 0x10) return false;
  std::memcpy(&out.nameWchars, detail + 0x00, 2);
  std::memcpy(&out.type, detail + 0x04, 4);
  std::memcpy(&out.length, detail + 0x08, 4);
  std::memcpy(&out.dataBytes, detail + 0x0C, 2);
  const size_t nameOff = 0x10;
  const size_t dataOff = nameOff + static_cast<size_t>(out.nameWchars) * 2;
  out.name = (out.nameWchars && dataOff <= n) ? detail + nameOff : nullptr;
  out.data = (out.dataBytes && dataOff + out.dataBytes <= n) ? detail + dataOff
                                                             : nullptr;
  return true;
}

// RegQueryValue's result arrives in the paired class-0 completion, whose detail
// is a KEY_VALUE_PARTIAL_INFORMATION: {u32 TitleIndex; u32 Type; u32 DataLength;
// u8 Data[]}. Parse the type + (possibly truncated) captured data out of it.
struct RegQueryResult {
  uint32_t type;          // REG_* value type
  uint32_t length;        // full DataLength in bytes
  uint16_t dataBytes;     // captured data bytes available in this record
  const uint8_t* data;    // -> data within the completion detail, or nullptr
};
inline bool parseRegQueryResult(const uint8_t* comp, size_t n,
                                RegQueryResult& out) noexcept {
  if (n < 0x0C) return false;
  std::memcpy(&out.type, comp + 0x04, 4);
  std::memcpy(&out.length, comp + 0x08, 4);
  const size_t avail = n - 0x0C;
  size_t db = out.length < avail ? out.length : avail;
  if (db > 0xFFFF) db = 0xFFFF;
  out.dataBytes = static_cast<uint16_t>(db);
  out.data = out.dataBytes ? comp + 0x0C : nullptr;
  return true;
}

// Registry detail records store the object-path length (in UTF-16 code units)
// as a u16 at +0x00. Returns 0 when the record is too short to carry it.
inline uint16_t regPathWchars(const uint8_t* detail, size_t n) noexcept {
  uint16_t w = 0;
  if (n >= 2) std::memcpy(&w, detail, 2);
  return w;
}

// Operation name for any class/op pair (class = EventRecordHeader::eventClass).
inline const char* operationName(uint16_t cls, uint16_t op) noexcept {
  switch (cls) {
    case 1: return processOpName(op);
    case 2: return registryOpName(op);
    case 3:
    case 6: return fileOpName(op);
    case 4: return profilingOpName(op);
    default: return "?";
  }
}

// Communication-port name. The trailing number is the protocol tag; different
// builds expose ProcessMonitor<NN>Port (connectAuto sweeps a range of tags).
inline constexpr wchar_t kPortName25[] = L"\\ProcessMonitor25Port";

// Control-message opcodes (first DWORD of every FilterSendMessage payload).
enum class Op : uint32_t {
  SetCapture = 0,   // {op, uint32 flags}         size 8   toggle capture on/off
  SetInterval = 1,  // {op, uint64 interval100ns} size 12  profiling/flush cadence
};

#pragma pack(push, 1)

// SetCapture flag bits, as the driver decodes them. This is the ONLY
// kernel-side selection the protocol offers: there is no rule-filter message,
// so all rule filtering is user mode. The default is kCaptureDefault (0x7).
enum CaptureFlags : uint32_t {
  // Process/thread/load-image notify routines + the profiling threads: event
  // classes Process (1) and Profiling (4). Also the source of the process
  // rundown records the ProcessTable needs for names, so keep it on.
  kCaptureProcess = 0x1,
  // Minifilter attached to all volumes + IRP pre-op callback gate: event
  // classes File System (3) and IPC (6).
  kCaptureFileSystem = 0x2,
  // Registry callback is registered iff (flags & 0xC) == 0x4: Registry (2).
  kCaptureRegistry = 0x4,
  kCaptureRegistryOff = 0x8,
  // Signals a kernel event (Procmon /ExternalCapture); selects no events.
  kCaptureExternal = 0x10,
  kCaptureDefault = kCaptureProcess | kCaptureFileSystem | kCaptureRegistry,
};

// Smallest capture mask that still produces event class `cls` (plus process
// info). Network (5) comes from ETW, not the driver.
inline uint32_t captureFlagsForClass(int cls) noexcept {
  switch (cls) {
    case 1:
    case 4:
    case 5: return kCaptureProcess;
    case 3:
    case 6: return kCaptureProcess | kCaptureFileSystem;
    case 2: return kCaptureProcess | kCaptureRegistry;
    default: return kCaptureDefault;
  }
}

// Op::SetCapture. flags = CaptureFlags mask; Procmon sends 0 to stop.
struct SetCaptureMsg {
  uint32_t opcode;  // = Op::SetCapture
  uint32_t flags;
};
static_assert(sizeof(SetCaptureMsg) == 8);

// Op::SetInterval. interval = 10'000'000 / rateHz (100ns units).
struct SetIntervalMsg {
  uint32_t opcode;  // = Op::SetInterval
  uint64_t interval;
};
static_assert(sizeof(SetIntervalMsg) == 12);

inline constexpr uint64_t kIntervalUnitsPerSec = 10'000'000ull;  // 0x989680

// Payload delivered by FilterGetMessage, immediately after FILTER_MESSAGE_HEADER:
//   [FILTER_MESSAGE_HEADER (0x10)] [uint32 payloadLen] [uint8 records[payloadLen]]
// payloadLen is the total byte count of the packed record array that follows.
struct EventBatchPrefix {
  uint32_t payloadLen;
};

// Each record is two-tier:
//   [ EventRecordHeader (52B) ][ stack: 8*frameCount ][ detail blob: detailSize ]
// The header carries framing + common meta; the detail blob begins with a
// per-operation DetailLeader (PID/TID/durations/path). Record stride:
//     0x34 + 8 * frameCount + detailSize
//

enum class EventClass : uint16_t {
  System = 0,        // not added to the model
  Process = 1,       // image path / command line handling
  Registry = 2,
  FileSystem = 3,    // path + filename sanitization
  Profiling = 4,     // writes a duration/counter field
  Network = 5,       // ETW-sourced (not emitted by the driver)
  Class6 = 6,        // IPC; shares FileSystem-style path handling
};

struct EventRecordHeader {
  uint32_t processIndex;   // +0x00  Procmon process-table index (NOT the OS PID);
                           //        resolve via the Process-rundown events
  uint32_t threadId;       // +0x04  originating thread id
  uint16_t eventClass;     // +0x08  EventClass (switch selector)
  uint16_t reserved_0a;    // +0x0A
  uint16_t operation;      // +0x0C  operation/subtype within the class
  uint16_t reserved_0e;    // +0x0E
  uint32_t sequence;       // +0x10  monotonic sequence (secondary sort key)
  uint32_t reserved_14;    // +0x14
  uint32_t reserved_18;    // +0x18
  uint64_t timestamp;      // +0x1C  event time, 100ns units (primary sort key)
  uint32_t result;         // +0x24  NTSTATUS (== 0x103 STATUS_PENDING special)
  uint16_t frameCount;     // +0x28  stack frames, 8 bytes each (x64)
  uint16_t reserved_2a;    // +0x2A
  uint32_t detailSize;     // +0x2C  detail blob length
  uint32_t reserved_30;    // +0x30  scratch
};
static_assert(sizeof(EventRecordHeader) == 0x34);
static_assert(offsetof(EventRecordHeader, eventClass) == 0x08);
static_assert(offsetof(EventRecordHeader, operation) == 0x0C);
static_assert(offsetof(EventRecordHeader, sequence) == 0x10);
static_assert(offsetof(EventRecordHeader, timestamp) == 0x1C);
static_assert(offsetof(EventRecordHeader, result) == 0x24);

inline constexpr uint32_t kStatusPending = 0x00000103;  // STATUS_PENDING

// Detail leader for a Process-rundown/create event (EventClass::Process,
// operation 0), at record + 52 + 8*frameCount. After the fixed part: a
// token/integrity blob and SID, then two consecutive UTF-16 strings — image
// path, then command line.
struct ProcessDetail {
  uint32_t processIndex;   // +0x00  == header processIndex
  uint32_t processId;      // +0x04  real OS PID
  uint32_t parentIndex;    // +0x08  parent's process index
  uint32_t parentId;       // +0x0C  real parent PID
  uint32_t sessionId;      // +0x10  session (0 = services, 1 = first user)
  uint32_t flags14;        // +0x14  boolean-ish (1/0)
  uint64_t createTime;     // +0x18  FILETIME (UTC, 100ns)
  uint32_t f20;            // +0x20  varies
  // +0x24.. token/integrity, SID, then UTF-16 imagePath\0 commandLine\0
};
static_assert(offsetof(ProcessDetail, processId) == 0x04);
static_assert(offsetof(ProcessDetail, sessionId) == 0x10);
static_assert(offsetof(ProcessDetail, createTime) == 0x18);

#pragma pack(pop)

// Image path + command line of a Process Defined (op 0) / Process Create (op 1)
// record. Both ops share one detail layout, and both define a process-table
// entry keyed by detail+0 (the new process's index). String layout:
//   d[0x2C] + d[0x2D]  token/SID blob length (two bytes, summed)
//   u16 @0x2E          image path char count   (bit15 = 1-byte unit)
//   u16 @0x30          command line char count (bit15 = 1-byte unit)
//   image @ 0x34 + d[0x2C] + d[0x2D], command line immediately after.
// Strings are length-prefixed, NOT NUL-terminated (the command line follows the
// image contiguously). Returns false if the blob is too short or the image is
// missing / uses the (unseen) 1-byte unit; cmdline may come back empty.
struct ProcessStrings {
  const wchar_t* image = nullptr;
  size_t imageLen = 0;
  const wchar_t* cmdline = nullptr;
  size_t cmdlineLen = 0;
};
inline bool parseProcessStrings(const uint8_t* d, size_t n,
                                ProcessStrings& out) noexcept {
  out = {};
  if (n < 0x34) return false;
  uint16_t imgPfx, cmdPfx;
  std::memcpy(&imgPfx, d + 0x2E, 2);
  std::memcpy(&cmdPfx, d + 0x30, 2);
  const size_t imgBase = 0x34 + size_t{d[0x2C]} + d[0x2D];
  const size_t imgChars = imgPfx & 0x7FFFu;
  if ((imgPfx & 0x8000u) || imgChars == 0 || imgBase + imgChars * 2 > n)
    return false;
  out.image = reinterpret_cast<const wchar_t*>(d + imgBase);
  out.imageLen = imgChars;
  const size_t cmdBase = imgBase + imgChars * 2;
  const size_t cmdChars = cmdPfx & 0x7FFFu;
  if (!(cmdPfx & 0x8000u) && cmdChars && cmdBase + cmdChars * 2 <= n) {
    out.cmdline = reinterpret_cast<const wchar_t*>(d + cmdBase);
    out.cmdlineLen = cmdChars;
  }
  return true;
}

// Process Create (op 1) images arrive as NT "\??\C:\..." paths while rundown
// (op 0) images are plain "C:\..."; drop the "\??\" prefix so both match.
inline std::wstring win32ImagePath(const wchar_t* p, size_t n) {
  if (n >= 4 && p[0] == L'\\' && p[1] == L'?' && p[2] == L'?' && p[3] == L'\\')
    return std::wstring(p + 4, n - 4);
  return std::wstring(p, n);
}

inline uint64_t recordSize(const EventRecordHeader& h) noexcept {
  return sizeof(EventRecordHeader) + 8ull * h.frameCount + h.detailSize;
}

// FilterGetMessage receive buffer capacity: 0x10 header + 128 KB payload.
inline constexpr uint32_t kMessageBufferSize = 0x20014;

}  // namespace pmx::proto
