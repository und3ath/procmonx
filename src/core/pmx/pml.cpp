#include "pmx/pml.h"

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "pmx/file_io.h"

namespace pmx {

namespace {

std::error_code errc(int e) { return {e, std::system_category()}; }

// Little-endian POD append helpers into the in-memory file buffer.
void putU8(std::vector<uint8_t>& b, uint8_t v) { b.push_back(v); }
void putU16(std::vector<uint8_t>& b, uint16_t v) {
  b.insert(b.end(), (const uint8_t*)&v, (const uint8_t*)&v + 2);
}
void putU32(std::vector<uint8_t>& b, uint32_t v) {
  b.insert(b.end(), (const uint8_t*)&v, (const uint8_t*)&v + 4);
}
void putU64(std::vector<uint8_t>& b, uint64_t v) {
  b.insert(b.end(), (const uint8_t*)&v, (const uint8_t*)&v + 8);
}
void putZeros(std::vector<uint8_t>& b, size_t n) { b.insert(b.end(), n, 0); }
// Raw UTF-16LE code units, no NUL terminator.
void putW(std::vector<uint8_t>& b, const std::wstring& s) {
  const uint8_t* p = (const uint8_t*)s.data();
  b.insert(b.end(), p, p + s.size() * 2);
}

// Patch helpers for writing into the already-reserved header region.
void patchBytes(std::vector<uint8_t>& b, size_t off, const void* data,
                size_t n) {
  std::memcpy(b.data() + off, data, n);
}
void patchU32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
  patchBytes(b, off, &v, 4);
}
void patchU64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
  patchBytes(b, off, &v, 8);
}
// Writes `s` as UTF-16LE into a fixed-size (in wchar_t units) NUL-padded
// field, truncating to fieldWchars-1 code units + NUL if too long.
void patchWFixed(std::vector<uint8_t>& b, size_t off, const std::wstring& s,
                 size_t fieldWchars) {
  std::wstring t = s;
  if (t.size() > fieldWchars - 1) t.resize(fieldWchars - 1);
  patchBytes(b, off, t.data(), t.size() * 2);
  // Remaining bytes in the field are already zero from buf.resize().
}

// Process-table struct fields, in exact on-disk order (matches how Procmon
// writes it and procmon-parser reads it):
//   u32 process_index, u32 pid, u32 parent_pid,                = 12
//   u32 parent_process_index,                                   = 4   (16)
//   u64 authentication_id,                                      = 8   (24)
//   u32 session,                                                = 4   (28)
//   u32 unknown,                                                = 4   (32)
//   u64 start_time, u64 end_time,                               = 16  (48)
//   u32 virtualized, u32 is_process_64bit,                      = 8   (56)
//   u32 integrity, u32 user, u32 process_name, u32 image_path,
//   u32 command_line, u32 company, u32 version, u32 description = 32  (88)
//   u32 icon_index_small, u32 icon_index_big,                   = 8   (96)
//   pvoid unknown (8 bytes, x64),                               = 8   (104)
//   u32 number_of_modules                                       = 4   (108)
// Total = 108 = 0x6C bytes.
constexpr size_t kProcStructSize = 108;

// Build a Process Monitor registry detail blob for one event. Procmon reads it
// as: u16 path-string-info (bit15 = is-ASCII, low 15 = char count), then
// operation-specific fixed fields, then the path string bytes, then (for a few
// ops) inline extra data. Stage 2a emits the Path plus correctly-sized, zeroed
// fixed fields (raw access masks / value types / data are not retained on the
// decoded Event yet), so the file loads and every registry row shows its Path;
// the Detail column stays minimal. `op` is the RegistryOperation code.
void appendRegDetail(std::vector<uint8_t>& d, const Event& ev) {
  const uint16_t op = ev.operation;
  const std::wstring& path = ev.path;
  auto u16 = [&](uint16_t v) {
    d.insert(d.end(), (const uint8_t*)&v, (const uint8_t*)&v + 2);
  };
  auto u32 = [&](uint32_t v) {
    d.insert(d.end(), (const uint8_t*)&v, (const uint8_t*)&v + 4);
  };
  size_t chars = path.size() > 0x7FFF ? 0x7FFF : path.size();
  // RegSetValue carries its captured value bytes inline after the path.
  const uint32_t setDataLen =
      op == 4 ? (uint32_t)ev.valueData.size() : 0u;
  u16((uint16_t)chars);  // path-string-info: is_ascii=0 (UTF-16), char count

  switch (op) {
    case 0:   // RegOpenKey
    case 1:   // RegCreateKey
      u16(0); u32(ev.desiredAccess);      // pad, desired_access
      break;
    case 3:   // RegQueryKey
    case 5:   // RegQueryValue (result Type/Data would need the extra section)
      u16(0); u32(ev.regLength); u32(2);  // pad, length, information_class
      break;
    case 6:   // RegEnumValue
    case 7:   // RegEnumKey
      u16(0); u32(0); u32(0); u32(0);     // pad, length, index, information_class
      break;
    case 4:   // RegSetValue — real type/length + inline data below
      u16(0); u32(ev.regType); u32(ev.regLength); u32(setDataLen);
      break;
    case 8:   // RegSetInfoKey (extra inline; length=0 -> none)
      u16(0); u32(0); u32(0); u16(0); u16(0);  // pad, class, pad, length, pad
      break;
    case 12:  // RegLoadKey (new path inline; empty)
    case 14:  // RegRenameKey
      u16(0);                             // new-path-string-info (0 chars)
      break;
    // Layouts below match what the PML reader expects (fixed-field min sizes,
    // path offsets): path at +8 for 18/19/20, at +6 for 21.
    case 18:  // RegOpenKey2: like RegOpenKey
      u16(0); u32(ev.desiredAccess);
      break;
    case 19:  // RegRestoreKey: +2 = file-path string info (empty), pad to 8
    case 20:  // RegSaveKey
      u16(0); u32(0);
      break;
    case 21:  // RegReplaceKey: +2 new-file, +4 old-file string infos (empty)
      u16(0); u16(0);
      break;
    default:  // Close/Delete*/Flush/Unload/QueryMultiple/*KeySecurity: no fields
      break;
  }

  // Path string bytes (UTF-16LE, char-count code units, no NUL).
  const uint8_t* p = (const uint8_t*)path.data();
  d.insert(d.end(), p, p + chars * 2);
  // RegSetValue: the captured value bytes follow the path inline; the reader
  // decodes them per reg_type (DWORD/QWORD/SZ/binary...) for the Data column.
  if (op == 4 && setDataLen)
    d.insert(d.end(), ev.valueData.begin(), ev.valueData.end());
}

// File System / IPC detail blob. Procmon reads: u8 sub_operation, 3 pad, a
// fixed per-sub-op block of (pvoid*5 + 0x14) = 60 bytes on x64, u16
// path-string-info, 2 pad, then the path string. Stage 2a zeroes the sub-op
// (keeps the base operation name) and the fixed block, so every file/IPC row
// shows its Path with a minimal Detail column.
void appendFsDetail(std::vector<uint8_t>& d, const Event& ev) {
  const uint16_t op = ev.operation;
  const std::wstring& path = ev.path;
  auto u16 = [&](uint16_t v) {
    d.insert(d.end(), (const uint8_t*)&v, (const uint8_t*)&v + 2);
  };
  auto u32 = [&](uint32_t v) {
    d.insert(d.end(), (const uint8_t*)&v, (const uint8_t*)&v + 4);
  };

  d.push_back(ev.fsSubOp);        // sub_operation: Procmon's op-name key
  d.insert(d.end(), 3, 0);        // padding

  // The 60-byte fixed block (pvoid*5 + 0x14, x64). Fill the fields the reader
  // pulls out per operation at their exact offsets; the rest stays zero.
  uint8_t blk[60] = {0};
  auto put32 = [&](size_t off, uint32_t v) { std::memcpy(blk + off, &v, 4); };
  auto put16 = [&](size_t off, uint16_t v) { std::memcpy(blk + off, &v, 2); };
  auto put64 = [&](size_t off, uint64_t v) { std::memcpy(blk + off, &v, 8); };
  if (op == 20) {  // CreateFile: disposition<<24 | options, attrs, share, alloc
    put32(0x14, ((uint32_t)ev.fsDisposition << 24) | (ev.fsOptions & 0xFFFFFF));
    put16(0x1C, ev.fsAttributes);
    put16(0x1E, ev.fsShareMode);
    put32(0x34, ev.fsAllocation);
  } else if (op == 23 || op == 24) {  // ReadFile / WriteFile: length, offset
    put32(0x0C, ev.ioLength);
    put64(0x1C, ev.ioOffset);
  }
  d.insert(d.end(), blk, blk + 60);

  size_t chars = path.size() > 0x7FFF ? 0x7FFF : path.size();
  u16((uint16_t)chars);           // path-string-info: is_ascii=0, char count
  u16(0);                         // padding
  const uint8_t* p = (const uint8_t*)path.data();
  d.insert(d.end(), p, p + chars * 2);

  // Post-path fields read from the main stream: CreateFile reads a u32 desired
  // access + u8 SID length (0 -> no SID) + 3 pad. Emit the real access for
  // CreateFile; a zero pad covers any other handler's small post-path reads
  // (bounded by detailSize, so surplus is ignored).
  if (op == 20) u32(ev.desiredAccess);
  d.insert(d.end(), 64, 0);
}

// Process (class 1) detail. Layouts per procmon-parser's process handlers; we
// fill the fields we have (pid, image path, command line) and zero the rest.
void appendProcessDetail(std::vector<uint8_t>& d, uint16_t op,
                         const std::wstring& path, const std::wstring& cmdline,
                         uint32_t pid) {
  auto u16 = [&](uint16_t v) {
    d.insert(d.end(), (const uint8_t*)&v, (const uint8_t*)&v + 2);
  };
  auto u32 = [&](uint32_t v) {
    d.insert(d.end(), (const uint8_t*)&v, (const uint8_t*)&v + 4);
  };
  auto zeros = [&](size_t n) { d.insert(d.end(), n, 0); };
  auto wbytes = [&](const std::wstring& s, size_t chars) {
    d.insert(d.end(), (const uint8_t*)s.data(),
             (const uint8_t*)s.data() + chars * 2);
  };
  size_t pc = path.size() > 0x7FFF ? 0x7FFF : path.size();
  size_t cc = cmdline.size() > 0x7FFF ? 0x7FFF : cmdline.size();

  switch (op) {
    case 0:   // Process_Defined (rundown)
    case 1:   // Process_Create
      zeros(4); u32(pid); zeros(0x24); d.push_back(0); d.push_back(0);
      u16((uint16_t)pc); u16((uint16_t)cc); zeros(2);
      wbytes(path, pc); wbytes(cmdline, cc);
      break;
    case 2:   // Process_Exit
    case 8:   // Process_Statistics
      u32(0); zeros(48);   // exit status + 6x u64 (kernel/user/ws/peak/priv/peak)
      break;
    case 3:   // Thread_Create
      u32(0);
      break;
    case 4:   // Thread_Exit
      zeros(4); zeros(16); // pad + 2x u64 durations
      break;
    case 5:   // Load_Image
      zeros(8); u32(0); u16((uint16_t)pc); zeros(2); wbytes(path, pc);
      break;
    case 7:   // Process_Start
      u32(0); u16((uint16_t)cc); u16(0); u32(0);
      wbytes(cmdline, cc);  // command line; current dir empty; env multisz empty
      break;
    case 9:   // System_Statistics: Procmon requires >= 0x13C bytes
      zeros(0x13C);
      break;
    default:
      break;
  }
}

// Network (class 5) detail: flags + length + 16-byte src/dst IPs + ports, then
// an (empty) UTF-16 multi-sz of extra key/value pairs. Path is computed by the
// reader from the IPs; with zeros it renders as 0.0.0.0:0 -> 0.0.0.0:0.
void appendNetworkDetail(std::vector<uint8_t>& d, const Event& ev) {
  auto u16 = [&](uint16_t v) {
    d.insert(d.end(), (const uint8_t*)&v, (const uint8_t*)&v + 2);
  };
  u16(ev.netFlags);          // flags: bit0 src-ipv4, bit1 dst-ipv4, bit2 tcp
  u16(0);                    // pad
  d.insert(d.end(), (const uint8_t*)&ev.ioLength,
           (const uint8_t*)&ev.ioLength + 4);           // length
  d.insert(d.end(), ev.netSrcIp, ev.netSrcIp + 16);     // source ip (net order)
  d.insert(d.end(), ev.netDstIp, ev.netDstIp + 16);     // dest ip
  u16(ev.netSrcPort);        // source port (host order; reader prints as-is)
  u16(ev.netDstPort);        // dest port
  d.insert(d.end(), 4, 0);   // empty extra multi-sz (double NUL)
}

// Profiling (class 4) detail: Process_Profiling (op 1) = 4x u64;
// Thread_Profiling (op 0) = 3x u32 (reader sets path to "Thread <tid>").
void appendProfilingDetail(std::vector<uint8_t>& d, uint16_t op) {
  if (op == 1) d.insert(d.end(), 32, 0);
  else if (op == 0) d.insert(d.end(), 12, 0);
  else if (op == 2) d.insert(d.end(), 2, 0);  // Debug Output: u16 string info (empty)
}

// Some operations deliver part of their detail in a separate "extra details"
// blob that the reader locates via the event's extra_details_offset. We place
// it immediately after the event's main details (gap 0), as [u16 size][bytes].
// Returns the extra bytes (empty when the op has none).
std::vector<uint8_t> buildExtraDetails(const Event& ev) {
  std::vector<uint8_t> x;
  auto u32 = [&](uint32_t v) {
    x.insert(x.end(), (const uint8_t*)&v, (const uint8_t*)&v + 4);
  };
  if (ev.eventClass == 2 && ev.operation == 5 && !ev.valueData.empty() &&
      ev.regType < 12) {
    // RegQueryValue result (KeyValuePartialInformation): 4 pad, type, length,
    // data. The main detail already declares information_class = 2 (partial).
    x.insert(x.end(), 4, 0);
    u32(ev.regType);
    u32((uint32_t)ev.valueData.size());
    x.insert(x.end(), ev.valueData.begin(), ev.valueData.end());
  } else if (ev.eventClass == 2 && (ev.operation == 0 || ev.operation == 1) &&
             ev.completed && (ev.information == 1 || ev.information == 2)) {
    // RegOpenKey/RegCreateKey: {u32 granted access; u32 disposition}
    // (REG_CREATED_NEW_KEY / REG_OPENED_EXISTING_KEY from the completion).
    // Granted access isn't captured; 0.
    u32(0);
    u32((uint32_t)ev.information);
  } else if (ev.eventClass == 3 && ev.operation == 20 && ev.completed) {
    // CreateFile OpenResult (u32) from the completion's IoStatus.Information.
    u32((uint32_t)ev.information);
  } else if ((ev.eventClass == 3 || ev.eventClass == 6) && ev.operation == 25 &&
             ev.fsSubOp == 9) {
    // QueryNameInformationFile: real logs carry the FILE_NAME_INFORMATION
    // result {u32 FileNameLength; WCHAR[]} here and readers expect it
    // unconditionally. The FS completion buffer isn't captured, so emit an
    // empty name.
    u32(0);
  }
  return x;
}

struct ProcRec {
  uint32_t idx = 0;
  uint32_t pid = 0;
  uint32_t ppid = 0;
  uint32_t integrity = 0;
  uint32_t user = 0;
  uint32_t processName = 0;
  uint32_t imagePath = 0;
  uint32_t cmdline = 0;
  uint32_t company = 0;
  uint32_t version = 0;
  uint32_t description = 0;
};

// True if the writer can frame this event's class (Procmon readers parse every
// event's detail, so an unframed one - class 0 completions from `--raw`, or an
// unknown class - would desync the whole file).
// Op ranges are the reader's per-class limits.
bool pmlWritable(const Event& ev) {
  switch (ev.eventClass) {
    case 1: return ev.operation <= 9;    // Process
    case 2: return ev.operation <= 21;   // Registry
    case 3:
    case 6: return ev.operation < 48;    // File System / IPC
    case 4: return ev.operation <= 2;    // Profiling
    case 5: return ev.operation <= 9;    // Network
    default: return false;
  }
}

// A process record from `ev` is "resolved" when the driver's process table knew
// the index at decode time (else decode left pid 0 / name "idx#N").
bool procResolved(const Event& ev) {
  return ev.pid != 0 || ev.processName.rfind(L"idx#", 0) != 0;
}

}  // namespace

std::error_code savePml(const wchar_t* path, const std::vector<Event>& all) {
  std::vector<const Event*> events;
  events.reserve(all.size());
  for (const Event& ev : all)
    if (pmlWritable(ev)) events.push_back(&ev);
  // Procmon's log view assumes events are stored in chronological order (its
  // own writer appends them as they happen). Ours arrive in completion order
  // (the Pairer emits a request when its completion lands), and out-of-order
  // records render as blank "hole" rows in Procmon. Order by time, then by
  // driver sequence for ties.
  std::stable_sort(events.begin(), events.end(),
                   [](const Event* a, const Event* b) {
                     if (a->timestamp != b->timestamp)
                       return a->timestamp < b->timestamp;
                     return a->sequence < b->sequence;
                   });

  // --- Step A: string interning (process fields only). ---
  std::vector<std::wstring> strings;
  std::unordered_map<std::wstring, uint32_t> index;
  auto intern = [&](const std::wstring& s) -> uint32_t {
    auto it = index.find(s);
    if (it != index.end()) return it->second;
    uint32_t id = (uint32_t)strings.size();
    strings.push_back(s);
    index.emplace(s, id);
    return id;
  };
  intern(L"");  // index 0 = empty string

  // --- Step B: collect distinct processes, first-seen order. A record first
  // built from an unresolved event ("idx#N", pid 0) is replaced by the first
  // resolved event for the same index. ---
  std::vector<ProcRec> processes;
  std::unordered_map<uint32_t, size_t> seenProcIdx;  // processIndex -> slot
  std::vector<bool> slotResolved;
  for (const Event* pev : events) {
    const Event& ev = *pev;
    auto seen = seenProcIdx.find(ev.processIndex);
    const bool resolved = procResolved(ev);
    if (seen != seenProcIdx.end() &&
        (slotResolved[seen->second] || !resolved))
      continue;
    ProcRec pr;
    pr.idx = ev.processIndex;
    pr.pid = ev.pid;
    pr.ppid = ev.parentPid;
    pr.integrity = intern(ev.integrity);
    pr.user = intern(ev.user);
    pr.processName = intern(ev.processName);
    pr.imagePath = intern(ev.imagePath);
    pr.cmdline = intern(ev.commandLine);
    pr.company = intern(L"");
    pr.version = intern(L"");
    pr.description = intern(L"");
    if (seen != seenProcIdx.end()) {
      processes[seen->second] = pr;
      slotResolved[seen->second] = true;
      continue;
    }
    seenProcIdx.emplace(ev.processIndex, processes.size());
    processes.push_back(pr);
    slotResolved.push_back(resolved);
  }

  // Procmon's loader requires process-table indexes to be STRICTLY ascending
  // ; first-seen order is rejected as corrupt.
  std::sort(processes.begin(), processes.end(),
            [](const ProcRec& a, const ProcRec& b) { return a.idx < b.idx; });

  // --- Step C: lay out sections. ---
  // Section order matches real Procmon files: readers (procmon-parser) infer
  // each section's size from the *next* section's offset, so events -> events
  // offset array -> process table -> strings -> icons -> hosts must be adjacent
  // and in this order.
  std::vector<uint8_t> buf;
  buf.resize(0x3A8, 0);  // header, patched at the end

  // 1. Events array (fixed 0x34-byte records, no stacks, no detail).
  const uint64_t eventsArrayOffset = buf.size();
  std::vector<uint32_t> eventOffsets;
  eventOffsets.reserve(events.size());
  for (const Event* pev : events) {
    const Event& ev = *pev;
    if (buf.size() > UINT32_MAX) return errc(ERROR_FILE_TOO_LARGE);  // u32 offsets
    eventOffsets.push_back((uint32_t)buf.size());
    // Build the operation-specific detail blob.
    std::vector<uint8_t> detail;
    if (ev.eventClass == 2) appendRegDetail(detail, ev);
    else if (ev.eventClass == 3 || ev.eventClass == 6) appendFsDetail(detail, ev);
    else if (ev.eventClass == 1) {
      if (ev.operation == 0 || ev.operation == 1) {
        // The process the record DESCRIBES (for Process Create: the child, not
        // the creator). Pre-v6 logs lack target*: fall back to the event's own
        // process, which is right for op 0.
        const bool haveTarget = ev.targetPid != 0 || !ev.targetCmdline.empty();
        appendProcessDetail(detail, ev.operation,
                            haveTarget ? ev.path : ev.imagePath,
                            haveTarget ? ev.targetCmdline : ev.commandLine,
                            haveTarget ? ev.targetPid : ev.pid);
      } else {
        appendProcessDetail(detail, ev.operation, ev.path.empty() ? ev.imagePath : ev.path,
                            ev.commandLine, ev.pid);
      }
    }
    else if (ev.eventClass == 5) appendNetworkDetail(detail, ev);
    else if (ev.eventClass == 4) appendProfilingDetail(detail, ev.operation);
    std::vector<uint8_t> extra = buildExtraDetails(ev);
    // The reader finds the extra blob at extra_detail_offset counted from the
    // event start; with no stack frames it sits right after the details as
    // [u16 size][bytes], so the offset is 0x34 + detail size.
    const uint32_t extraOff =
        extra.empty() ? 0u : (uint32_t)(0x34 + detail.size());
    putU32(buf, ev.processIndex);
    putU32(buf, ev.tid);            // thread_id
    putU32(buf, ev.eventClass);
    putU16(buf, ev.operation);
    putZeros(buf, 6);
    putU64(buf, ev.duration);
    putU64(buf, ev.timestamp);
    putU32(buf, ev.result);
    putU16(buf, 0);                 // stack_depth
    putU16(buf, 0);                 // zero
    putU32(buf, (uint32_t)detail.size());  // detail_size
    putU32(buf, extraOff);          // extra_detail_offset
    buf.insert(buf.end(), detail.begin(), detail.end());
    if (!extra.empty()) {
      putU16(buf, (uint16_t)extra.size());
      buf.insert(buf.end(), extra.begin(), extra.end());
    }
  }

  // 2. Events offset array ({u32 file offset, u8 flags} per event).
  const uint64_t eventsOffsetArrayOffset = buf.size();
  for (uint32_t off : eventOffsets) {
    putU32(buf, off);
    putU8(buf, 0);  // flags
  }

  // 3. Process table.
  const uint64_t processTableOffset = buf.size();
  {
    uint32_t count = (uint32_t)processes.size();
    putU32(buf, count);
    for (const auto& p : processes) putU32(buf, p.idx);
    // Struct offsets are relative to the process-table start.
    const uint64_t relStructsStart = 4 + 4ull * count + 4ull * count;
    for (uint32_t i = 0; i < count; ++i)
      putU32(buf, (uint32_t)(relStructsStart + (uint64_t)i * kProcStructSize));
    for (const auto& p : processes) {
      putU32(buf, p.idx);
      putU32(buf, p.pid);
      putU32(buf, p.ppid);
      putU32(buf, 0);              // parent_process_index
      putU64(buf, 0);              // authentication_id
      putU32(buf, 0);              // session
      putU32(buf, 0);              // unknown
      putU64(buf, 0);              // start_time
      putU64(buf, 0);              // end_time
      putU32(buf, 0);              // virtualized
      putU32(buf, 1);              // is_process_64bit
      putU32(buf, p.integrity);
      putU32(buf, p.user);
      putU32(buf, p.processName);
      putU32(buf, p.imagePath);
      putU32(buf, p.cmdline);
      putU32(buf, p.company);
      putU32(buf, p.version);
      putU32(buf, p.description);
      putU32(buf, 0);              // icon_index_small
      putU32(buf, 0);              // icon_index_big
      // +0x60 (pvoid-sized): Procmon's loader requires the BYTE at struct+96
      //  to be 1, else the file is rejected as corrupt.
      putU8(buf, 1);
      putZeros(buf, 7);
      putU32(buf, 0);              // number_of_modules (64-byte entries follow)
    }
  }

  // 4. Strings table.
  const uint64_t stringsTableOffset = buf.size();
  {
    uint32_t count = (uint32_t)strings.size();
    putU32(buf, count);
    uint64_t rel = 4 + 4ull * count;  // first entry starts here, relative to table
    //  Procmon's loader requires each non-empty string's byte
    // size to INCLUDE a terminating NUL and the last wchar to be 0; a size that
    // excludes it makes the whole file "corrupt". Emit every string as
    // {u32 bytes incl. NUL; UTF-16 data; L'\0'}.
    for (const auto& s : strings) {
      putU32(buf, (uint32_t)rel);
      rel += 4 + 2ull * (s.size() + 1);
    }
    for (const auto& s : strings) {
      putU32(buf, (uint32_t)(2 * (s.size() + 1)));
      putW(buf, s);
      putU16(buf, 0);
    }
  }

  // 5. Icon table (empty).
  const uint64_t iconTableOffset = buf.size();
  putU32(buf, 0);

  // 6. Hosts/ports table (empty): a hostnames sub-table then a ports sub-table,
  // each just a zero count.
  const uint64_t hostsPortsOffset = buf.size();
  putU32(buf, 0);  // number_of_hostnames
  putU32(buf, 0);  // number_of_ports

  // --- Step D: patch the 936-byte header. ---
  patchBytes(buf, 0x00, "PML_", 4);
  patchU32(buf, 0x04, 9);   // format version
  patchU32(buf, 0x08, 1);   // is 64-bit

  const wchar_t* computerName = _wgetenv(L"COMPUTERNAME");
  patchWFixed(buf, 0x0C, computerName ? computerName : L"PMX", 16);
  patchWFixed(buf, 0x2C, L"C:\\Windows", 260);

  patchU32(buf, 0x234, (uint32_t)events.size());
  patchU64(buf, 0x238, 0);
  patchU64(buf, 0x240, eventsArrayOffset);
  patchU64(buf, 0x248, eventsOffsetArrayOffset);
  patchU64(buf, 0x250, processTableOffset);
  patchU64(buf, 0x258, stringsTableOffset);
  patchU64(buf, 0x260, iconTableOffset);
  patchU64(buf, 0x268, 0x7FFFFFFEFFFFull);  // max user address

  // OSVERSIONINFOEXW block: zero except size/major/minor/build.
  patchU32(buf, 0x270, 0x11C);
  patchU32(buf, 0x274, 10);
  patchU32(buf, 0x278, 0);
  patchU32(buf, 0x27C, 26100);

  patchU32(buf, 0x38C, 1);   // logical processors
  patchU64(buf, 0x390, 0);   // ram
  patchU64(buf, 0x398, 0x3A8);  // header size
  patchU64(buf, 0x3A0, hostsPortsOffset);

  return writeWholeFile(path, buf.data(), buf.size());
}

}  // namespace pmx
