#pragma once
// Decoded, owned event — the unit that filters match, the store holds, and the
// UI/PML export render. Produced by decodeEvent() from a paired CompletedEvent
// plus the ProcessTable. Strings are plain (not interned) for simplicity; a
// StringPool can be layered in later if memory becomes a concern.

#include <cstdint>
#include <string>
#include <vector>

namespace pmx {

struct Event {
  uint32_t sequence = 0;
  uint64_t timestamp = 0;     // FILETIME (UTC, 100ns)
  uint32_t processIndex = 0;  // Procmon process-table index
  uint32_t pid = 0;
  uint32_t parentPid = 0;
  uint32_t tid = 0;           // originating thread id
  uint16_t eventClass = 0;    // proto::EventClass
  uint16_t operation = 0;     // per-class op code
  uint32_t result = 0;        // final NTSTATUS (paired), or the request's own
  uint64_t information = 0;    // completion IoStatus.Information
  uint64_t duration = 0;       // completion - request time (100ns); 0 if none
  bool completed = false;     // a class-0 completion was matched

  std::wstring processName;   // image basename (e.g. "svchost.exe")
  std::wstring imagePath;     // full image path (if known)
  std::wstring commandLine;   // command line (if known)
  std::wstring user;          // token user "DOMAIN\\name" (if known)
  std::wstring integrity;     // integrity level (if known)
  std::string  opName;        // friendly operation name (ASCII)
  std::string  className;     // "FileSystem" / "Registry" / ...
  std::wstring path;          // object path (file / registry key)
  std::wstring detail;        // formatted detail column (Offset/Length/Access/…)

  // Raw detail fields (populated by decodeEvent, consumed by the PML writer for
  // the Detail column). Zero/empty when not applicable to the event.
  uint32_t desiredAccess = 0;   // registry RegOpenKey/RegCreateKey desired access mask
  uint32_t regType = 0;         // registry value type (REG_*) for Set/QueryValue
  uint32_t regLength = 0;       // registry value full data length in bytes
  std::vector<uint8_t> valueData;  // registry value data bytes (Set/QueryValue)

  // Raw file-system detail (CreateFile + Read/Write), for the PML Detail column.
  uint32_t fsDisposition = 0;   // CreateFile disposition (0..5)
  uint32_t fsOptions = 0;       // CreateFile create options (low 24 bits)
  uint32_t fsAllocation = 0;    // CreateFile allocation size
  uint16_t fsAttributes = 0;    // CreateFile attributes
  uint16_t fsShareMode = 0;     // CreateFile share mode
  // FS/IPC sub-operation discriminator = the driver detail's first byte
  // (FILE_INFORMATION_CLASS / FS_INFORMATION_CLASS / IRP minor). Procmon names
  // ops that have a sub-op table (QueryInformationFile, DirectoryControl, ...)
  // by looking it up; a wrong value shows as "<Unknown>".
  uint8_t fsSubOp = 0;
  uint64_t ioOffset = 0;        // ReadFile/WriteFile offset
  uint32_t ioLength = 0;        // ReadFile/WriteFile length

  // Process Defined / Create (class 1, op 0/1): the process the record
  // DESCRIBES. For op 1 that is the new child, while pid/processName above are
  // the creator. Image = `path`.
  uint32_t targetPid = 0;
  std::wstring targetCmdline;

  // Raw network detail (class 5), for the PML Detail column. IPs network order
  // (first 4 bytes for IPv4); ports host order. netFlags: bit0 src-ipv4,
  // bit1 dst-ipv4, bit2 tcp.
  uint8_t netSrcIp[16] = {};
  uint8_t netDstIp[16] = {};
  uint16_t netSrcPort = 0;
  uint16_t netDstPort = 0;
  uint8_t netFlags = 0;
};

}  // namespace pmx
