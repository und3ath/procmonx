#pragma once
// Symbolic decoders for FileSystem/Registry detail flag/enum fields, matching
// how Process Monitor renders them.
//
// ACCESS_MASK: Desired Access is formatted by greedy longest-first subtraction
// (for each table entry, if all of its bits are present, emit its name and clear
// them; leftover bits print as hex). Two tables are applied in sequence to one
// mask, after MapGenericMask: table1 = generic combos + file-specific rights,
// table2 = standard rights.

#include <cstdint>
#include <cstdio>
#include <string>

namespace pmx::proto {

// Expand the generic bits (GENERIC_READ/WRITE/EXECUTE/ALL) into the file
// specific + standard rights they map to, matching Procmon's GENERIC_MAPPING.
inline uint32_t mapGenericFileAccess(uint32_t m) noexcept {
  if (m & 0x80000000u) m = (m & ~0x80000000u) | 0x00120089u;  // GENERIC_READ
  if (m & 0x40000000u) m = (m & ~0x40000000u) | 0x00120116u;  // GENERIC_WRITE
  if (m & 0x20000000u) m = (m & ~0x20000000u) | 0x001200A0u;  // GENERIC_EXECUTE
  if (m & 0x10000000u) m = (m & ~0x10000000u) | 0x001F01FFu;  // GENERIC_ALL
  return m;
}

// Format an NT file ACCESS_MASK the way Procmon renders "Desired Access".
inline std::string accessMaskString(uint32_t mask) {
  struct Entry {
    uint32_t bits;
    const char* name;
  };
  // Order matters: broadest combos first so they collapse (e.g. 0x120089 →
  // "Generic Read" instead of its six constituent rights).
  static const Entry kTable1[] = {
      {0x1F01FF, "All Access"},
      {0x1201BF, "Generic Read/Write/Execute"},
      {0x12019F, "Generic Read/Write"},
      {0x1200A9, "Generic Read/Execute"},
      {0x1201B6, "Generic Write/Execute"},
      {0x120089, "Generic Read"},
      {0x120116, "Generic Write"},
      {0x1200A0, "Generic Execute"},
      {0x000001, "Read Data/List Directory"},
      {0x000002, "Write Data/Add File"},
      {0x000004, "Append Data/Add Subdirectory/Create Pipe Instance"},
      {0x000008, "Read EA"},
      {0x000010, "Write EA"},
      {0x000020, "Execute/Traverse"},
      {0x000040, "Delete Child"},
      {0x000080, "Read Attributes"},
      {0x000100, "Write Attributes"},
  };
  static const Entry kTable2[] = {
      {0x0010000, "Delete"},
      {0x0020000, "Read Control"},
      {0x0040000, "Write DAC"},
      {0x0080000, "Write Owner"},
      {0x0100000, "Synchronize"},
      {0x1000000, "Access System Security"},
      {0x2000000, "Maximum Allowed"},
  };

  uint32_t rem = mapGenericFileAccess(mask);
  std::string out;
  auto pass = [&](const Entry* t, size_t n) {
    for (size_t i = 0; i < n; ++i) {
      if (t[i].bits && (rem & t[i].bits) == t[i].bits) {
        if (!out.empty()) out += ", ";
        out += t[i].name;
        rem &= ~t[i].bits;
      }
    }
  };
  pass(kTable1, sizeof kTable1 / sizeof *kTable1);
  pass(kTable2, sizeof kTable2 / sizeof *kTable2);
  if (rem) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%X", rem);
    if (!out.empty()) out += ", ";
    out += b;
  }
  if (out.empty()) out = "None";
  return out;
}

// Format NtCreateFile CreateOptions (FILE_* flags) as the "Options" column.
inline std::string createOptionsString(uint32_t opts) {
  struct Entry {
    uint32_t bits;
    const char* name;
  };
  static const Entry kOpts[] = {
      {0x00000001, "Directory"},
      {0x00000002, "Write Through"},
      {0x00000004, "Sequential Access"},
      {0x00000008, "No Buffering"},
      {0x00000010, "Synchronous IO Alert"},
      {0x00000020, "Synchronous IO Non-Alert"},
      {0x00000040, "Non-Directory File"},
      {0x00000080, "Create Tree Connection"},
      {0x00000100, "Complete If Oplocked"},
      {0x00000200, "No EA Knowledge"},
      {0x00000400, "Open for Recovery"},
      {0x00000800, "Random Access"},
      {0x00001000, "Delete On Close"},
      {0x00002000, "Open By ID"},
      {0x00004000, "Open For Backup"},
      {0x00008000, "No Compression"},
      {0x00100000, "Reserve OpFilter"},
      {0x00200000, "Open Reparse Point"},
      {0x00400000, "Open No Recall"},
      {0x00800000, "Open For Free Space Query"},
      {0x01000000, "Open Requiring Oplock"},
      {0x02000000, "Disallow Exclusive"},
  };
  uint32_t rem = opts;
  std::string out;
  for (const auto& e : kOpts) {
    if ((rem & e.bits) == e.bits) {
      if (!out.empty()) out += ", ";
      out += e.name;
      rem &= ~e.bits;
    }
  }
  if (rem) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%X", rem);
    if (!out.empty()) out += ", ";
    out += b;
  }
  if (out.empty()) out = "None";
  return out;
}

// Registry KEY ACCESS_MASK -> the "Desired Access" column for RegOpenKey /
// RegCreateKey (KEY rights + standard rights, after the KEY GENERIC_MAPPING).
inline uint32_t mapGenericKeyAccess(uint32_t m) noexcept {
  if (m & 0x80000000u) m = (m & ~0x80000000u) | 0x00020019u;  // KEY GENERIC_READ
  if (m & 0x40000000u) m = (m & ~0x40000000u) | 0x00020006u;  // GENERIC_WRITE
  if (m & 0x20000000u) m = (m & ~0x20000000u) | 0x00020019u;  // GENERIC_EXECUTE
  if (m & 0x10000000u) m = (m & ~0x10000000u) | 0x000F003Fu;  // GENERIC_ALL
  return m;
}

inline std::string keyAccessString(uint32_t mask) {
  struct Entry {
    uint32_t bits;
    const char* name;
  };
  static const Entry kKey[] = {
      {0x000F003F, "All Access"},   {0x0002001F, "Read/Write"},
      {0x00020019, "Read"},         {0x00020006, "Write"},
      {0x00000001, "Query Value"},  {0x00000002, "Set Value"},
      {0x00000004, "Create Sub Key"}, {0x00000008, "Enumerate Sub Keys"},
      {0x00000010, "Notify"},       {0x00000020, "Create Link"},
      {0x00000300, "WOW64_Res"},    {0x00000200, "WOW64_32Key"},
      {0x00000100, "WOW64_64Key"},
  };
  static const Entry kStd[] = {
      {0x00010000, "Delete"},        {0x00020000, "Read Control"},
      {0x00040000, "Write DAC"},     {0x00080000, "Write Owner"},
      {0x00100000, "Synchronize"},   {0x01000000, "Access System Security"},
      {0x02000000, "Maximum Allowed"},
  };
  uint32_t rem = mapGenericKeyAccess(mask);
  std::string out;
  auto pass = [&](const Entry* t, size_t n) {
    for (size_t i = 0; i < n; ++i)
      if (t[i].bits && (rem & t[i].bits) == t[i].bits) {
        if (!out.empty()) out += ", ";
        out += t[i].name;
        rem &= ~t[i].bits;
      }
  };
  pass(kKey, sizeof kKey / sizeof *kKey);
  pass(kStd, sizeof kStd / sizeof *kStd);
  if (rem) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%X", rem);
    if (!out.empty()) out += ", ";
    out += b;
  }
  return out.empty() ? "None" : out;
}

// RegCreateKey disposition from the completion's Information.
inline const char* regDispositionString(uint64_t info) noexcept {
  switch (info) {
    case 1: return "REG_CREATED_NEW_KEY";
    case 2: return "REG_OPENED_EXISTING_KEY";
    default: return "";
  }
}

// CreateFile OpenResult (IoStatus.Information after NtCreateFile), from the
// paired completion.
inline const char* openResultString(uint64_t info) noexcept {
  switch (info) {
    case 0: return "Superseded";
    case 1: return "Opened";
    case 2: return "Created";
    case 3: return "Overwritten";
    case 4: return "Exists";
    case 5: return "DoesNotExist";
    default: return "<unknown>";
  }
}

// Registry value type (REG_*); index = the type dword. >= 12 → "<Unknown>".
inline const char* regTypeName(uint32_t t) noexcept {
  static const char* const k[] = {
      "REG_NONE",         "REG_SZ",
      "REG_EXPAND_SZ",    "REG_BINARY",
      "REG_DWORD",        "REG_DWORD_BIG_ENDIAN",
      "REG_LINK",         "REG_MULTI_SZ",
      "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR",
      "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD"};
  return t < 12 ? k[t] : "<Unknown>";
}

// NtCreateFile CreateDisposition (the top byte of +0x18).
inline const char* createDispositionString(uint8_t d) noexcept {
  switch (d) {
    case 0: return "Supersede";
    case 1: return "Open";
    case 2: return "Create";
    case 3: return "OpenIf";
    case 4: return "Overwrite";
    case 5: return "OverwriteIf";
    default: return "<unknown>";
  }
}

// FILE_ATTRIBUTE_* mask → concatenated short codes (empty separator, 0 → "n/a").
inline std::string fileAttributesString(uint16_t attr) {
  if (attr == 0) return "n/a";
  struct Entry {
    uint16_t bits;
    const char* code;
  };
  static const Entry kAttr[] = {
      {0x0001, "R"},   {0x0002, "H"},  {0x0004, "S"},   {0x0010, "D"},
      {0x0020, "A"},   {0x0040, "D"},  {0x0080, "N"},   {0x0100, "T"},
      {0x0200, "SF"},  {0x0400, "RP"}, {0x0800, "C"},   {0x1000, "O"},
      {0x2000, "NCI"}, {0x4000, "E"},
  };  // 0x10000 (Virtual) is 32-bit; only the low u16 is read here.
  uint32_t rem = attr;
  std::string out;
  for (const auto& e : kAttr) {
    if ((rem & e.bits) == e.bits) {
      out += e.code;
      rem &= ~static_cast<uint32_t>(e.bits);
    }
  }
  if (rem) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%X", rem);
    out += b;
  }
  return out.empty() ? "n/a" : out;
}

// FILE_SHARE_* mask (", " separator, 0 → "None").
inline std::string shareModeString(uint16_t share) {
  static const struct {
    uint16_t bits;
    const char* name;
  } kShare[] = {{1, "Read"}, {2, "Write"}, {4, "Delete"}};
  uint32_t rem = share;
  std::string out;
  for (const auto& e : kShare) {
    if ((rem & e.bits) == e.bits) {
      if (!out.empty()) out += ", ";
      out += e.name;
      rem &= ~static_cast<uint32_t>(e.bits);
    }
  }
  if (rem) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%X", rem);
    if (!out.empty()) out += ", ";
    out += b;
  }
  return out.empty() ? "None" : out;
}

}  // namespace pmx::proto
