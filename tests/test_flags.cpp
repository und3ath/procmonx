#include "pmx/driver/flags.h"

#include <string>

#include "test_util.h"

int test_flags() {
  int before = g_failures;
  using pmx::proto::accessMaskString;

  // Combined generics collapse to a single friendly name.
  CHECK(accessMaskString(0x00120089) == "Generic Read");
  CHECK(accessMaskString(0x00120116) == "Generic Write");
  CHECK(accessMaskString(0x001200A0) == "Generic Execute");
  CHECK(accessMaskString(0x001F01FF) == "All Access");

  // Generic bits map through MapGenericMask, then collapse.
  CHECK(accessMaskString(0x80000000) == "Generic Read");     // GENERIC_READ
  CHECK(accessMaskString(0x10000000) == "All Access");       // GENERIC_ALL

  // Individual rights across both tables, joined by ", ".
  CHECK(accessMaskString(0x00100001) ==
        "Read Data/List Directory, Synchronize");
  CHECK(accessMaskString(0x00000080) == "Read Attributes");
  CHECK(accessMaskString(0x00010000) == "Delete");

  // Leftover unknown bits render as hex; zero mask is "None".
  CHECK(accessMaskString(0x00000000) == "None");
  CHECK(accessMaskString(0x00000200) == "0x200");
  CHECK(accessMaskString(0x00000201) == "Read Data/List Directory, 0x200");

  using pmx::proto::createOptionsString;
  CHECK(createOptionsString(0x00000000) == "None");
  CHECK(createOptionsString(0x00000001) == "Directory");
  CHECK(createOptionsString(0x00000020) == "Synchronous IO Non-Alert");
  CHECK(createOptionsString(0x00000044) ==
        "Sequential Access, Non-Directory File");
  CHECK(createOptionsString(0x00001000) == "Delete On Close");
  CHECK(createOptionsString(0x00080000) == "0x80000");  // reserved bit -> hex

  using pmx::proto::createDispositionString;
  CHECK(std::string(createDispositionString(0)) == "Supersede");
  CHECK(std::string(createDispositionString(1)) == "Open");
  CHECK(std::string(createDispositionString(3)) == "OpenIf");
  CHECK(std::string(createDispositionString(5)) == "OverwriteIf");
  CHECK(std::string(createDispositionString(9)) == "<unknown>");

  using pmx::proto::fileAttributesString;
  CHECK(fileAttributesString(0) == "n/a");
  CHECK(fileAttributesString(0x20) == "A");            // Archive
  CHECK(fileAttributesString(0x01) == "R");            // Readonly
  CHECK(fileAttributesString(0x21) == "RA");           // Readonly+Archive
  CHECK(fileAttributesString(0x80) == "N");            // Normal
  CHECK(fileAttributesString(0x200) == "SF");          // SparseFile

  using pmx::proto::shareModeString;
  CHECK(shareModeString(0) == "None");
  CHECK(shareModeString(1) == "Read");
  CHECK(shareModeString(7) == "Read, Write, Delete");
  CHECK(shareModeString(5) == "Read, Delete");

  using pmx::proto::keyAccessString;
  CHECK(keyAccessString(0xF003F) == "All Access");
  CHECK(keyAccessString(0x20019) == "Read");
  CHECK(keyAccessString(0x20006) == "Write");
  CHECK(keyAccessString(0x1) == "Query Value");
  CHECK(keyAccessString(0x8) == "Enumerate Sub Keys");
  CHECK(keyAccessString(0x80000000) == "Read");  // generic-read maps through
  using pmx::proto::regDispositionString;
  CHECK(std::string(regDispositionString(1)) == "REG_CREATED_NEW_KEY");
  CHECK(std::string(regDispositionString(2)) == "REG_OPENED_EXISTING_KEY");

  using pmx::proto::regTypeName;
  CHECK(std::string(regTypeName(0)) == "REG_NONE");
  CHECK(std::string(regTypeName(1)) == "REG_SZ");
  CHECK(std::string(regTypeName(4)) == "REG_DWORD");
  CHECK(std::string(regTypeName(11)) == "REG_QWORD");
  CHECK(std::string(regTypeName(99)) == "<Unknown>");

  return g_failures - before;
}
