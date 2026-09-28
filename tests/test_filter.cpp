#include "pmx/filter.h"

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "pmx/filter_json.h"
#include "pmx/filter_pmc.h"
#include "test_util.h"

namespace {
void putU32le(std::vector<uint8_t>& b, uint32_t v) {
  b.push_back(v & 0xFF);
  b.push_back((v >> 8) & 0xFF);
  b.push_back((v >> 16) & 0xFF);
  b.push_back((v >> 24) & 0xFF);
}
// Append one Procmon FilterRules record (col, rel, action, value + reserved).
void putRule(std::vector<uint8_t>& b, uint32_t col, uint32_t rel, uint8_t action,
             const wchar_t* value) {
  putU32le(b, col);
  putU32le(b, rel);
  b.push_back(action);
  uint32_t chars = (uint32_t)wcslen(value) + 1;  // include null
  putU32le(b, chars * 2);
  for (uint32_t i = 0; i < chars; ++i) {
    uint16_t c = (uint16_t)value[i];
    b.push_back(c & 0xFF);
    b.push_back((c >> 8) & 0xFF);
  }
  for (int i = 0; i < 8; ++i) b.push_back(0);  // reserved
}
}  // namespace

namespace {
pmx::Event mk(const wchar_t* name, uint32_t pid, const char* op,
              const wchar_t* path, uint32_t result) {
  pmx::Event e;
  e.processName = name;
  e.pid = pid;
  e.opName = op;
  e.path = path;
  e.result = result;
  e.className = "FileSystem";
  return e;
}
}  // namespace

int test_filter() {
  int before = g_failures;
  using namespace pmx;

  // Rule parsing.
  {
    auto r = parseRule(L"Path contains steam", Action::Include);
    CHECK(r.has_value());
    CHECK(r->column == Column::Path);
    CHECK(r->relation == Relation::Contains);
    CHECK(r->value == L"steam");
    CHECK(r->action == Action::Include);

    auto r2 = parseRule(L"op is CreateFile", Action::Exclude);
    CHECK(r2.has_value());
    CHECK(r2->column == Column::Operation);
    CHECK(r2->relation == Relation::Is);

    CHECK(!parseRule(L"Bogus contains x", Action::Include).has_value());
    CHECK(!parseRule(L"Path", Action::Include).has_value());
  }

  // Empty set: everything shows.
  {
    FilterSet fs;
    CHECK(fs.matches(mk(L"a.exe", 1, "ReadFile", L"C:\\a", 0)));
  }

  // Include-only: only matching events show.
  {
    FilterSet fs;
    fs.add(*parseRule(L"Path contains steam", Action::Include));
    CHECK(fs.matches(mk(L"s.exe", 1, "ReadFile", L"C:\\SteamLibrary\\x", 0)));
    CHECK(!fs.matches(mk(L"s.exe", 1, "ReadFile", L"C:\\Windows\\x", 0)));
  }

  // Exclude wins over include.
  {
    FilterSet fs;
    fs.add(*parseRule(L"Operation is ReadFile", Action::Include));
    fs.add(*parseRule(L"ProcessName is System", Action::Exclude));
    CHECK(fs.matches(mk(L"a.exe", 1, "ReadFile", L"p", 0)));
    CHECK(!fs.matches(mk(L"System", 4, "ReadFile", L"p", 0)));  // excluded
    CHECK(!fs.matches(mk(L"a.exe", 1, "WriteFile", L"p", 0)));  // no include match
  }

  // Procmon semantics: includes on the same column OR'd, different columns AND'd.
  {
    FilterSet fs;
    fs.add(*parseRule(L"ProcessName is a.exe", Action::Include));
    fs.add(*parseRule(L"ProcessName is b.exe", Action::Include));
    fs.add(*parseRule(L"Operation is WriteFile", Action::Include));
    CHECK(fs.matches(mk(L"a.exe", 1, "WriteFile", L"p", 0)));
    CHECK(fs.matches(mk(L"b.exe", 1, "WriteFile", L"p", 0)));
    CHECK(!fs.matches(mk(L"a.exe", 1, "ReadFile", L"p", 0)));   // op group fails
    CHECK(!fs.matches(mk(L"c.exe", 1, "WriteFile", L"p", 0)));  // name group fails
  }

  // IncludeMode::Any: every include OR'd regardless of column (old behaviour).
  {
    FilterSet fs;
    fs.setIncludeMode(IncludeMode::Any);
    fs.add(*parseRule(L"ProcessName is a.exe", Action::Include));
    fs.add(*parseRule(L"Operation is WriteFile", Action::Include));
    CHECK(fs.matches(mk(L"a.exe", 1, "ReadFile", L"p", 0)));
    CHECK(fs.matches(mk(L"z.exe", 1, "WriteFile", L"p", 0)));
    CHECK(!fs.matches(mk(L"z.exe", 1, "ReadFile", L"p", 0)));
  }

  // FilterGroup: lenses independent; Any = OR, All = AND. One lens's exclude
  // never suppresses another lens's include under Any.
  {
    FilterSet l1, l2;
    l1.add(*parseRule(L"ProcessName is a.exe", Action::Include));
    l2.add(*parseRule(L"Operation is WriteFile", Action::Include));
    l2.add(*parseRule(L"ProcessName is a.exe", Action::Exclude));
    FilterGroup g;
    g.addSet(l1);
    g.addSet(l2);
    CHECK(g.matches(mk(L"a.exe", 1, "WriteFile", L"p", 0)));  // via l1
    CHECK(g.matches(mk(L"b.exe", 1, "WriteFile", L"p", 0)));  // via l2
    CHECK(!g.matches(mk(L"b.exe", 1, "ReadFile", L"p", 0)));
    g.setMode(GroupMode::All);
    CHECK(!g.matches(mk(L"a.exe", 1, "WriteFile", L"p", 0)));  // l2 excludes
    FilterGroup g2;
    g2.setMode(GroupMode::All);
    FilterSet m1, m2;
    m1.add(*parseRule(L"ProcessName is b.exe", Action::Include));
    m2.add(*parseRule(L"Operation is WriteFile", Action::Include));
    g2.addSet(m1);
    g2.addSet(m2);
    CHECK(g2.matches(mk(L"b.exe", 1, "WriteFile", L"p", 0)));
    CHECK(!g2.matches(mk(L"b.exe", 1, "ReadFile", L"p", 0)));
  }

  // Mode parsing.
  CHECK(parseIncludeMode(L"any") == IncludeMode::Any);
  CHECK(parseIncludeMode(L"Procmon") == IncludeMode::PerColumn);
  CHECK(!parseIncludeMode(L"bogus").has_value());
  CHECK(parseGroupMode(L"ALL") == GroupMode::All);
  CHECK(parseGroupMode(L"or") == GroupMode::Any);

  // JSON: "match" key, UTF-8 BOM, numeric value, save round-trip.
  {
    wchar_t dir[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    std::wstring path = std::wstring(dir) + L"pmx_test_filter.json";
    const char body[] =
        "\xEF\xBB\xBF{ \"match\": \"any\", \"filters\": ["
        "{\"column\":\"PID\",\"relation\":\"is\",\"value\":1234,\"action\":\"include\"},"
        "{\"column\":\"Path\",\"relation\":\"contains\",\"value\":\"x\"} ] }";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD w = 0;
    WriteFile(h, body, sizeof body - 1, &w, nullptr);
    CloseHandle(h);
    FilterSet fs;
    CHECK(!loadFilterJson(path.c_str(), fs));
    CHECK(fs.includeMode() == IncludeMode::Any);
    CHECK(fs.rules().size() == 2);
    if (fs.rules().size() == 2) CHECK(fs.rules()[0].value == L"1234");
    CHECK(fs.matches(mk(L"a", 1234, "op", L"p", 0)));
    CHECK(!saveFilterJson(path.c_str(), fs));
    FilterSet back;
    CHECK(!loadFilterJson(path.c_str(), back));
    CHECK(back.includeMode() == IncludeMode::Any && back.rules().size() == 2);
    DeleteFileW(path.c_str());
  }

  // Malformed rules: rejected (not silently dropped/inverted), with a `why`
  // naming the 1-based rule index.
  {
    auto tryLoad = [](const char* body, std::string& why) {
      wchar_t dir[MAX_PATH];
      GetTempPathW(MAX_PATH, dir);
      std::wstring path = std::wstring(dir) + L"pmx_test_filter_bad.json";
      HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      DWORD w = 0;
      WriteFile(h, body, (DWORD)std::strlen(body), &w, nullptr);
      CloseHandle(h);
      FilterSet fs;
      std::error_code ec = loadFilterJson(path.c_str(), fs, &why);
      DeleteFileW(path.c_str());
      return ec;
    };

    // Unknown column.
    {
      std::string why;
      auto ec = tryLoad(
          "{ \"filters\": ["
          "{\"column\":\"Path\",\"relation\":\"is\",\"value\":\"x\"},"
          "{\"column\":\"Proces\",\"relation\":\"is\",\"value\":\"x\"} ] }",
          why);
      CHECK(ec);
      CHECK(why.find("rule 2") != std::string::npos);
      CHECK(why.find("Proces") != std::string::npos);
    }
    // Unknown relation.
    {
      std::string why;
      auto ec = tryLoad(
          "{ \"filters\": ["
          "{\"column\":\"Path\",\"relation\":\"bogus\",\"value\":\"x\"} ] }",
          why);
      CHECK(ec);
      CHECK(why.find("rule 1") != std::string::npos);
      CHECK(why.find("bogus") != std::string::npos);
    }
    // Bad action (typo doesn't silently invert to include).
    {
      std::string why;
      auto ec = tryLoad(
          "{ \"filters\": ["
          "{\"column\":\"Path\",\"relation\":\"is\",\"value\":\"x\",\"action\":\"exlude\"} ] }",
          why);
      CHECK(ec);
      CHECK(why.find("rule 1") != std::string::npos);
      CHECK(why.find("exlude") != std::string::npos);
      CHECK(why.find("include|exclude") != std::string::npos);
    }
    // Missing column.
    {
      std::string why;
      auto ec = tryLoad(
          "{ \"filters\": [ {\"relation\":\"is\",\"value\":\"x\"} ] }", why);
      CHECK(ec);
      CHECK(why.find("rule 1") != std::string::npos);
      CHECK(why.find("missing column") != std::string::npos);
    }
    // Action is accepted case-insensitively.
    {
      std::string why;
      auto ec = tryLoad(
          "{ \"filters\": ["
          "{\"column\":\"Path\",\"relation\":\"is\",\"value\":\"x\",\"action\":\"EXCLUDE\"},"
          "{\"column\":\"Path\",\"relation\":\"is\",\"value\":\"y\",\"action\":\"Include\"} ] }",
          why);
      CHECK(!ec);
    }
    // Missing action defaults to include.
    {
      std::string why;
      FilterSet fs;
      wchar_t dir[MAX_PATH];
      GetTempPathW(MAX_PATH, dir);
      std::wstring path = std::wstring(dir) + L"pmx_test_filter_defact.json";
      const char body[] =
          "{ \"filters\": [ {\"column\":\"Path\",\"relation\":\"is\",\"value\":\"x\"} ] }";
      HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      DWORD w = 0;
      WriteFile(h, body, sizeof body - 1, &w, nullptr);
      CloseHandle(h);
      CHECK(!loadFilterJson(path.c_str(), fs, &why));
      DeleteFileW(path.c_str());
      CHECK(fs.rules().size() == 1);
      if (fs.rules().size() == 1) CHECK(fs.rules()[0].action == Action::Include);
    }
  }

  // Every shipped hunt lens must still load cleanly.
  {
    std::wstring dir = std::wstring(L"" PMX_SOURCE_DIR) + L"\\conf\\hunt";
    std::wstring pattern = dir + L"\\*.json";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    CHECK(h != INVALID_HANDLE_VALUE);
    int count = 0;
    if (h != INVALID_HANDLE_VALUE) {
      do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        FilterSet fs;
        std::string why;
        std::error_code ec = loadFilterJson(full.c_str(), fs, &why);
        CHECK(!ec);
        ++count;
      } while (FindNextFileW(h, &fd));
      FindClose(h);
    }
    CHECK(count > 0);
  }

  // Numeric isNot with a non-numeric value always matches; is never does.
  {
    FilterSet fs;
    fs.add(*parseRule(L"PID isNot abc", Action::Include));
    CHECK(fs.matches(mk(L"a", 5, "op", L"p", 0)));
    FilterSet fs2;
    fs2.add(*parseRule(L"PID is abc", Action::Include));
    CHECK(!fs2.matches(mk(L"a", 5, "op", L"p", 0)));
  }

  // Result vs a number = raw NTSTATUS ordering (--failed); names stay strings.
  {
    FilterSet fs;
    fs.add(*parseRule(L"Result moreThan 0xBFFFFFFF", Action::Include));
    CHECK(fs.matches(mk(L"a", 1, "op", L"p", 0xC0000034)));   // NAME_NOT_FOUND
    CHECK(!fs.matches(mk(L"a", 1, "op", L"p", 0x80000006)));  // NO_MORE_FILES
    CHECK(!fs.matches(mk(L"a", 1, "op", L"p", 0)));
    FilterSet hex;
    hex.add(*parseRule(L"PID is 0x10", Action::Include));
    CHECK(hex.matches(mk(L"a", 16, "op", L"p", 0)));
  }

  // Numeric relations on PID.
  {
    FilterSet fs;
    fs.add(*parseRule(L"PID morethan 1000", Action::Include));
    CHECK(fs.matches(mk(L"a", 2000, "ReadFile", L"p", 0)));
    CHECK(!fs.matches(mk(L"a", 500, "ReadFile", L"p", 0)));
  }

  // Result column matches the friendly status name.
  {
    FilterSet fs;
    fs.add(*parseRule(L"Result is NAME_NOT_FOUND", Action::Include));
    CHECK(fs.matches(mk(L"a", 1, "CreateFile", L"p", 0xC0000034)));
    CHECK(!fs.matches(mk(L"a", 1, "CreateFile", L"p", 0)));
  }

  // Relations: beginsWith / endsWith / excludes / isNot.
  {
    CHECK(FilterSet{}.matches(mk(L"x", 1, "op", L"p", 0)));
    FilterSet fs;
    fs.add(*parseRule(L"ProcessName endswith .exe", Action::Include));
    CHECK(fs.matches(mk(L"foo.exe", 1, "op", L"p", 0)));
    CHECK(!fs.matches(mk(L"foo.dll", 1, "op", L"p", 0)));
  }

  // statusName mapping.
  CHECK(statusName(0) == "SUCCESS");
  CHECK(statusName(0xC0000034) == "NAME_NOT_FOUND");
  CHECK(statusName(0x12345678) == "0x12345678");

  // Procmon FilterRules blob parsing (real column/relation/action codes).
  {
    std::vector<uint8_t> b;
    b.push_back(1);      // version
    putU32le(b, 3);      // rule count
    putRule(b, 0x9c75, 0, 1, L"nxc_ghost.exe");  // ProcessName is _ Include
    putRule(b, 0x9c77, 4, 1, L"IRP_MJ_");        // Operation beginsWith Include
    putRule(b, 0x9c87, 0, 0, L"$Mft");           // Path is $Mft Exclude
    FilterSet fs;
    CHECK(parseFilterBlob(b.data(), b.size(), fs));
    CHECK(fs.rules().size() == 3);
    if (fs.rules().size() == 3) {
      CHECK(fs.rules()[0].column == Column::ProcessName);
      CHECK(fs.rules()[0].relation == Relation::Is);
      CHECK(fs.rules()[0].value == L"nxc_ghost.exe");
      CHECK(fs.rules()[0].action == Action::Include);
      CHECK(fs.rules()[1].column == Column::Operation);
      CHECK(fs.rules()[1].relation == Relation::BeginsWith);
      CHECK(fs.rules()[1].value == L"IRP_MJ_");
      CHECK(fs.rules()[2].column == Column::Path);
      CHECK(fs.rules()[2].action == Action::Exclude);
    }
  }

  // Unmapped column codes and truncation are reported, not silently dropped.
  {
    std::vector<uint8_t> b;
    b.push_back(1);
    putU32le(b, 3);
    putRule(b, 0x9c75, 0, 1, L"a.exe");
    putRule(b, 0x9cff, 0, 1, L"x");  // unknown column
    FilterSet fs;
    std::vector<std::string> skipped;
    CHECK(parseFilterBlob(b.data(), b.size(), fs, &skipped));
    CHECK(fs.rules().size() == 1);
    CHECK(skipped.size() == 2);  // rule 2 unmapped, rule 3 missing
    if (skipped.size() == 2) {
      CHECK(skipped[0].find("rule 2") != std::string::npos);
      CHECK(skipped[1].find("truncated") != std::string::npos);
    }
  }

  // Procmon's spellings match our names.
  {
    FilterSet fs;
    fs.add(*parseRule(L"Result is NAME NOT FOUND", Action::Include));
    CHECK(fs.matches(mk(L"a", 1, "CreateFile", L"p", 0xC0000034)));
    Event ev = mk(L"a", 1, "CreateFile", L"p", 0);
    ev.className = "FileSystem";
    FilterSet cls;
    cls.add(*parseRule(L"Class is File System", Action::Include));
    CHECK(cls.matches(ev));
  }

  return g_failures - before;
}
