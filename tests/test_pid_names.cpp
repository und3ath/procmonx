#include "pmx/enrich/pid_names.h"

#include <windows.h>

#include <string>

#include "test_util.h"

namespace {
uint64_t nowFt() {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}
}  // namespace

int test_pid_names() {
  int before = g_failures;
  using namespace pmx;

  PidNameCache c;
  CHECK(c.lookup(0, 0) == L"Idle");
  CHECK(c.lookup(4, 0) == L"System");
  CHECK(c.lookup(GetCurrentProcessId(), 0) == L"pmx_tests.exe");
  // A PID nobody holds (not a multiple of 4 -> never a real PID).
  CHECK(c.lookup(0xFFFFFFF1u, 0) == L"PID 4294967281");

  // A real child: named while alive; after it exits, an event stamped BEFORE
  // the exit still maps to it (ETW delivers late).
  wchar_t cmd[] = L"cmd.exe /c exit 0";
  STARTUPINFOW si{sizeof si};
  PROCESS_INFORMATION pi{};
  if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                     CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si,
                     &pi)) {
    const uint64_t tAlive = nowFt();
    CHECK(c.lookup(pi.dwProcessId, tAlive) == L"cmd.exe");
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CHECK(c.lookup(pi.dwProcessId, tAlive) == L"cmd.exe");  // late event
    // After the exit with nothing new on the PID: keeps the old name rather
    // than flipping to "PID N" for stragglers.
    CHECK(c.lookup(pi.dwProcessId, nowFt() + 20'000'000ull) == L"cmd.exe");
  } else {
    CHECK(!"CreateProcess cmd.exe failed");
  }
  return g_failures - before;
}
