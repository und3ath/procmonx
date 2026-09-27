#include "pmx/driver/driver_controller.h"

#include <windows.h>
#include <fltuser.h>

#include <cwchar>

namespace pmx {

namespace {
std::error_code hres(HRESULT hr) {
  const int win32 = HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr)
                                                           : static_cast<int>(hr);
  return {win32, std::system_category()};
}
}  // namespace

std::vector<LoadedFilter> DriverController::loadedFilters(std::error_code& ec) {
  std::vector<LoadedFilter> out;
  ec = {};

  std::vector<uint8_t> buf(1024);
  HANDLE find = nullptr;
  DWORD needed = 0;
  HRESULT hr = FilterFindFirst(FilterFullInformation, buf.data(),
                               static_cast<DWORD>(buf.size()), &needed, &find);
  if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
    buf.resize(needed);
    hr = FilterFindFirst(FilterFullInformation, buf.data(),
                         static_cast<DWORD>(buf.size()), &needed, &find);
  }
  if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) return out;
  if (FAILED(hr)) {
    ec = hres(hr);
    return out;
  }

  auto append = [&out](const uint8_t* data) {
    const auto* info = reinterpret_cast<const FILTER_FULL_INFORMATION*>(data);
    LoadedFilter f;
    f.frameId = info->FrameID;
    f.instances = info->NumberOfInstances;
    f.name.assign(info->FilterNameBuffer,
                  info->FilterNameLength / sizeof(wchar_t));
    out.push_back(std::move(f));
  };
  append(buf.data());

  for (;;) {
    needed = 0;
    hr = FilterFindNext(find, FilterFullInformation, buf.data(),
                        static_cast<DWORD>(buf.size()), &needed);
    if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
      buf.resize(needed);
      hr = FilterFindNext(find, FilterFullInformation, buf.data(),
                          static_cast<DWORD>(buf.size()), &needed);
    }
    if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) break;
    if (FAILED(hr)) {
      ec = hres(hr);
      break;
    }
    append(buf.data());
  }
  FilterFindClose(find);
  return out;
}

std::optional<std::wstring> DriverController::loadedProcmonName(
    std::error_code& ec) {
  const auto filters = loadedFilters(ec);
  if (ec) return std::nullopt;
  for (const auto& f : filters)
    if (_wcsnicmp(f.name.c_str(), L"PROCMON", 7) == 0) return f.name;
  return std::nullopt;
}

bool DriverController::enablePrivilege(const wchar_t* name) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    return false;
  TOKEN_PRIVILEGES tp{};
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  bool ok = LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid) != 0;
  if (ok) {
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    ok = GetLastError() == ERROR_SUCCESS;  // NOT_ALL_ASSIGNED => token lacks it
  }
  CloseHandle(token);
  return ok;
}

std::error_code DriverController::load(const wchar_t* serviceName) {
  enablePrivilege(SE_LOAD_DRIVER_NAME);
  const HRESULT hr = FilterLoad(serviceName);
  return FAILED(hr) ? hres(hr) : std::error_code{};
}

std::error_code DriverController::unload(const wchar_t* serviceName) {
  enablePrivilege(SE_LOAD_DRIVER_NAME);
  const HRESULT hr = FilterUnload(serviceName);
  return FAILED(hr) ? hres(hr) : std::error_code{};
}

namespace {
std::error_code lastError() {
  return {static_cast<int>(GetLastError()), std::system_category()};
}
}  // namespace

std::error_code DriverController::installService(const wchar_t* serviceName,
                                                 const wchar_t* sysPath,
                                                 const wchar_t* altitude) {
  // ImagePath as an NT path so it resolves regardless of drive mapping.
  const std::wstring image = std::wstring(L"\\??\\") + sysPath;

  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (!scm) return lastError();

  SC_HANDLE svc = CreateServiceW(
      scm, serviceName, serviceName, SERVICE_ALL_ACCESS,
      SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
      image.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
  std::error_code ec{};
  if (!svc) {
    const DWORD e = GetLastError();
    if (e != ERROR_SERVICE_EXISTS) {
      CloseServiceHandle(scm);
      return {static_cast<int>(e), std::system_category()};
    }
    // Already registered (earlier run, possibly from another build dir): point
    // its ImagePath at the current .sys so FilterLoad doesn't hit a stale path.
    svc = OpenServiceW(scm, serviceName, SERVICE_CHANGE_CONFIG);
    if (!svc ||
        !ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                              SERVICE_NO_CHANGE, image.c_str(), nullptr,
                              nullptr, nullptr, nullptr, nullptr, nullptr))
      ec = lastError();
    if (svc) CloseServiceHandle(svc);
  } else {
    CloseServiceHandle(svc);
  }
  CloseServiceHandle(scm);
  if (ec) return ec;

  // Minifilter registration: Instances subkey with a default instance + altitude.
  wchar_t key[256];
  swprintf(key, 256,
           L"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances", serviceName);
  HKEY hInst = nullptr;
  LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, nullptr, 0, KEY_WRITE,
                           nullptr, &hInst, nullptr);
  if (r != ERROR_SUCCESS) return {static_cast<int>(r), std::system_category()};

  const wchar_t* defInstance = L"ProcMon Instance";
  RegSetValueExW(hInst, L"DefaultInstance", 0, REG_SZ,
                 reinterpret_cast<const BYTE*>(defInstance),
                 static_cast<DWORD>((wcslen(defInstance) + 1) * sizeof(wchar_t)));

  HKEY hOne = nullptr;
  r = RegCreateKeyExW(hInst, defInstance, 0, nullptr, 0, KEY_WRITE, nullptr,
                      &hOne, nullptr);
  if (r == ERROR_SUCCESS) {
    RegSetValueExW(hOne, L"Altitude", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(altitude),
                   static_cast<DWORD>((wcslen(altitude) + 1) * sizeof(wchar_t)));
    DWORD flags = 0;
    RegSetValueExW(hOne, L"Flags", 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&flags), sizeof(flags));
    RegCloseKey(hOne);
  }
  RegCloseKey(hInst);
  return ec;
}

std::error_code DriverController::removeService(const wchar_t* serviceName) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!scm) return lastError();
  SC_HANDLE svc = OpenServiceW(scm, serviceName, DELETE);
  std::error_code ec{};
  if (!svc) {
    ec = lastError();
  } else {
    if (!DeleteService(svc)) ec = lastError();
    CloseServiceHandle(svc);
  }
  CloseServiceHandle(scm);
  return ec;
}

std::error_code DriverController::attachAllVolumes(const wchar_t* serviceName,
                                                   int* attached) {
  if (attached) *attached = 0;
  std::vector<uint8_t> buf(1024);
  HANDLE find = nullptr;
  DWORD needed = 0;
  HRESULT hr = FilterVolumeFindFirst(FilterVolumeBasicInformation, buf.data(),
                                     static_cast<DWORD>(buf.size()), &needed,
                                     &find);
  if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
    buf.resize(needed);
    hr = FilterVolumeFindFirst(FilterVolumeBasicInformation, buf.data(),
                               static_cast<DWORD>(buf.size()), &needed, &find);
  }
  if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) return {};
  if (FAILED(hr)) return hres(hr);

  std::error_code firstErr{};
  auto attachOne = [&](const uint8_t* data) {
    const auto* v = reinterpret_cast<const FILTER_VOLUME_BASIC_INFORMATION*>(data);
    std::wstring vol(v->FilterVolumeName,
                     v->FilterVolumeNameLength / sizeof(wchar_t));
    const HRESULT ah =
        FilterAttach(serviceName, vol.c_str(), nullptr, 0, nullptr);
    if (SUCCEEDED(ah)) {
      if (attached) ++*attached;
    } else {
      // Already attached / unsupported volume are expected; keep going. The
      // ERROR_FLT_* constants are full HRESULTs (facility 0x1F), so compare the
      // HRESULT itself; ERROR_INVALID_DEVICE_OBJECT_PARAMETER is a Win32 code.
      const bool expected =
          ah == ERROR_FLT_INSTANCE_NAME_COLLISION ||
          ah == ERROR_FLT_INSTANCE_ALTITUDE_COLLISION ||
          ah == HRESULT_FROM_WIN32(ERROR_INVALID_DEVICE_OBJECT_PARAMETER);
      if (!expected && !firstErr) firstErr = hres(ah);
    }
  };
  attachOne(buf.data());
  for (;;) {
    needed = 0;
    hr = FilterVolumeFindNext(find, FilterVolumeBasicInformation, buf.data(),
                              static_cast<DWORD>(buf.size()), &needed);
    if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
      buf.resize(needed);
      hr = FilterVolumeFindNext(find, FilterVolumeBasicInformation, buf.data(),
                                static_cast<DWORD>(buf.size()), &needed);
    }
    if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) break;
    if (FAILED(hr)) {
      if (!firstErr) firstErr = hres(hr);
      break;
    }
    attachOne(buf.data());
  }
  FilterVolumeFindClose(find);
  return firstErr;
}

std::error_code DriverController::ensureLoaded(const wchar_t* serviceName,
                                               const wchar_t* sysPath,
                                               std::wstring* filterName) {
  std::error_code ec;
  const auto loaded = loadedProcmonName(ec);
  if (ec) return ec;
  // Attach under the name the filter is actually registered as: if real Procmon
  // already loaded it (e.g. as PROCMON24) FilterAttach("PROCMON25") would fail.
  const std::wstring name = loaded ? *loaded : std::wstring(serviceName);
  if (filterName) *filterName = name;
  if (!loaded) {
    ec = installService(serviceName, sysPath);
    if (ec) return ec;
    ec = load(serviceName);
    if (ec) return ec;
  }
  return attachAllVolumes(name.c_str());
}

bool DriverController::isElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elev{};
  DWORD sz = sizeof(elev);
  const bool ok =
      GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz);
  CloseHandle(token);
  return ok && elev.TokenIsElevated;
}

}  // namespace pmx
