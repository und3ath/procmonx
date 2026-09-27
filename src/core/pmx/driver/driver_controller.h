#pragma once
// Manage the Procmon minifilter: query whether it is loaded, and (with admin +
// the signed .sys registered as a service) load/unload it. procmonx never ships
// the driver; this only drives a Procmon install already present on the machine.

#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace pmx {

struct LoadedFilter {
  std::wstring name;
  uint32_t frameId = 0;
  uint32_t instances = 0;
};

class DriverController {
 public:
  // All loaded minifilters (via FilterFindFirst/Next).
  static std::vector<LoadedFilter> loadedFilters(std::error_code& ec);

  // Name of a loaded minifilter whose name starts with "PROCMON" (e.g.
  // "PROCMON24" when real Procmon loaded it under its own service), if any.
  static std::optional<std::wstring> loadedProcmonName(std::error_code& ec);

  // True if a minifilter whose name starts with "PROCMON" is loaded.
  static bool procmonLoaded(std::error_code& ec) {
    return loadedProcmonName(ec).has_value();
  }

  // FilterLoad / FilterUnload by service name (e.g. L"PROCMON25"). Requires
  // elevation and SeLoadDriverPrivilege; the service must already be registered.
  static std::error_code load(const wchar_t* serviceName);
  static std::error_code unload(const wchar_t* serviceName);

  // Register the minifilter as a service so FilterLoad can find it, without
  // running Procmon.exe. Creates the SERVICE_FILE_SYSTEM_DRIVER service with
  // ImagePath = sysPath, plus the Instances\<name> Instance key carrying the
  // Altitude (Procmon uses 385200). Idempotent: if the service already exists
  // its ImagePath is re-pointed at sysPath (a stale path would make FilterLoad
  // fail with file-not-found).
  static std::error_code installService(const wchar_t* serviceName,
                                        const wchar_t* sysPath,
                                        const wchar_t* altitude = L"385200");

  // Delete the service registration (does not unload a running instance).
  static std::error_code removeService(const wchar_t* serviceName);

  // Attach the loaded minifilter to every mounted volume (FilterAttach). Procmon
  // relies on FltMgr auto-attach; a hand-registered service often does not, so
  // no instances exist and no events flow until we attach explicitly. Returns
  // the number attached in *attached; already-attached volumes are not errors.
  static std::error_code attachAllVolumes(const wchar_t* serviceName,
                                          int* attached = nullptr);

  // Convenience: install (if missing), load, then attach all volumes. If some
  // PROCMON* filter is already loaded it is reused and attached under ITS name,
  // reported via *filterName (else *filterName = serviceName).
  static std::error_code ensureLoaded(const wchar_t* serviceName,
                                      const wchar_t* sysPath,
                                      std::wstring* filterName = nullptr);

  static bool isElevated();

  // Enable a privilege (e.g. SE_LOAD_DRIVER_NAME) in this process token. The
  // token must already hold it (elevated); this flips it from disabled to
  // enabled. Returns true on success.
  static bool enablePrivilege(const wchar_t* name);
};

}  // namespace pmx
