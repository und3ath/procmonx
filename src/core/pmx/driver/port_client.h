#pragma once
// RAII client for the Procmon minifilter communication port.
//
// Connects to \ProcessMonitor<NN>Port, toggles capture, and drains the packed
// event stream via FilterGetMessage. Observation only; the driver is never
// asked to block or modify I/O.

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "pmx/driver/protocol.h"

namespace pmx {

// One decoded framing of a single event record inside a batch: the fixed header
// plus the raw stack and detail bytes (not yet field-decoded).
struct RawRecord {
  const proto::EventRecordHeader* header;
  std::span<const uint8_t> stack;   // 8 * frameCount bytes
  std::span<const uint8_t> detail;  // detailSize bytes
};

class PortClient {
 public:
  PortClient() = default;
  ~PortClient();
  PortClient(const PortClient&) = delete;
  PortClient& operator=(const PortClient&) = delete;

  // Connect to an explicit port name (e.g. proto::kPortName25). context is the
  // 4-byte connection context sent at connect time and selects the channel:
  //   0 = event/control channel (the event stream)   <- default
  //   1 = name-resolution helper channel (no events)
  std::error_code connect(const wchar_t* portName, uint32_t context = 0);

  // Sweep known ProcessMonitor<NN>Port names and connect to the first that
  // answers; on success, portVersion() reports NN. Returns the last error if
  // none respond.
  std::error_code connectAuto(uint32_t context = 0);

  void disconnect() noexcept;
  bool connected() const noexcept { return port_ != nullptr; }
  int portVersion() const noexcept { return version_; }  // NN, or -1

  // Op::SetCapture. flags selects event classes (see protocol.h). on=false
  // sends flags=0 to stop the driver streaming.
  std::error_code setCapture(bool on, uint32_t flags);

  // Op::SetInterval. rateHz==0 sends interval 0.
  std::error_code setInterval(uint32_t rateHz);

  // Blocking single pull: waits for one FilterGetMessage batch and invokes sink
  // once per framed record. Returns:
  //   - {} on a batch delivered (sink called 0+ times),
  //   - std::errc::operation_canceled after cancel(),
  //   - other error_code on failure.
  using RecordSink = std::function<void(const RawRecord&)>;
  std::error_code pumpOnce(const RecordSink& sink);

  // Loop pumpOnce until cancel() or an error. Returns the terminating status
  // ({} if cancelled cleanly).
  std::error_code pumpLoop(const RecordSink& sink);

  // Signal any in-flight/blocking pump to stop. Safe from another thread.
  void cancel() noexcept;

 private:
  std::error_code send(const void* msg, uint32_t size);

  void* port_ = nullptr;         // HANDLE
  void* cancelEvent_ = nullptr;  // HANDLE, manual-reset
  void* ioEvent_ = nullptr;      // HANDLE, auto-reset (overlapped)
  int version_ = -1;
  std::vector<uint8_t> buffer_;  // reused FilterGetMessage buffer
};

}  // namespace pmx
