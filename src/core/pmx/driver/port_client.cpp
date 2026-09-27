#include "pmx/driver/port_client.h"

#include <windows.h>
#include <fltuser.h>

#include <cstdio>
#include <cstring>

namespace pmx {

namespace {
std::error_code hres(HRESULT hr) {
  // FilterXxx APIs return HRESULTs wrapping Win32 codes.
  const int win32 = HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr)
                                                           : static_cast<int>(hr);
  return {win32, std::system_category()};
}
}  // namespace

PortClient::~PortClient() {
  disconnect();
  if (cancelEvent_) CloseHandle(cancelEvent_);
  if (ioEvent_) CloseHandle(ioEvent_);
}

std::error_code PortClient::connect(const wchar_t* portName, uint32_t context) {
  disconnect();
  HANDLE h = nullptr;
  const HRESULT hr = FilterConnectCommunicationPort(
      portName, 0, &context, sizeof(context), nullptr, &h);
  if (FAILED(hr)) return hres(hr);
  port_ = h;
  if (!cancelEvent_) cancelEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!ioEvent_) ioEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  ResetEvent(cancelEvent_);
  buffer_.resize(proto::kMessageBufferSize);
  return {};
}

std::error_code PortClient::connectAuto(uint32_t context) {
  std::error_code last{ERROR_FILE_NOT_FOUND, std::system_category()};
  // Newest first; extend as new protocol tags appear.
  for (int nn : {25, 24, 23, 22, 21, 20}) {
    wchar_t name[64];
    swprintf(name, 64, L"\\ProcessMonitor%dPort", nn);
    last = connect(name, context);
    if (!last) {
      version_ = nn;
      return {};
    }
  }
  version_ = -1;
  return last;
}

void PortClient::disconnect() noexcept {
  if (port_) {
    CloseHandle(port_);
    port_ = nullptr;
  }
}

std::error_code PortClient::send(const void* msg, uint32_t size) {
  if (!port_) return {ERROR_INVALID_HANDLE, std::system_category()};
  DWORD returned = 0;
  const HRESULT hr = FilterSendMessage(port_, const_cast<void*>(msg), size,
                                       nullptr, 0, &returned);
  return FAILED(hr) ? hres(hr) : std::error_code{};
}

std::error_code PortClient::setCapture(bool on, uint32_t flags) {
  proto::SetCaptureMsg m{static_cast<uint32_t>(proto::Op::SetCapture),
                         on ? flags : 0u};
  return send(&m, sizeof(m));
}

std::error_code PortClient::setInterval(uint32_t rateHz) {
  proto::SetIntervalMsg m{static_cast<uint32_t>(proto::Op::SetInterval),
                          rateHz ? proto::kIntervalUnitsPerSec / rateHz : 0ull};
  return send(&m, sizeof(m));
}

void PortClient::cancel() noexcept {
  if (cancelEvent_) SetEvent(cancelEvent_);
}

std::error_code PortClient::pumpOnce(const RecordSink& sink) {
  if (!port_) return {ERROR_INVALID_HANDLE, std::system_category()};

  OVERLAPPED ov{};
  ov.hEvent = ioEvent_;
  HRESULT hr = FilterGetMessage(
      port_, reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer_.data()),
      static_cast<DWORD>(buffer_.size()), &ov);

  if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
    HANDLE waits[2] = {ioEvent_, cancelEvent_};
    const DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    DWORD bytes = 0;
    if (w != WAIT_OBJECT_0) {
      const DWORD waitErr = GetLastError();
      // `ov` lives on this stack frame and the read targets buffer_: after
      // CancelIoEx the kernel may still complete the request, so block until it
      // has before returning (otherwise it writes into a dead frame).
      CancelIoEx(port_, &ov);
      GetOverlappedResult(port_, &ov, &bytes, TRUE);
      if (w == WAIT_OBJECT_0 + 1)
        return std::make_error_code(std::errc::operation_canceled);
      return {static_cast<int>(waitErr), std::system_category()};
    }
    if (!GetOverlappedResult(port_, &ov, &bytes, FALSE))
      return {static_cast<int>(GetLastError()), std::system_category()};
    hr = S_OK;
  }
  if (FAILED(hr)) return hres(hr);

  // Payload: [FILTER_MESSAGE_HEADER][uint32 payloadLen][records...]
  constexpr size_t kHdr = sizeof(FILTER_MESSAGE_HEADER);
  if (buffer_.size() < kHdr + sizeof(proto::EventBatchPrefix)) return {};
  const uint8_t* base = buffer_.data();
  const uint32_t payloadLen =
      reinterpret_cast<const proto::EventBatchPrefix*>(base + kHdr)->payloadLen;
  const uint8_t* p = base + kHdr + sizeof(proto::EventBatchPrefix);
  const uint8_t* end = p + payloadLen;
  if (end > base + buffer_.size()) end = base + buffer_.size();

  while (p + sizeof(proto::EventRecordHeader) <= end) {
    const auto* h = reinterpret_cast<const proto::EventRecordHeader*>(p);
    const uint64_t total = proto::recordSize(*h);
    if (p + total > end) break;  // truncated/desynced — stop this batch
    RawRecord rec{
        h,
        {p + sizeof(proto::EventRecordHeader), size_t{8} * h->frameCount},
        {p + sizeof(proto::EventRecordHeader) + size_t{8} * h->frameCount,
         h->detailSize},
    };
    sink(rec);
    p += total;
  }
  return {};
}

std::error_code PortClient::pumpLoop(const RecordSink& sink) {
  for (;;) {
    std::error_code ec = pumpOnce(sink);
    if (ec == std::errc::operation_canceled) return {};
    if (ec) return ec;
  }
}

}  // namespace pmx
