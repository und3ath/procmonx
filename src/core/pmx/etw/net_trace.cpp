#include "pmx/etw/net_trace.h"

#include <windows.h>

#include <initguid.h>
#include <evntcons.h>
#include <evntrace.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>

#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

namespace pmx {
namespace {

// Classic MOF kernel network providers (NT Kernel Logger session only).
static const GUID kTcpIpGuid = {
    0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
static const GUID kUdpIpGuid = {
    0xbf3a50c5, 0xa9c9, 0x4988, {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};

#pragma pack(push, 1)
struct TcpIpV4Data {
  uint32_t pid;
  uint32_t size;
  uint32_t daddr;
  uint32_t saddr;
  uint16_t dport;
  uint16_t sport;
};
struct TcpIpV6Data {
  uint32_t pid;
  uint32_t size;
  uint8_t daddr[16];
  uint8_t saddr[16];
  uint16_t dport;
  uint16_t sport;
};
#pragma pack(pop)

// State shared between run() and the static ETW callback, referenced via
// EVENT_TRACE_LOGFILEW::Context / EVENT_RECORD::UserContext.
struct CallbackCtx {
  const NetTrace::Sink* sink = nullptr;
  std::atomic<uint64_t>* count = nullptr;
  std::atomic<bool>* stop = nullptr;  // once set, callbacks drain without emitting
};

const char* baseOpName(int base) {
  switch (base) {
    case 10: return "Send";
    case 11: return "Receive";
    case 12: return "Connect";
    case 13: return "Disconnect";
    case 14: return "Retransmit";
    case 15: return "Accept";
    case 16: return "Reconnect";
    case 17: return "Fail";
    case 18: return "TCPCopy";
    default: return nullptr;
  }
}

void WINAPI OnRecord(EVENT_RECORD* rec) {
  if (!rec || !rec->UserContext) return;
  auto* ctx = static_cast<CallbackCtx*>(rec->UserContext);
  // Once a stop is requested, drain remaining buffered events without emitting
  // (keeps teardown fast and bounds overshoot past a --count limit).
  if (ctx->stop && ctx->stop->load(std::memory_order_relaxed)) return;

  const GUID& provider = rec->EventHeader.ProviderId;
  bool isTcp;
  if (IsEqualGUID(provider, kTcpIpGuid))
    isTcp = true;
  else if (IsEqualGUID(provider, kUdpIpGuid))
    isTcp = false;
  else
    return;

  int opcode = rec->EventHeader.EventDescriptor.Opcode;
  bool isIpv6 = opcode >= 26;
  int base = isIpv6 ? (opcode - 16) : opcode;
  const char* verb = baseOpName(base);
  if (!verb) return;

  static thread_local char nameBuf[32];
  std::snprintf(nameBuf, sizeof nameBuf, "%s %s", isTcp ? "TCP" : "UDP", verb);

  NetEvent ev;
  ev.timestamp = static_cast<uint64_t>(rec->EventHeader.TimeStamp.QuadPart);
  ev.isTcp = isTcp;
  ev.isIpv6 = isIpv6;
  ev.opcode = static_cast<uint16_t>(opcode);
  ev.opName = nameBuf;

  const uint8_t* data = static_cast<const uint8_t*>(rec->UserData);
  const ULONG len = rec->UserDataLength;

  char abuf[64];
  if (!isIpv6) {
    if (len < sizeof(TcpIpV4Data)) return;
    TcpIpV4Data d;
    std::memcpy(&d, data, sizeof d);
    ev.pid = d.pid;
    ev.length = d.size;

    std::memcpy(ev.srcIp, &d.saddr, 4);
    std::memcpy(ev.dstIp, &d.daddr, 4);
    ev.srcPort = ntohs(d.sport);
    ev.dstPort = ntohs(d.dport);

    in_addr src{}; std::memcpy(&src, &d.saddr, sizeof src);
    if (InetNtopA(AF_INET, &src, abuf, sizeof abuf))
      ev.localAddr = std::string(abuf) + ":" + std::to_string(ev.srcPort);

    in_addr dst{}; std::memcpy(&dst, &d.daddr, sizeof dst);
    if (InetNtopA(AF_INET, &dst, abuf, sizeof abuf))
      ev.remoteAddr = std::string(abuf) + ":" + std::to_string(ev.dstPort);
  } else {
    if (len < sizeof(TcpIpV6Data)) return;
    TcpIpV6Data d;
    std::memcpy(&d, data, sizeof d);
    ev.pid = d.pid;
    ev.length = d.size;

    std::memcpy(ev.srcIp, d.saddr, 16);
    std::memcpy(ev.dstIp, d.daddr, 16);
    ev.srcPort = ntohs(d.sport);
    ev.dstPort = ntohs(d.dport);

    in6_addr src{}; std::memcpy(&src, d.saddr, sizeof src);
    if (InetNtopA(AF_INET6, &src, abuf, sizeof abuf))
      ev.localAddr = std::string(abuf) + ":" + std::to_string(ev.srcPort);

    in6_addr dst{}; std::memcpy(&dst, d.daddr, sizeof dst);
    if (InetNtopA(AF_INET6, &dst, abuf, sizeof abuf))
      ev.remoteAddr = std::string(abuf) + ":" + std::to_string(ev.dstPort);
  }

  ctx->count->fetch_add(1, std::memory_order_relaxed);
  (*ctx->sink)(ev);
}

}  // namespace

std::error_code NetTrace::run(const Sink& sink, uint64_t maxCount) {
  const size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAMEW);
  std::vector<uint8_t> buf(propsSize, 0);
  auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
  props->Wnode.BufferSize = static_cast<ULONG>(propsSize);
  props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  props->Wnode.ClientContext = 1;  // QPC timer resolution
  props->Wnode.Guid = SystemTraceControlGuid;
  props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  props->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
  props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  // Clear any stale session from a previous run/crash using a SEPARATE buffer:
  // ControlTraceW writes the queried/stopped session's properties back into the
  // buffer it is given, which would clobber the EnableFlags/LogFileMode/Guid we
  // set above and make the StartTraceW below fail on the second and later runs.
  {
    std::vector<uint8_t> tmp(propsSize, 0);
    auto* tp = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(tmp.data());
    tp->Wnode.BufferSize = static_cast<ULONG>(propsSize);
    tp->Wnode.Guid = SystemTraceControlGuid;
    tp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(0, KERNEL_LOGGER_NAMEW, tp, EVENT_TRACE_CONTROL_STOP);
  }

  // Stop already requested before we started: don't spin up a session at all.
  if (stopRequested_.load(std::memory_order_relaxed)) return {};

  TRACEHANDLE sessionHandle = 0;
  ULONG startStatus = StartTraceW(&sessionHandle, KERNEL_LOGGER_NAMEW, props);
  if (startStatus != ERROR_SUCCESS)
    return {static_cast<int>(startStatus), std::system_category()};

  EVENT_TRACE_LOGFILEW logFile{};
  logFile.LoggerName = const_cast<LPWSTR>(KERNEL_LOGGER_NAMEW);
  logFile.ProcessTraceMode =
      PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  logFile.EventRecordCallback = &OnRecord;

  // NOTE: stopRequested_ is deliberately NOT reset here. stop() may be called
  // (Ctrl-C, or `live --count` met by driver events) before this thread reaches
  // run(); clearing the flag would lose that request and run() would never end.
  std::atomic<uint64_t> count{0};
  CallbackCtx ctx;
  ctx.sink = &sink;
  ctx.count = &count;
  ctx.stop = &stopRequested_;
  logFile.Context = &ctx;

  TRACEHANDLE traceHandle = OpenTraceW(&logFile);
  if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
    DWORD err = GetLastError();
    ControlTraceW(0, KERNEL_LOGGER_NAMEW, props, EVENT_TRACE_CONTROL_STOP);
    return {static_cast<int>(err), std::system_category()};
  }

  std::thread worker([traceHandle]() mutable {
    ProcessTrace(&traceHandle, 1, nullptr, nullptr);
  });

  for (;;) {
    if (stopRequested_.load(std::memory_order_relaxed)) break;
    if (maxCount != 0 && count.load(std::memory_order_relaxed) >= maxCount) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  // Suppress further emits, stop the session (no new events), then close the
  // consumer so ProcessTrace drains its buffers and returns.
  stopRequested_.store(true, std::memory_order_relaxed);
  ControlTraceW(0, KERNEL_LOGGER_NAMEW, props, EVENT_TRACE_CONTROL_STOP);
  CloseTrace(traceHandle);
  if (worker.joinable()) worker.join();

  return {};
}

void NetTrace::stop() noexcept { stopRequested_ = true; }

}  // namespace pmx
