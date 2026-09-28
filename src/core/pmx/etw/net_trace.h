#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <system_error>

namespace pmx {

// One decoded network event from the kernel TcpIp/UdpIp ETW provider.
struct NetEvent {
  uint64_t timestamp = 0;   // FILETIME (100ns since 1601), from the ETW record
  uint32_t pid = 0;
  uint16_t opcode = 0;      // raw ETW opcode (10 Send, 11 Receive, ...)
  bool isTcp = true;
  bool isIpv6 = false;
  const char* opName = "";  // "TCP Send", "UDP Receive", ...
  std::string localAddr;    // "1.2.3.4:1234"  (source)
  std::string remoteAddr;   // "5.6.7.8:80"     (dest)
  uint32_t length = 0;      // bytes transferred (0 if n/a)
  // Raw address material for binary re-encoding (e.g. PML). IPs in network byte
  // order (first 4 bytes used for IPv4); ports in host order.
  uint8_t srcIp[16] = {};
  uint8_t dstIp[16] = {};
  uint16_t srcPort = 0;
  uint16_t dstPort = 0;
};

// Real-time consumer of the NT Kernel Logger network events. Needs elevation.
class NetTrace {
 public:
  using Sink = std::function<void(const NetEvent&)>;
  // Runs until `maxCount` events delivered (0 = until stop()) or an error. The
  // sink is called from the processing thread for each decoded event. A stop()
  // issued before run() is honoured (the flag is sticky; one run per object).
  // The NT Kernel Logger is a single system-wide session: if another consumer
  // stops it, run() returns ERROR_OPERATION_ABORTED instead of waiting forever.
  std::error_code run(const Sink& sink, uint64_t maxCount);
  void stop() noexcept;  // request the run() to end (thread-safe)
  // Called from run() when an existing NT Kernel Logger session (another tool,
  // or a crashed pmx) had to be stopped to start ours.
  std::function<void()> onTookOverSession;
 private:
  std::atomic<bool> stopRequested_{false};
};

}  // namespace pmx
