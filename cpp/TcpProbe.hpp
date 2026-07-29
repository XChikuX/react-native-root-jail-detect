///
/// TcpProbe.hpp
///
/// Loopback-only TCP port probes for local instrumentation services
/// (Frida server, SSH on jailbroken iOS, ADB-over-TCP/emulator).
///
/// Probes are non-blocking, bound by a per-port deadline, and target
/// `127.0.0.1` / `::1` only. A successful connect (or optional banner match)
/// is a positive finding; refused/timeout is silence — never proof of clean.
///

#pragma once

#include "ProcParsers.hpp"

#include <chrono>
#include <string_view>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  /// Minimal port probe descriptor. `signalId` maps into the public signal
  /// catalog so scoring and wrappers can reason about the hit. `weight`
  /// is the catalog weight (kept here for documentation; callers should still
  /// resolve via `lookupSignal`). `description` is a short redacted hint.
  struct PortProbe final {
    uint16_t port;
    std::string_view signalId;
    std::string_view description;
  };

  /// Known loopback services we probe. The list is intentionally narrow and
  /// loopback-bound; never add a non-loopback target here.
  constexpr PortProbe K_LOOPBACK_PORT_PROBES[] = {
    // Frida default listening port (changeable via `-l`; absence is not clean).
    {27042, "android.network.frida", "frida-listener"},
    // Jailbroken iOS SSH (OpenSSH) / older checkra1n/Meridian (port 44).
    {22,    "ios.network.ssh",       "ssh-listener"},
    {44,    "ios.network.ssh",       "ssh-listener-alt"},
    // ADB daemon in TCP mode or Android emulator. Weak on physical devices.
    {5037,  "android.network.adb",   "adb-listener"},
  };

  /// Probe every port in `probes` that has not yet exceeded the shared
  /// `deadline`. Returns `ProcFinding`s for ports that accepted a connection.
  /// RAII closes the socket on every return path.
  std::vector<ProcFinding> probeLocalTcpServices(
    const PortProbe* probes,
    size_t probeCount,
    std::chrono::steady_clock::time_point deadline
  ) noexcept;

  /// Convenience overload that probes the default `K_LOOPBACK_PORT_PROBES`.
  std::vector<ProcFinding> probeDefaultLocalTcpServices(
    std::chrono::steady_clock::time_point deadline
  ) noexcept;

} // namespace margelo::nitro::rootjaildetect
