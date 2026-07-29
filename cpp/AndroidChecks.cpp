///
/// AndroidChecks.cpp
///

#include "AndroidChecks.hpp"
#include "AndroidProbes.hpp"
#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"
#include "TcpProbe.hpp"

#include <string>
#include <utility>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  namespace {

    // Canonical `/proc` and `/sys` paths probed by the Android baseline.
    constexpr std::string_view K_PROC_MAPS = "/proc/self/maps";
    constexpr std::string_view K_PROC_MOUNTINFO = "/proc/self/mountinfo";
    constexpr std::string_view K_INIT_MOUNTINFO = "/proc/1/mountinfo";
    constexpr std::string_view K_PROC_MOUNTS = "/proc/self/mounts";
    constexpr std::string_view K_PROC_STATUS = "/proc/self/status";
    constexpr std::string_view K_PROC_CMDLINE = "/proc/self/cmdline";
    constexpr std::string_view K_PROC_NET_UNIX = "/proc/net/unix";
    constexpr std::string_view K_SELINUX_ENFORCE = "/sys/fs/selinux/enforce";

    // Build a `DetectionSignal` from a parser/probe finding, applying the
    // default weight and severity from the catalog. Evidence is attached only
    // when the caller opted in, and even then it is the already-redacted
    // snippet produced by the parser (never a raw sensitive value).
    DetectionSignal buildSignal(std::string_view id, const std::string& evidence,
                                bool includeEvidence) noexcept {
      std::optional<SignalSpec> spec = lookupSignal(id);
      if (!spec.has_value()) {
        // Unknown ids should never be produced by the detectors. Emit a
        // zero-weight, low-severity placeholder so the result stays well-formed
        // and the id is still visible for debugging.
        return DetectionSignal(
          std::string(id),
          Severity::LOW,
          0.0,
          includeEvidence ? std::optional<std::string>(evidence) : std::nullopt,
          std::nullopt
        );
      }
      return DetectionSignal(
        std::string(spec->id),
        spec->severity,
        spec->score,
        includeEvidence ? std::optional<std::string>(evidence) : std::nullopt,
        std::nullopt
      );
    }

    DetectionSignal unavailableSignal(std::string_view id) noexcept {
      return DetectionSignal(std::string(id), Severity::LOW, 0.0, std::nullopt, true);
    }

    bool expired(std::chrono::steady_clock::time_point deadline) noexcept {
      return std::chrono::steady_clock::now() >= deadline;
    }

    // Append findings as signals. `available=false` is not used here because
    // each detector only emits a finding when it actually matched something.
    void appendFindings(std::vector<DetectionSignal>& signals,
                        const std::vector<ProcFinding>& findings, bool includeEvidence) noexcept {
      for (const ProcFinding& finding : findings) {
        signals.push_back(buildSignal(finding.signalId, finding.evidence, includeEvidence));
      }
    }

  } // namespace

  AndroidCheckResult runAndroidChecks(bool includeEvidence,
                                      std::chrono::steady_clock::time_point deadline) noexcept {
    AndroidCheckResult result;

    // ---- Memory maps: Zygisk / LSPosed / Frida / Riru ----------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_MAPS));
      result.partial = true;
    } else if (auto maps = readFileIfExists(K_PROC_MAPS)) {
      appendFindings(result.signals, scanMapsForHooks(*maps), includeEvidence);
    } else {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_MAPS));
    }

    // ---- Mount metadata: Magisk / KSU / APatch overlays --------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_MOUNTS));
      result.partial = true;
    } else {
      std::optional<std::string> mountinfo = readFileIfExists(K_PROC_MOUNTINFO);
      std::optional<std::string> mounts = readFileIfExists(K_PROC_MOUNTS);
      if (!mountinfo.has_value() && !mounts.has_value()) {
        result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_MOUNTS));
      } else {
        appendFindings(
          result.signals,
          scanMountsForRootArtifacts(mountinfo.value_or(""), mounts.value_or("")),
          includeEvidence
        );
        if (mountinfo.has_value()) {
          if (auto initMountinfo = readFileIfExists(K_INIT_MOUNTINFO)) {
            appendFindings(result.signals,
                           scanNamespaceOnlyMountArtifacts(*mountinfo, *initMountinfo),
                           includeEvidence);
          }
        }
      }
    }

    // ---- SELinux enforcement state -----------------------------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_SELINUX));
      result.partial = true;
    } else if (auto enforce = readFileIfExists(K_SELINUX_ENFORCE)) {
      std::optional<bool> enforcing = parseSelinuxEnforce(*enforce);
      if (enforcing.has_value() && !enforcing.value()) {
        // Permissive/disabled SELinux on what should be a production device.
        result.signals.push_back(
          buildSignal(SignalId::ANDROID_SELINUX_PERMISSIVE, "selinux=enforce:0", includeEvidence)
        );
      }
    } else {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_SELINUX));
    }

    // ---- Root-manager paths and `su` binaries ------------------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_ROOT_PATHS));
      result.partial = true;
    } else {
      appendFindings(result.signals, probeRootPaths(), includeEvidence);
    }

    // ---- Build / verified-boot properties ----------------------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_PROPERTIES));
      result.partial = true;
    } else {
      appendFindings(result.signals, probeBuildProperties(), includeEvidence);
    }

    // ---- Debugger: TracerPid (informational) -------------------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_DEBUGGER));
      result.partial = true;
    } else if (auto status = readFileIfExists(K_PROC_STATUS)) {
      std::optional<int> tracerPid = parseTracerPid(*status);
      if (tracerPid.has_value() && tracerPid.value() != 0) {
        // Reported on `debuggerDetected` and as a zero-weight signal so the
        // reason list can explain *why* the debugger flag is set without the
        // score treating it as compromise by default.
        result.debuggerDetected = true;
        result.signals.push_back(
          buildSignal(SignalId::ANDROID_DEBUGGER_TRACERPID,
                      "TracerPid!=0", includeEvidence)
        );
      }
    } else {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_DEBUGGER));
    }

    // ---- Runtime instrumentation: current command line and local sockets ---
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_RUNTIME));
      result.partial = true;
    } else {
      bool available = false;
      if (auto cmdline = readFileIfExists(K_PROC_CMDLINE)) {
        available = true;
        if (cmdline->find("frida") != std::string::npos) {
          result.signals.push_back(buildSignal(
            SignalId::ANDROID_CMDLINE_INSTRUMENTATION, "frida-command-line", includeEvidence));
        }
      }
      if (auto unixSockets = readFileIfExists(K_PROC_NET_UNIX)) {
        available = true;
        if (unixSockets->find("frida") != std::string::npos) {
          result.signals.push_back(buildSignal(
            SignalId::ANDROID_SOCKET_INSTRUMENTATION, "frida-local-socket", includeEvidence));
        }
      }
      if (!available) {
        result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_RUNTIME));
      }
    }

    // ---- Loopback TCP service probes (Frida / SSH / ADB) --------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_RUNTIME));
      result.partial = true;
    } else {
      std::vector<ProcFinding> networkFindings = probeDefaultLocalTcpServices(deadline);
      if (networkFindings.empty() &&
          std::find_if(result.signals.begin(), result.signals.end(),
                       [](const DetectionSignal& s) {
                         return s.id == SignalId::ANDROID_CHECK_RUNTIME;
                       }) == result.signals.end()) {
        // Probing ports gave no additional signal; nothing to report.
      } else {
        appendFindings(result.signals, networkFindings, includeEvidence);
      }
    }

    return result;
  }

} // namespace margelo::nitro::rootjaildetect
