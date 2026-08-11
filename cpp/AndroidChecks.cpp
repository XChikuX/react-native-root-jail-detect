///
/// AndroidChecks.cpp
///

#include "AndroidChecks.hpp"
#include "AndroidProbes.hpp"
#include "HybridPackageManagerProbe.hpp"
#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"
#include "TcpProbe.hpp"

#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include <NitroModules/HybridObjectRegistry.hpp>

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
          platformForSignal(id),
          SignalCategory::DEBUGGER,
          Severity::LOW,
          0.0,
          true,
          0.0,
          includeEvidence ? std::optional<std::string>(evidence) : std::nullopt,
          std::nullopt
        );
      }
      return DetectionSignal(
        std::string(spec->id),
        platformForSignal(spec->id),
        spec->category,
        spec->severity,
        spec->score,
        true,
        spec->reliability,
        includeEvidence ? std::optional<std::string>(evidence) : std::nullopt,
        std::nullopt
      );
    }

    DetectionSignal unavailableSignal(std::string_view id) noexcept {
      return DetectionSignal(
        std::string(id),
        platformForSignal(id),
        SignalCategory::DEBUGGER,
        Severity::LOW,
        0.0,
        false,
        0.0,
        std::nullopt,
        true
      );
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
    } else if (auto maps = readFileIfExists(K_PROC_MAPS, deadline, 256 * 1024)) {
      appendFindings(result.signals, scanMapsForHooks(*maps), includeEvidence);
      appendFindings(result.signals, scanMapsForAnonymousInjection(*maps), includeEvidence);
    } else {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_MAPS));
    }

    // ---- Mount metadata: Magisk / KSU / APatch overlays --------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_MOUNTS));
      result.partial = true;
    } else {
      std::optional<std::string> mountinfo = readFileIfExists(K_PROC_MOUNTINFO, deadline, 128 * 1024);
      std::optional<std::string> mounts = readFileIfExists(K_PROC_MOUNTS, deadline, 128 * 1024);
      if (!mountinfo.has_value() && !mounts.has_value()) {
        result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_MOUNTS));
      } else {
        appendFindings(
          result.signals,
          scanMountsForRootArtifacts(mountinfo.value_or(""), mounts.value_or("")),
          includeEvidence
        );
        appendFindings(result.signals, scanMountsForMagiskChain(mountinfo.value_or("")), includeEvidence);
        if (mountinfo.has_value()) {
          if (auto initMountinfo = readFileIfExists(K_INIT_MOUNTINFO, deadline, 128 * 1024)) {
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
    } else if (auto enforce = readFileIfExists(K_SELINUX_ENFORCE, deadline, 16)) {
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
      appendFindings(result.signals, probeAddonD(), includeEvidence);
      appendFindings(result.signals, probeInstallRecovery(), includeEvidence);
      appendFindings(result.signals, probeLspdCache(), includeEvidence);

      ModuleProbeResult modules = probeMagiskModules(deadline);
      appendFindings(result.signals, modules.findings, includeEvidence);
      if (!modules.available) {
        result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_MODULES));
      }
    }

    // ---- Build / verified-boot properties ----------------------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_PROPERTIES));
      result.partial = true;
    } else {
      appendFindings(result.signals, probeSystemAttributes(), includeEvidence);
      appendFindings(result.signals, probeCustomRom(), includeEvidence);
    }

    // A writable hosts file is a narrow tampering check. Merely finding local
    // ad-blocking entries is intentionally not evidence.
    if (expired(deadline)) {
      result.partial = true;
    } else {
      appendFindings(result.signals, probeHostsFile(), includeEvidence);
    }

    // ---- Debugger: TracerPid (informational) -------------------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_DEBUGGER));
      result.partial = true;
    } else if (auto status = readFileIfExists(K_PROC_STATUS, deadline, 8 * 1024)) {
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
      if (auto cmdline = readFileIfExists(K_PROC_CMDLINE, deadline, 4 * 1024)) {
        available = true;
        if (cmdline->find("frida") != std::string::npos) {
          result.signals.push_back(buildSignal(
            SignalId::ANDROID_CMDLINE_INSTRUMENTATION, "frida-command-line", includeEvidence));
        }
      }
      if (auto unixSockets = readFileIfExists(K_PROC_NET_UNIX, deadline, 128 * 1024)) {
        available = true;
        if (unixSockets->find("frida") != std::string::npos) {
          result.signals.push_back(buildSignal(
            SignalId::ANDROID_SOCKET_INSTRUMENTATION, "frida-local-socket", includeEvidence));
        }
      }
      if (!available) {
        result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_RUNTIME));
      }
      appendFindings(result.signals, probeEnvironmentAndCommands(), includeEvidence);
    }

    // ---- Sandbox write test -------------------------------------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_SANDBOX));
      result.partial = true;
    } else {
      constexpr const char* kSandboxTestPath = "/data/local/tmp/su_check.txt";
      std::ofstream testFile(kSandboxTestPath);
      if (testFile.is_open()) {
        testFile << "root-test";
        testFile.close();
        std::remove(kSandboxTestPath);
        result.signals.push_back(
          buildSignal(SignalId::ANDROID_SANDBOX_WRITE, "sandbox-write-success", includeEvidence)
        );
      }
      appendFindings(result.signals, probeSystemDirectoryWrite(), includeEvidence);
    }

    // ---- PackageManager enumeration -----------------------------------------
    if (expired(deadline)) {
      result.partial = true;
    } else {
      std::shared_ptr<HybridPackageManagerProbeSpec> probe;
      try {
        std::shared_ptr<margelo::nitro::HybridObject> object =
          margelo::nitro::HybridObjectRegistry::createHybridObject("PackageManagerProbe");
        probe = std::dynamic_pointer_cast<HybridPackageManagerProbeSpec>(object);
      } catch (...) {
        probe = nullptr;
      }
      if (!probe) {
        probe = std::make_shared<HybridPackageManagerProbe>();
      }
      try {
        std::vector<std::string> rootPackages = probe->getInstalledRootPackages();
        if (!rootPackages.empty()) {
          for (const auto& pkg : rootPackages) {
            result.signals.push_back(
              buildSignal(SignalId::ANDROID_PACKAGE_MANAGER_ROOT, "root-package:" + pkg, includeEvidence)
            );
            break;  // Only emit one signal for the first detected package
          }
        }
        std::vector<std::string> hidingPackages = probe->getInstalledHidingPackages();
        if (!hidingPackages.empty()) {
          result.signals.push_back(buildSignal(
            SignalId::ANDROID_PACKAGE_MANAGER_HMA,
            "hiding-package:" + hidingPackages.front(),
            includeEvidence
          ));
        }
        std::vector<std::string> riskyPackages = probe->getInstalledRiskyPackages();
        if (!riskyPackages.empty()) {
          result.signals.push_back(buildSignal(
            SignalId::ANDROID_PACKAGE_MANAGER_RISKY,
            "risky-package:" + riskyPackages.front(),
            includeEvidence
          ));
        }
      } catch (...) {
        // PackageManager probe failed; not a detection.
      }
    }

    // ---- Loopback TCP service probes (Frida / SSH / ADB) --------------------
    if (expired(deadline)) {
      result.signals.push_back(unavailableSignal(SignalId::ANDROID_CHECK_RUNTIME));
      result.partial = true;
    } else {
      // Probe returns one finding per responding port; an empty list means no
      // loopback service answered and there is nothing to report here. The
      // unavailable marker for this step reuses `ANDROID_CHECK_RUNTIME` until a
      // dedicated `ANDROID_CHECK_NETWORK` id is added to the public catalog.
      std::vector<ProcFinding> networkFindings = probeDefaultLocalTcpServices(deadline);
      appendFindings(result.signals, networkFindings, includeEvidence);
    }

    return result;
  }

} // namespace margelo::nitro::rootjaildetect
