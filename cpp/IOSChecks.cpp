///
/// IOSChecks.cpp
///

#include "IOSChecks.hpp"
#include "SignalCatalog.hpp"
#include "TcpProbe.hpp"

#include <chrono>
#include <cstring>
#include <optional>
#include <string>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#endif

namespace margelo::nitro::rootjaildetect {

  namespace {

    // Build a `DetectionSignal` from a signal id by looking up the catalog
    // weight/severity. This is the same path AndroidChecks uses so that
    // changes to the signal catalog (id renames, weight tuning) flow through
    // to iOS without duplicating the literal values here. If the id is not in
    // the catalog (which should never happen for ids produced by this file),
    // we emit a zero-weight placeholder so the result stays well-formed.
    DetectionSignal buildSignal(std::string_view id, const std::string& evidence,
                                bool includeEvidence) noexcept {
      std::optional<SignalSpec> spec = lookupSignal(id);
      if (!spec.has_value()) {
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

  } // namespace

  IOSCheckResult runIOSChecks(bool includeEvidence,
                              std::chrono::steady_clock::time_point deadline) noexcept {
    IOSCheckResult result;
#if defined(__APPLE__)
#if TARGET_OS_SIMULATOR
    result.signals.push_back(buildSignal(SignalId::IOS_SIMULATOR, "ios-simulator", includeEvidence));
    return result;
#else
    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_JAILBREAK));
      return result;
    }

    // Classic jailbreak artifacts. A single positive hit is sufficient
    // because all of these map to the same signal id; we never want to
    // count equivalent filesystem evidence twice.
    constexpr const char* kJailbreakPaths[] = {
      "/private/jb",
      "/var/jb",
      "/Applications/Cydia.app",
      "/Library/MobileSubstrate/MobileSubstrate.dylib",
      // Common rootless bootstrap prefixes / markers.
      "/private/preboot/jb",
      "/private/preboot/dopamine",
      "/private/preboot/palera1n",
      "/var/jb/.installed_dopamine",
      "/var/jb/.installed_palera1n",
      "/var/jb/usr/lib/TweakInject.dylib",
      // TrollStore-related persistence helpers — separate signal, low FP when
      // the file exists but it does not grant full jailbreak filesystem access.
      "/var/containers/Bundle/trollstoreapp",
      "/var/containers/Bundle/.trollstoreappinstalled",
    };

    bool rootlessArtifactFound = false;
    bool classicArtifactFound = false;
    bool dopamineArtifactFound = false;
    bool palera1nArtifactFound = false;
    bool trollstoreArtifactFound = false;

    for (const char* path : kJailbreakPaths) {
      struct stat status {};
      if (::stat(path, &status) != 0) {
        continue;
      }
      const std::string_view pv(path);
      if (pv.find("/var/jb") != std::string_view::npos ||
          pv.find("/private/preboot/jb") != std::string_view::npos) {
        rootlessArtifactFound = true;
      }
      if (pv.find("dopamine") != std::string_view::npos ||
          pv == "/var/jb/.installed_dopamine") {
        dopamineArtifactFound = true;
      }
      if (pv.find("palera1n") != std::string_view::npos ||
          pv == "/var/jb/.installed_palera1n") {
        palera1nArtifactFound = true;
      }
      if (pv.find("trollstore") != std::string_view::npos) {
        trollstoreArtifactFound = true;
      }
      if (!rootlessArtifactFound && !dopamineArtifactFound &&
          !palera1nArtifactFound && !trollstoreArtifactFound) {
        classicArtifactFound = true;
      }
    }

    // Emit distinct, stable signal ids so callers can reason about the class of
    // jailbreak profile observed. We report at most one rootless bootstrap signal
    // plus profile-specific markers.
    if (rootlessArtifactFound) {
      result.signals.push_back(
        buildSignal(SignalId::IOS_JAILBREAK_ROOTLESS, "rootless-bootstrap-artifact", includeEvidence)
      );
    }
    if (dopamineArtifactFound) {
      result.signals.push_back(
        buildSignal(SignalId::IOS_JAILBREAK_DOPAMINE, "dopamine-artifact", includeEvidence)
      );
    }
    if (palera1nArtifactFound) {
      result.signals.push_back(
        buildSignal(SignalId::IOS_JAILBREAK_PALERA1N, "palera1n-artifact", includeEvidence)
      );
    }
    if (trollstoreArtifactFound) {
      result.signals.push_back(
        buildSignal(SignalId::IOS_SIDeload_TROLLSTORE, "trollstore-artifact", includeEvidence)
      );
    }
    if (classicArtifactFound) {
      result.signals.push_back(
        buildSignal(SignalId::IOS_JAILBREAK_ARTIFACT, "known-jailbreak-artifact", includeEvidence)
      );
    }

    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_DYLD));
      return result;
    }

    // Injections frameworks and common renamed Frida gadget names. Tokens are
    // specific enough to avoid most benign libraries while still catching the
    // renamed artifacts commonly used to evade naive scans (e.g. `libgadget`,
    // `libhelper`). The `gadget`/`libgadget` tokens map to the same Frida signal
    // id as the explicit Frida string so the score does not double-count.
    for (uint32_t index = 0; index < _dyld_image_count(); ++index) {
      const char* image = _dyld_get_image_name(index);
      if (image == nullptr) {
        continue;
      }
      const std::string path(image);
      if (path.find("MobileSubstrate") != std::string::npos ||
          path.find("Substitute") != std::string::npos ||
          path.find("libhooker") != std::string::npos ||
          path.find("ellekit") != std::string::npos ||
          path.find("rosalie") != std::string::npos) {
        result.signals.push_back(
          buildSignal(SignalId::IOS_DYLD_HOOK, "suspicious-loaded-image", includeEvidence)
        );
        break;
      }
      // Frida / renamed gadget artifacts are reported under the same high-weight
      // signal id as Android. Keep the substring list aligned with the rename
      // patterns added to `ProcParsers.cpp` `K_HOOK_PATTERNS`.
      if (path.find("Frida") != std::string::npos ||
          path.find("frida") != std::string::npos ||
          path.find("libgadget") != std::string::npos ||
          path.find("gadget.dylib") != std::string::npos) {
        result.signals.push_back(
          buildSignal(SignalId::IOS_DYLD_HOOK, "frida-or-gadget-image", includeEvidence)
        );
        break;
      }
    }

    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_DEBUGGER));
      return result;
    }

    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    kinfo_proc process {};
    size_t size = sizeof(process);
    if (::sysctl(mib, 4, &process, &size, nullptr, 0) == 0 &&
        (process.kp_proc.p_flag & P_TRACED) != 0) {
      result.debuggerDetected = true;
      result.signals.push_back(buildSignal(SignalId::IOS_DEBUGGER_SYSCTL, "sysctl-traced", includeEvidence));
    }

    // ---- Loopback TCP service probes (Frida / SSH) --------------------------
    if (expired(deadline)) {
      result.partial = true;
    } else {
      // Only probe the iOS-relevant Frida and SSH ports; ADB is Android-only.
      constexpr PortProbe kIOSProbes[] = {
        {22,    SignalId::IOS_NETWORK_SSH,   "ssh-listener"},
        {44,    SignalId::IOS_NETWORK_SSH,   "ssh-listener-alt"},
        {27042, SignalId::IOS_NETWORK_FRIDA, "frida-listener"},
      };
      std::vector<ProcFinding> networkFindings =
        probeLocalTcpServices(kIOSProbes, sizeof(kIOSProbes) / sizeof(kIOSProbes[0]), deadline);
      for (const ProcFinding& finding : networkFindings) {
        result.signals.push_back(buildSignal(finding.signalId, finding.evidence, includeEvidence));
      }
    }
#endif
#else
    (void) includeEvidence;
    (void) deadline;
#endif
    return result;
  }

} // namespace margelo::nitro::rootjaildetect
