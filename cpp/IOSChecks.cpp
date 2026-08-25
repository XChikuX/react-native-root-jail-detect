///
/// IOSChecks.cpp
///

#include "IOSChecks.hpp"
#include "HybridUrlSchemeProbe.hpp"
#include "IOSMatchers.hpp"
#include "SignalCatalog.hpp"
#include "TcpProbe.hpp"

#include <NitroModules/HybridObjectRegistry.hpp>

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
#include <fstream>
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

  } // namespace

  IOSCheckResult runIOSChecks(bool includeEvidence,
                              std::chrono::steady_clock::time_point deadline) noexcept {
    IOSCheckContext context;
    context.includeEvidence = includeEvidence;
    context.deadline = deadline;
    return runIOSChecks(context);
  }

  IOSCheckResult runIOSChecks(const IOSCheckContext& context) noexcept {
    const bool includeEvidence = context.includeEvidence;
    IOSCheckResult result;
#if defined(__APPLE__)
#if TARGET_OS_SIMULATOR
    result.signals.push_back(buildSignal(SignalId::IOS_SIMULATOR, "ios-simulator", includeEvidence));
    return result;
#else
    const auto deadline = context.deadline;
    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_JAILBREAK));
      return result;
    }

    // ---- Filesystem artifact probes -----------------------------------------
    // Table-driven (see IOSMatchers.hpp): every literal is evidence-backed;
    // classification is a pure table lookup per path, so a device exposing
    // BOTH rootless and classic artifacts (rootless bootstrap over rootful
    // remnants) reports both classes instead of the first one evaluated
    // (v0.12.0 order-coupling bug). Removed in v0.13.0 as unverified:
    // `/private/preboot/{jb,dopamine,palera1n}` (real layout is
    // `/private/preboot/<UUID>/jb` via the `/var/jb` symlink),
    // `/var/jb/.installed_{dopamine,palera1n}` (no source evidence), and the
    // TrollStore bundle paths (TrollStore installs into normal containers;
    // see README "Threat Model" — `ios.sideload.trollstore` is parked at
    // hypothesis weight with no probe).
    bool rootlessArtifactFound = false;
    bool classicArtifactFound = false;
    bool rootlessSymlinkOnly = false;

    for (const IOSArtifactProbe& probe : IOS_ARTIFACT_PROBES) {
      struct stat status {};
      bool exists = ::stat(probe.path, &status) == 0;
      if (!exists && probe.symlinkProbe) {
        // `stat` follows symlinks: a dangling `/var/jb` (jailbreak deactivated,
        // bootstrap still laid down) is invisible to it. `lstat` sees the link
        // itself and counts it as a rootless artifact.
        struct stat linkStatus {};
        if (::lstat(probe.path, &linkStatus) == 0) {
          exists = true;
          rootlessSymlinkOnly = true;
        }
      }
      if (!exists) {
        continue;
      }
      switch (classifyIOSArtifactPath(probe.path)) {
        case IOSArtifactClass::ROOTLESS:
          rootlessArtifactFound = true;
          break;
        case IOSArtifactClass::CLASSIC:
          classicArtifactFound = true;
          break;
        case IOSArtifactClass::NONE:
          break;
      }
    }

    // Emit every matched class as its own stable signal id so callers can
    // reason about the jailbreak profile observed. Scoring deduplicates by
    // id, and a hybrid rootless+classic device is *more* compromised, not
    // less — both ids fire (40 combined weight, matching two independent
    // artifact classes; reviewed in ScoringTests).
    if (rootlessArtifactFound) {
      result.signals.push_back(
        buildSignal(SignalId::IOS_JAILBREAK_ROOTLESS,
                    rootlessSymlinkOnly ? "rootless-bootstrap-symlink" : "rootless-bootstrap-artifact",
                    includeEvidence)
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

    // ---- dyld loaded-image scan ----------------------------------------------
    // Matching lives in `IOSMatchers.hpp` (pure, host-testable):
    // case-insensitive tokens, provenance rules for the rootless bootstrap
    // tree (`/var/jb/`) and roothide `.jbroot` references, plus renamed-Frida
    // gadget patterns. At most ONE dyld signal is emitted per pass — the
    // scan answers "is a hooking/injection image loaded", not "how many";
    // duplicate emissions would double-count the same evidence.
    for (uint32_t index = 0; index < _dyld_image_count(); ++index) {
      const char* image = _dyld_get_image_name(index);
      if (image == nullptr) {
        continue;
      }
      const IOSImageVerdict verdict = matchLoadedImage(image);
      if (verdict.frida) {
        result.signals.push_back(
          buildSignal(SignalId::IOS_DYLD_HOOK, "frida-or-gadget-image", includeEvidence)
        );
        break;
      }
      if (verdict.hook) {
        result.signals.push_back(
          buildSignal(SignalId::IOS_DYLD_HOOK, "suspicious-loaded-image", includeEvidence)
        );
        break;
      }
    }

    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_DEBUGGER));
      return result;
    }

    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, static_cast<int>(getpid())};
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

    // ---- Sandbox write test -------------------------------------------------
    if (expired(deadline)) {
      result.partial = true;
      result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_SANDBOX));
    } else {
      constexpr const char* kSandboxTestPath = "/private/jbtest.txt";
      std::ofstream testFile(kSandboxTestPath);
      if (testFile.is_open()) {
        testFile << "jailbreak-test";
        testFile.close();
        std::remove(kSandboxTestPath);
        result.signals.push_back(
          buildSignal(SignalId::IOS_SANDBOX_WRITE, "sandbox-write-success", includeEvidence)
        );
      }
    }

    // ---- URL scheme checks --------------------------------------------------
    if (expired(deadline)) {
      result.partial = true;
    } else if (!context.urlSchemes.empty()) {
      std::shared_ptr<HybridUrlSchemeProbeSpec> probe = context.urlSchemeProbe;
      if (!probe) {
        try {
          std::shared_ptr<margelo::nitro::HybridObject> object =
            margelo::nitro::HybridObjectRegistry::createHybridObject("UrlSchemeProbe");
          probe = std::dynamic_pointer_cast<HybridUrlSchemeProbeSpec>(object);
        } catch (...) {
          probe = nullptr;
        }
        if (!probe) {
          // Fall back to the no-op stub so the runner can keep going.
          probe = std::make_shared<HybridUrlSchemeProbe>();
        }
      }
      try {
        bool anySchemeResponded = false;
        // Metadata for the per-scheme detail signals. Dynamic ids cannot live in
        // the static catalog, so they mirror the aggregate signal's spec but carry
        // a zero score — the aggregate below stays the single scoring contributor,
        // keeping the total identical whether or not per-scheme detail is enabled.
        const std::optional<SignalSpec> aggregateSpec =
          lookupSignal(SignalId::IOS_URLSCHEME_JAILBREAK_STORE);
        for (const std::string& scheme : context.urlSchemes) {
          bool canOpen = probe->canOpenUrl(scheme);
          if (canOpen) {
            anySchemeResponded = true;
            if (context.urlSchemesPerSignal) {
              result.signals.push_back(DetectionSignal(
                "ios.urlscheme." + scheme,
                Platform::IOS,
                aggregateSpec.has_value() ? aggregateSpec->category : SignalCategory::SANDBOX,
                aggregateSpec.has_value() ? aggregateSpec->severity : Severity::MEDIUM,
                0.0,
                true,
                aggregateSpec.has_value() ? aggregateSpec->reliability : 0.45,
                includeEvidence ? std::optional<std::string>(scheme + "://") : std::nullopt,
                std::nullopt
              ));
            }
          }
        }
        if (anySchemeResponded) {
          result.signals.push_back(buildSignal(SignalId::IOS_URLSCHEME_JAILBREAK_STORE,
                                               "jailbreak-store-schemes", includeEvidence));
        }
      } catch (...) {
        // `canOpenURL` can throw if a scheme is malformed or if UIKit is not
        // yet ready. Treat failure as unavailable, never as a detection.
        result.signals.push_back(unavailableSignal(SignalId::IOS_CHECK_URLSCHEME));
      }
    }
#endif
#else
    (void) includeEvidence;
#endif
    return result;
  }

} // namespace margelo::nitro::rootjaildetect
