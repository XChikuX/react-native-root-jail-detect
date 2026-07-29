///
/// AndroidChecks.cpp
///

#include "AndroidChecks.hpp"
#include "AndroidProbes.hpp"
#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"

#include <string>
#include <utility>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  namespace {

    // Canonical `/proc` and `/sys` paths probed by the Android baseline.
    constexpr std::string_view K_PROC_MAPS = "/proc/self/maps";
    constexpr std::string_view K_PROC_MOUNTINFO = "/proc/self/mountinfo";
    constexpr std::string_view K_PROC_MOUNTS = "/proc/self/mounts";
    constexpr std::string_view K_PROC_STATUS = "/proc/self/status";
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

    // Append findings as signals. `available=false` is not used here because
    // each detector only emits a finding when it actually matched something.
    void appendFindings(std::vector<DetectionSignal>& signals,
                        const std::vector<ProcFinding>& findings, bool includeEvidence) noexcept {
      for (const ProcFinding& finding : findings) {
        signals.push_back(buildSignal(finding.signalId, finding.evidence, includeEvidence));
      }
    }

  } // namespace

  AndroidCheckResult runAndroidChecks(bool includeEvidence) noexcept {
    AndroidCheckResult result;

    // ---- Memory maps: Zygisk / LSPosed / Frida / Riru ----------------------
    if (auto maps = readFileIfExists(K_PROC_MAPS)) {
      appendFindings(result.signals, scanMapsForHooks(*maps), includeEvidence);
    }

    // ---- Mount metadata: Magisk / KSU / APatch overlays --------------------
    std::optional<std::string> mountinfo = readFileIfExists(K_PROC_MOUNTINFO);
    std::optional<std::string> mounts = readFileIfExists(K_PROC_MOUNTS);
    if (mountinfo.has_value() || mounts.has_value()) {
      appendFindings(
        result.signals,
        scanMountsForRootArtifacts(mountinfo.value_or(""), mounts.value_or("")),
        includeEvidence
      );
    }

    // ---- SELinux enforcement state -----------------------------------------
    if (auto enforce = readFileIfExists(K_SELINUX_ENFORCE)) {
      std::optional<bool> enforcing = parseSelinuxEnforce(*enforce);
      if (enforcing.has_value() && !enforcing.value()) {
        // Permissive/disabled SELinux on what should be a production device.
        result.signals.push_back(
          buildSignal(SignalId::ANDROID_SELINUX_PERMISSIVE, "selinux=enforce:0", includeEvidence)
        );
      }
    }

    // ---- Root-manager paths and `su` binaries ------------------------------
    appendFindings(result.signals, probeRootPaths(), includeEvidence);

    // ---- Build / verified-boot properties ----------------------------------
    appendFindings(result.signals, probeBuildProperties(), includeEvidence);

    // ---- Debugger: TracerPid (informational) -------------------------------
    if (auto status = readFileIfExists(K_PROC_STATUS)) {
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
    }

    return result;
  }

} // namespace margelo::nitro::rootjaildetect
