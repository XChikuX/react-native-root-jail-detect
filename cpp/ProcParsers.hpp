///
/// ProcParsers.hpp
///
/// Pure, side-effect-free parsing of Linux `/proc` text formats used by the
/// Android detection path. Every function takes already-read file content and
/// returns structured findings, so the parsing logic is deterministic and
/// unit-testable with fixture strings independently of any device.
///
/// File I/O (`readFileIfExists`) is the single impure entry point and is kept
/// here because every `/proc` consumer needs the same "open, read, swallow
/// errors" shape. It never turns an unreadable file into a detection.
///

#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace margelo::nitro::rootjaildetect {

  /// One positive finding from a `/proc` scan: which known pattern matched and
  /// the redacted line/path that matched it. `evidence` is only attached to the
  /// emitted `DetectionSignal` when the caller opted into `includeEvidence`.
  struct ProcFinding final {
    /// Signal id this finding maps to (a `SignalId::*` value).
    std::string_view signalId;
    /// Redacted snippet describing what was observed (e.g. a normalized path or
    /// matched token, never a raw sensitive value).
    std::string evidence;
  };

  /// Parsed fields from one Magisk-compatible `module.prop` file.
  struct MagiskModule final {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
  };

  /// The property values used by the Android cross-checks. Keeping this value
  /// type platform-neutral makes the consistency rules fixture-testable.
  struct SystemAttributes final {
    std::string debuggable;
    std::string buildType;
    std::string secure;
    std::string verifiedBootState;
    std::string vbmetaDeviceState;
    std::string fingerprint;
    std::string buildTags;
    std::string magiskHide;
    std::string magiskDisable;
    std::string magiskDaemon;
    std::string magiskPfs;
  };

  /// Read an entire file into a string. Returns `std::nullopt` if the file
  /// cannot be opened or read. Never throws — callers treat absence as "no
  /// data", not as evidence of compromise. The overload without a deadline
  /// uses a generous default size cap for backwards compatibility.
  std::optional<std::string> readFileIfExists(std::string_view path) noexcept;

  /// Read a file with a bounded deadline and size cap. The deadline is polled
  /// between read chunks so a pathologically slow source cannot stall the
  /// entire detection pass. Excess bytes beyond `maxBytes` are discarded.
  std::optional<std::string> readFileIfExists(
    std::string_view path,
    std::chrono::steady_clock::time_point deadline,
    size_t maxBytes
  ) noexcept;

  /// Scan `/proc/self/maps` content for known Zygisk, LSPosed, Frida, and Riru
  /// library/path artifacts. Returns one finding per distinct signal id that
  /// matched (callers deduplicate further by id during scoring).
  std::vector<ProcFinding> scanMapsForHooks(std::string_view mapsContent) noexcept;

  /// Find a small cluster of executable anonymous mappings. A single anonymous
  /// executable region is common on ART/JIT devices and is deliberately ignored;
  /// this low-confidence heuristic requires at least two regions.
  std::vector<ProcFinding> parseMapsForAnonymousInjection(std::string_view mapsContent) noexcept;

  /// Alias with the scan naming used by the Android orchestrator.
  std::vector<ProcFinding> scanMapsForAnonymousInjection(std::string_view mapsContent) noexcept;

  /// Parse one or more newline-separated `module.prop` documents. Documents may
  /// be separated by a blank line, which is convenient for host-side fixtures.
  std::vector<MagiskModule> parseMagiskModulesProps(std::string_view propsContent) noexcept;

  /// Parse the system-property cross-checks without touching Android APIs.
  std::vector<ProcFinding> parseSystemAttributeInconsistencies(
    const SystemAttributes& attributes
  ) noexcept;

  /// Convenience overload for fixture callers that model properties as a map.
  std::vector<ProcFinding> parseSystemAttributeInconsistencies(
    const std::map<std::string, std::string>& properties
  ) noexcept;

  /// Scan `/proc/self/mountinfo` and `/proc/self/mounts` content for Magisk /
  /// KernelSU / APatch overlay artifacts and suspicious bind mounts. Both
  /// inputs are optional (pass empty strings when a source was unavailable).
  std::vector<ProcFinding> scanMountsForRootArtifacts(
    std::string_view mountinfoContent,
    std::string_view mountsContent
  ) noexcept;

  /// Find a conservative multi-layer root-overlay candidate in mount metadata.
  std::vector<ProcFinding> scanMountsForMagiskChain(std::string_view mountinfoContent) noexcept;

  /// Find suspicious mount artifacts visible in the app namespace but absent
  /// from the initial namespace. Namespace identity is never a finding by
  /// itself; only known root-framework content that differs is reported.
  std::vector<ProcFinding> scanNamespaceOnlyMountArtifacts(
    std::string_view selfMountinfoContent,
    std::string_view initMountinfoContent
  ) noexcept;

  /// Parse `TracerPid:` from `/proc/self/status` content. Returns `std::nullopt`
  /// when the field is absent or unparseable. A nonzero value means a tracer is
  /// attached; this is reported as an informational signal, not as compromise.
  std::optional<int> parseTracerPid(std::string_view statusContent) noexcept;

  /// Parse the contents of `/sys/fs/selinux/enforce`. Returns `std::nullopt`
  /// when the file is absent or unparseable, `false` when SELinux is in
  /// permissive/disabled mode, and `true` when enforcing.
  std::optional<bool> parseSelinuxEnforce(std::string_view enforceContent) noexcept;

} // namespace margelo::nitro::rootjaildetect
