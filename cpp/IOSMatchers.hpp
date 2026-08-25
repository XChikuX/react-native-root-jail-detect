///
/// IOSMatchers.hpp
///
/// Pure, side-effect-free matching logic for the iOS detection path
/// (WS-I-C/WS-I-D of the iOS remediation plan). Extracted from
/// `IOSChecks.cpp` so the artifact-path classification and the dyld
/// loaded-image matching are fixture-testable on the host, exactly like the
/// Android `ProcParsers` split.
///
/// Everything here is deterministic over input strings: no filesystem, no
/// dyld APIs, no platform headers. `IOSChecks.cpp` owns the impure side
/// (stat/lstat/_dyld) and calls into these helpers.
///
/// Verified-observable policy (see IOS_PLAN.md and README "Threat Model"):
///   - Every literal in `IOS_ARTIFACT_PROBES` is backed by public evidence
///     (jailbreak tool documentation or source). Literals that could not be
///     verified (`.installed_dopamine`, `.installed_palera1n`, the TrollStore
///     bundle paths, the bare `/private/preboot/<name>` forms) were removed
///     rather than shipped as implied coverage.
///   - Roothide-class environments randomize their bootstrap path and are a
///     documented false-negative ceiling for path-based checks; the
///     `/.jbroot` image-location rule below catches *loaded* roothide
///     artifacts but not a hidden, inactive bootstrap.
///

#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>

namespace margelo::nitro::rootjaildetect {

  /// Classification of an iOS jailbreak artifact path. Profile-specific
  /// classes (Dopamine/palera1n/TrollStore) have no verified filesystem
  /// observables as of 2026-08 and are therefore not probeable; their signal
  /// ids remain in the public catalog but nothing feeds them.
  enum class IOSArtifactClass {
    NONE,     ///< Not a known artifact path.
    CLASSIC,  ///< Rootful-era artifact at a classic rootfs path.
    ROOTLESS, ///< Rootless bootstrap artifact (iOS 15+ convention).
  };

  /// One filesystem probe: a path and the class a positive `stat`/`lstat`
  /// result belongs to. `symlinkProbe` marks paths where a dangling symlink
  /// (found via `lstat` after `stat` fails) still counts as an artifact —
  /// a `/var/jb` left dangling means the jailbreak is deactivated but the
  /// bootstrap is still laid down on disk.
  struct IOSArtifactProbe {
    const char* path;
    IOSArtifactClass clazz;
    bool symlinkProbe;
  };

  /// The probe table. Evidence-backed entries only:
  ///   - `/var/jb` and `/private/jb`: the rootless bootstrap symlink
  ///     convention shared by Dopamine, palera1n rootless, and procursus-based
  ///     bootstraps (points to `/private/preboot/<UUID>/jb` — the bare
  ///     `/private/preboot/jb` literal is NOT a real layout and was removed).
  ///   - `/var/jb/usr/lib/TweakInject.dylib`: tweak-injection location used by
  ///     rootless bootstraps (ElleKit et al.).
  ///   - Classic rootful artifacts: Cydia.app, MobileSubstrate.dylib,
  ///     procursus strap marker, Sileo/Zebra app bundles.
  inline constexpr std::array<IOSArtifactProbe, 8> IOS_ARTIFACT_PROBES{{
    {"/var/jb", IOSArtifactClass::ROOTLESS, true},
    {"/private/jb", IOSArtifactClass::ROOTLESS, true},
    {"/var/jb/usr/lib/TweakInject.dylib", IOSArtifactClass::ROOTLESS, false},
    {"/Applications/Cydia.app", IOSArtifactClass::CLASSIC, false},
    {"/Applications/Sileo.app", IOSArtifactClass::CLASSIC, false},
    {"/Applications/Zebra.app", IOSArtifactClass::CLASSIC, false},
    {"/Library/MobileSubstrate/MobileSubstrate.dylib", IOSArtifactClass::CLASSIC, false},
    {"/.procursus_strapped", IOSArtifactClass::CLASSIC, false},
  }};

  /// Classify an existing path into its artifact class. Classification is a
  /// pure table lookup — deliberately NOT substring matching — so a path
  /// belongs to exactly one class regardless of probe iteration order
  /// (fixes the order-coupled classification shipped in v0.12.0).
  inline IOSArtifactClass classifyIOSArtifactPath(std::string_view path) noexcept {
    for (const IOSArtifactProbe& probe : IOS_ARTIFACT_PROBES) {
      if (path == probe.path) {
        return probe.clazz;
      }
    }
    return IOSArtifactClass::NONE;
  }

  /// Verdict for one loaded dyld image. `hook` and `frida` are disjoint
  /// classes reported under distinct evidence strings; both map to the same
  /// `ios.dyld.hook` catalog weight upstream.
  struct IOSImageVerdict {
    bool hook = false;   ///< Hooking/injection framework (incl. provenance rule).
    bool frida = false;  ///< Frida agent or renamed gadget.
    const char* token = nullptr; ///< Matched token (for evidence); null when no match.
  };

  namespace detail {

    /// ASCII-only lowercase of a path component for case-insensitive
    /// matching. Paths from dyld are ASCII on iOS; non-ASCII bytes pass
    /// through unchanged (they never match a token).
    inline char asciiLower(char c) noexcept {
      return static_cast<char>(
        std::tolower(static_cast<unsigned char>(c))
      );
    }

    inline bool containsCI(std::string_view haystack, std::string_view needle) noexcept {
      if (needle.empty() || haystack.size() < needle.size()) {
        return false;
      }
      const size_t last = haystack.size() - needle.size();
      for (size_t i = 0; i <= last; ++i) {
        size_t j = 0;
        while (j < needle.size() &&
               asciiLower(haystack[i + j]) == needle[j]) {
          ++j;
        }
        if (j == needle.size()) {
          return true;
        }
      }
      return false;
    }

  } // namespace detail

  /// Match a loaded dyld image path against the injection/hooking corpus.
  ///
  /// Rules (WS-I-E):
  ///   - Case-insensitive token match (a renamed `ElleKit` build with any
  ///     capitalization is caught; v0.12.0 missed all non-lowercase variants).
  ///   - Tokens are lowercase; callers pass the raw path.
  ///   - Provenance rule: any image loaded from the rootless bootstrap tree
  ///     (`/var/jb/`) or referencing a roothide `.jbroot` bootstrap counts as
  ///     hook-class evidence by location, catching fully renamed frameworks.
  ///   - At most one verdict per image; the caller emits at most one dyld
  ///     signal per pass (documented — do not "fix" into duplicate scoring).
  inline IOSImageVerdict matchLoadedImage(std::string_view imagePath) noexcept {
    IOSImageVerdict verdict;
    if (imagePath.empty()) {
      return verdict;
    }

    constexpr std::string_view kHookTokens[] = {
      // Hooking frameworks (lowercase; matched case-insensitively).
      "mobilesubstrate",
      "cydiasubstrate", // on-disk name on older rootful setups
      "substitute",
      "libhooker",
      "ellekit",
      "rosalie",
      "cynject",
    };
    for (std::string_view token : kHookTokens) {
      if (detail::containsCI(imagePath, token)) {
        verdict.hook = true;
        verdict.token = "token";
        return verdict;
      }
    }

    constexpr std::string_view kFridaTokens[] = {
      "frida",
      "libgadget",
      "gadget.dylib",
    };
    for (std::string_view token : kFridaTokens) {
      if (detail::containsCI(imagePath, token)) {
        verdict.frida = true;
        verdict.token = "frida-token";
        return verdict;
      }
    }

    // Provenance rule: loaded from the rootless bootstrap tree or a roothide
    // randomized bootstrap. These path shapes are exclusive to jailbreak
    // packaging — no stock image resolves under `/var/jb/` or a `.jbroot`
    // symlink (the roothide convention: every directory containing a Mach-O
    // carries a `.jbroot` symlink; dyld paths reference it via
    // `@loader_path/.jbroot/...`).
    if (imagePath.find("/var/jb/") != std::string_view::npos ||
        imagePath.find("/.jbroot") != std::string_view::npos) {
      verdict.hook = true;
      verdict.token = "bootstrap-path";
      return verdict;
    }

    return verdict;
  }

} // namespace margelo::nitro::rootjaildetect
