///
/// ProcParsers.cpp
///

#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

namespace margelo::nitro::rootjaildetect {

  namespace {

    // ---- Known artifact tokens ------------------------------------------------
    // Substring tokens are matched case-insensitively against the path segment
    // of a maps/mount line. They intentionally avoid generic tokens that would
    // fire on stock devices. Each list maps to a single signal id; scoring
    // deduplicates by id so multiple distinct Frida artifacts still count once.

    struct PatternEntry {
      std::string_view token;
      std::string_view signalId;
    };

    // Libraries/process names injected by Zygisk/LSPosed/Frida/Riru. Matched
    // against the full maps line (pathname segment, but a full-line substring
    // search is safe because these tokens are specific enough).
    constexpr PatternEntry K_HOOK_PATTERNS[] = {
      // Zygisk (Magisk's module framework) and known module loaders.
      {"zygisk",        SignalId::ANDROID_MAPS_ZYGISK},
      {"magisk-zisk",   SignalId::ANDROID_MAPS_ZYGISK},
      {"libzygisk",     SignalId::ANDROID_MAPS_ZYGISK},
      // LSPosed / Xposed (often loaded via Riru or Zygisk).
      {"lsposed",       SignalId::ANDROID_MAPS_LSPOSED},
      {"xposed",        SignalId::ANDROID_MAPS_LSPOSED},
      // Frida agent and its well-known thread/pipe artifacts.
      {"frida",           SignalId::ANDROID_MAPS_FRIDA},
      {"frida-agent",     SignalId::ANDROID_MAPS_FRIDA},
      {"gum-js-loop",     SignalId::ANDROID_MAPS_FRIDA},
      {"gmain",           SignalId::ANDROID_MAPS_FRIDA},
      {"linjector",       SignalId::ANDROID_MAPS_FRIDA},
      {"pool-frida",      SignalId::ANDROID_MAPS_FRIDA},
      // Renamed Frida gadgets. These are intentionally specific to keep false
      // positives low; "libhelper" and "gadget" are meaningful only as mapped
      // module names in memory, not as generic substrings in unrelated text.
      {"libgadget",       SignalId::ANDROID_MAPS_FRIDA},
      {"gadget.so",       SignalId::ANDROID_MAPS_FRIDA},
      {"libhelper.so",    SignalId::ANDROID_MAPS_FRIDA},
      // Riru (legacy Magisk module framework, predecessor of Zygisk).
      {"libriru",         SignalId::ANDROID_MAPS_RIRU},
      {"riru",            SignalId::ANDROID_MAPS_RIRU},
    };

    // Tokens that, when seen in mount metadata, strongly suggest a root
    // framework's overlay/bind mounts are present. Note: `kernelsu` and `apatch`
    // map to `ANDROID_MOUNT_MAGISK` by design so all root-framework mount
    // artifacts share one published signal class and deduplicate cleanly.
    constexpr PatternEntry K_MOUNT_PATTERNS[] = {
      {"magisk",        SignalId::ANDROID_MOUNT_MAGISK},
      {".magisk",       SignalId::ANDROID_MOUNT_MAGISK},
      {"magisk_mirror", SignalId::ANDROID_MOUNT_MAGISK},
      {"kernelsu",      SignalId::ANDROID_MOUNT_MAGISK},
      {"apatch",        SignalId::ANDROID_MOUNT_MAGISK},
      {"/data/adb",     SignalId::ANDROID_MOUNT_MAGISK},
    };

    // Case-insensitive substring search. `std::string_view::find` is
    // case-sensitive, so we fall back to a small manual scan. Inputs here are
    // tiny (a few dozen tokens per scan against lines of a proc file), so a
    // straightforward implementation is both clear and fast enough.
    bool containsCI(std::string_view haystack, std::string_view needle) noexcept {
      if (needle.empty()) {
        return true;
      }
      if (haystack.size() < needle.size()) {
        return false;
      }
      const size_t end = haystack.size() - needle.size();
      for (size_t i = 0; i <= end; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
          if (std::tolower(static_cast<unsigned char>(haystack[i + j])) !=
              std::tolower(static_cast<unsigned char>(needle[j]))) {
            match = false;
            break;
          }
        }
        if (match) {
          return true;
        }
      }
      return false;
    }

    // Strip a `/proc/self/maps` line down to its optional pathname (the
    // whitespace-delimited trailing field) so evidence stays compact and we do
    // not attach raw address ranges to signals.
    std::string_view mapsPathname(std::string_view line) noexcept {
      // Format: address perms offset dev inode pathname
      // Walk fields separated by runs of whitespace.
      size_t pos = 0;
      int field = 0;
      while (field < 5 && pos < line.size()) {
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) {
          ++pos;
        }
        while (pos < line.size() && !std::isspace(static_cast<unsigned char>(line[pos]))) {
          ++pos;
        }
        ++field;
      }
      while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) {
        ++pos;
      }
      return line.substr(pos);
    }

    struct MapsRegion final {
      std::string_view permissions;
      std::string_view pathname;
    };

    std::optional<MapsRegion> parseMapsRegion(std::string_view line) noexcept {
      size_t starts[6] = {};
      size_t ends[6] = {};
      size_t field = 0;
      size_t pos = 0;
      while (field < 6) {
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) {
          ++pos;
        }
        if (pos >= line.size()) {
          break;
        }
        starts[field] = pos;
        while (pos < line.size() && !std::isspace(static_cast<unsigned char>(line[pos]))) {
          ++pos;
        }
        ends[field] = pos;
        ++field;
      }
      if (field < 5) {
        return std::nullopt;
      }
      size_t pathnameStart = ends[4];
      while (pathnameStart < line.size() &&
             std::isspace(static_cast<unsigned char>(line[pathnameStart]))) {
        ++pathnameStart;
      }
      return MapsRegion{
        line.substr(starts[1], ends[1] - starts[1]),
        line.substr(pathnameStart),
      };
    }

    std::string trim(std::string_view value) {
      size_t begin = 0;
      while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) {
        ++begin;
      }
      size_t end = value.size();
      while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
      }
      return std::string(value.substr(begin, end - begin));
    }

    void parseModuleDocument(std::string_view document, std::vector<MagiskModule>& modules) {
      MagiskModule module;
      size_t lineStart = 0;
      for (size_t i = 0; i <= document.size(); ++i) {
        if (i != document.size() && document[i] != '\n') {
          continue;
        }
        std::string_view line = document.substr(lineStart, i - lineStart);
        const size_t separator = line.find('=');
        if (separator != std::string_view::npos) {
          const std::string key = trim(line.substr(0, separator));
          const std::string value = trim(line.substr(separator + 1));
          if (key == "id") module.id = value;
          else if (key == "name") module.name = value;
          else if (key == "version") module.version = value;
          else if (key == "author") module.author = value;
        }
        lineStart = i + 1;
      }
      if (!module.id.empty() || !module.name.empty()) {
        modules.push_back(std::move(module));
      }
    }

    void recordOnce(std::vector<ProcFinding>& out, std::vector<std::string_view>& seen,
                    std::string_view signalId, std::string evidence) {
      // Keep only the first match per signal id. Evidence from the first hit is
      // sufficient for a human-readable reason; later duplicates would only
      // inflate the payload without changing the score.
      if (std::find(seen.begin(), seen.end(), signalId) != seen.end()) {
        return;
      }
      seen.push_back(signalId);
      out.push_back(ProcFinding{signalId, std::move(evidence)});
    }

    void scanLines(std::string_view content, const PatternEntry* entries, size_t entryCount,
                   std::vector<ProcFinding>& out, std::vector<std::string_view>& seen,
                   bool usePathnameOnly) {
      size_t lineStart = 0;
      for (size_t i = 0; i <= content.size(); ++i) {
        if (i == content.size() || content[i] == '\n') {
          std::string_view line = content.substr(lineStart, i - lineStart);
          std::string_view haystack = usePathnameOnly ? mapsPathname(line) : line;
          if (!haystack.empty()) {
            for (size_t e = 0; e < entryCount; ++e) {
              if (containsCI(haystack, entries[e].token)) {
                // Keep evidence explainable without returning raw mount lines or
                // mapped paths, which can disclose app-private locations.
                std::string evidence(entries[e].token);
                recordOnce(out, seen, entries[e].signalId, std::move(evidence));
                break; // one signal per maps line is enough
              }
            }
          }
          lineStart = i + 1;
        }
      }
    }

  } // namespace

  /**
   * Read a file with a bounded deadline and optional size cap.
   *
   * Implementation constraints:
   *   - The deadline is checked periodically while reading; a single read will
   *     not be split, but the loop polls between chunks so a slow source cannot
   *     stall the entire pass indefinitely.
   *   - `maxBytes` limits how many bytes we will allocate/return. Excess bytes
   *     beyond the cap are discarded and the partial content is returned.
   *   - Any I/O failure is treated as "no data"; a missing/unreadable `/proc`
   *     entry must never become evidence of compromise.
   */
  std::optional<std::string> readFileIfExists(std::string_view path,
                                              std::chrono::steady_clock::time_point deadline,
                                              size_t maxBytes) noexcept {
    try {
      std::ifstream stream(std::string(path), std::ios::binary);
      if (!stream.is_open()) {
        return std::nullopt;
      }

      std::string contents;
      contents.reserve(std::min(maxBytes, static_cast<size_t>(8192)));

      constexpr size_t kChunkSize = 4096;
      char chunk[kChunkSize];
      bool deadlineExceeded = false;

      while (stream.good() && contents.size() < maxBytes) {
        // Poll the deadline between chunks so a pathologically slow file cannot
        // burn the entire pass budget.
        if (std::chrono::steady_clock::now() >= deadline) {
          deadlineExceeded = true;
          break;
        }
        stream.read(chunk, static_cast<std::streamsize>(std::min(
                             kChunkSize, maxBytes - contents.size())));
        const std::streamsize bytesRead = stream.gcount();
        if (bytesRead > 0) {
          contents.append(chunk, static_cast<size_t>(bytesRead));
        }
      }

      if (stream.bad() && contents.empty()) {
        return std::nullopt;
      }
      if (deadlineExceeded && contents.empty()) {
        return std::nullopt;
      }
      return contents;
    } catch (...) {
      // Any I/O failure is treated as "no data". A missing/unreadable `/proc`
      // entry must never become evidence of compromise.
      return std::nullopt;
    }
  }

  std::optional<std::string> readFileIfExists(std::string_view path) noexcept {
    // Provide the legacy overload with "no deadline" and a generous size cap for
    // callers that do not yet pass a deadline.
    return readFileIfExists(path, std::chrono::steady_clock::time_point::max(),
                            static_cast<size_t>(512 * 1024));
  }

  std::vector<ProcFinding> scanMapsForHooks(std::string_view mapsContent) noexcept {
    std::vector<ProcFinding> findings;
    std::vector<std::string_view> seen;
    scanLines(mapsContent, K_HOOK_PATTERNS, sizeof(K_HOOK_PATTERNS) / sizeof(K_HOOK_PATTERNS[0]),
              findings, seen, /*usePathnameOnly=*/true);
    return findings;
  }

  std::vector<ProcFinding> parseMapsForAnonymousInjection(std::string_view mapsContent) noexcept {
    std::vector<ProcFinding> findings;
    size_t executableAnonymousCount = 0;
    size_t lineStart = 0;
    for (size_t i = 0; i <= mapsContent.size(); ++i) {
      if (i != mapsContent.size() && mapsContent[i] != '\n') {
        continue;
      }
      const std::string_view line = mapsContent.substr(lineStart, i - lineStart);
      if (const auto region = parseMapsRegion(line)) {
        const bool executable = region->permissions.find('x') != std::string_view::npos;
        const bool anonymous = region->pathname.empty() || region->pathname.rfind("[anon:", 0) == 0;
        if (executable && anonymous) {
          ++executableAnonymousCount;
        }
      }
      lineStart = i + 1;
    }
    // ART/JIT commonly exposes one executable anonymous VMA. Require a cluster
    // so this remains corroboration rather than a standalone compromise proof.
    if (executableAnonymousCount >= 2) {
      findings.push_back(ProcFinding{
        SignalId::ANDROID_MAPS_ANON_INJECTION,
        "executable-anonymous-mappings=" + std::to_string(executableAnonymousCount),
      });
    }
    return findings;
  }

  std::vector<ProcFinding> scanMapsForAnonymousInjection(std::string_view mapsContent) noexcept {
    return parseMapsForAnonymousInjection(mapsContent);
  }

  std::vector<MagiskModule> parseMagiskModulesProps(std::string_view propsContent) noexcept {
    std::vector<MagiskModule> modules;
    size_t documentStart = 0;
    for (size_t i = 0; i <= propsContent.size(); ++i) {
      const bool boundary = i == propsContent.size() ||
        (propsContent[i] == '\n' && i + 1 < propsContent.size() && propsContent[i + 1] == '\n');
      if (boundary) {
        parseModuleDocument(propsContent.substr(documentStart, i - documentStart), modules);
        documentStart = i + 2;
        if (i == propsContent.size()) {
          break;
        }
      }
    }
    return modules;
  }

  std::vector<ProcFinding> parseSystemAttributeInconsistencies(
    const SystemAttributes& attributes
  ) noexcept {
    std::vector<ProcFinding> findings;
    std::vector<std::string_view> seen;
    auto add = [&](std::string_view id, std::string evidence) {
      recordOnce(findings, seen, id, std::move(evidence));
    };

    if (attributes.debuggable == "0" && attributes.buildType == "userdebug") {
      add(SignalId::ANDROID_PROPS_INCONSISTENT_DEBUGGABLE, "ro.debuggable=0/build_type=userdebug");
    }
    if (attributes.debuggable == "1" && attributes.secure == "1") {
      add(SignalId::ANDROID_PROPS_INCONSISTENT_DEBUGGABLE, "ro.debuggable=1/ro.secure=1");
    }
    if ((attributes.verifiedBootState == "green" || attributes.verifiedBootState == "GREEN") &&
        (attributes.vbmetaDeviceState == "unlocked" || attributes.vbmetaDeviceState == "UNLOCKED")) {
      add(SignalId::ANDROID_PROPS_INCONSISTENT_VERIFIEDBOOT, "verifiedboot=green/vbmeta=unlocked");
    }
    if (containsCI(attributes.fingerprint, "release-keys") &&
        containsCI(attributes.buildTags, "test-keys")) {
      add(SignalId::ANDROID_PROPS_INCONSISTENT_FINGERPRINT, "fingerprint=release-keys/tags=test-keys");
    }
    if (containsCI(attributes.fingerprint, "/user/") && attributes.buildType == "userdebug") {
      add(SignalId::ANDROID_PROPS_INCONSISTENT_FINGERPRINT, "fingerprint=user/build_type=userdebug");
    }
    if (!attributes.magiskHide.empty() || !attributes.magiskDisable.empty() ||
        !attributes.magiskDaemon.empty() || !attributes.magiskPfs.empty()) {
      add(SignalId::ANDROID_MAGISK_DISABLE_PROP, "magisk-specific-property-present");
    }
    return findings;
  }

  std::vector<ProcFinding> parseSystemAttributeInconsistencies(
    const std::map<std::string, std::string>& properties
  ) noexcept {
    const auto value = [&properties](std::string_view key) -> std::string {
      const auto found = properties.find(std::string(key));
      return found == properties.end() ? std::string() : found->second;
    };
    return parseSystemAttributeInconsistencies(SystemAttributes{
      value("ro.debuggable"),
      value("ro.build.type"),
      value("ro.secure"),
      value("ro.boot.verifiedbootstate"),
      value("ro.boot.vbmeta.device_state"),
      value("ro.build.fingerprint"),
      value("ro.build.tags"),
      value("persist.magisk.hide"),
      value("ro.magisk.disable"),
      value("init.svc.magisk_daemon"),
      value("init.svc.magisk_pfs"),
    });
  }

  std::vector<ProcFinding> scanMountsForRootArtifacts(
    std::string_view mountinfoContent,
    std::string_view mountsContent
  ) noexcept {
    std::vector<ProcFinding> findings;
    std::vector<std::string_view> seen;
    // For mounts we match against the whole line because the relevant tokens
    // (mount source, mount point, super options) can appear in any field.
    scanLines(mountinfoContent, K_MOUNT_PATTERNS, sizeof(K_MOUNT_PATTERNS) / sizeof(K_MOUNT_PATTERNS[0]),
              findings, seen, /*usePathnameOnly=*/false);
    scanLines(mountsContent, K_MOUNT_PATTERNS, sizeof(K_MOUNT_PATTERNS) / sizeof(K_MOUNT_PATTERNS[0]),
              findings, seen, /*usePathnameOnly=*/false);
    return findings;
  }

  std::vector<ProcFinding> scanMountsForMagiskChain(std::string_view mountinfoContent) noexcept {
    size_t suspiciousLayers = 0;
    size_t lineStart = 0;
    for (size_t i = 0; i <= mountinfoContent.size(); ++i) {
      if (i != mountinfoContent.size() && mountinfoContent[i] != '\n') {
        continue;
      }
      const std::string_view line = mountinfoContent.substr(lineStart, i - lineStart);
      if (containsCI(line, "magisk") || containsCI(line, "/data/adb") ||
          containsCI(line, "overlay") || containsCI(line, "/debug_ramdisk")) {
        ++suspiciousLayers;
      }
      lineStart = i + 1;
    }
    if (suspiciousLayers >= 3) {
      return {ProcFinding{
        SignalId::ANDROID_MOUNT_MAGISK_CHAIN,
        "layered-suspicious-mounts=" + std::to_string(suspiciousLayers),
      }};
    }
    return {};
  }

  std::vector<ProcFinding> scanNamespaceOnlyMountArtifacts(
    std::string_view selfMountinfoContent,
    std::string_view initMountinfoContent
  ) noexcept {
    std::vector<ProcFinding> findings;
    // A different mount namespace is normal for Android apps, and `/proc/1/mountinfo`
    // is unreadable by untrusted apps on stock Android (PID 1 is hidden by SELinux).
    // The namespace-only comparison is therefore mostly dead code on production
    // devices. It is retained as a low-weight fallback for environments where the
    // init namespace happens to be visible (emulators, some debug builds), but the
    // real overlay detection work is shifting to structured self-namespace path
    // diffs and `statx(STATX_ATTR_MOUNT_ROOT)` in later hardening (see the Roadmap in README.md).
    for (const PatternEntry& entry : K_MOUNT_PATTERNS) {
      if (containsCI(selfMountinfoContent, entry.token) &&
          !containsCI(initMountinfoContent, entry.token)) {
        findings.push_back(ProcFinding{SignalId::ANDROID_MOUNT_OVERLAY,
                                       "namespace-only-root-artifact"});
        break;
      }
    }
    return findings;
  }

  std::optional<int> parseTracerPid(std::string_view statusContent) noexcept {
    // Locate the `TracerPid:` line and parse the integer that follows.
    constexpr std::string_view kPrefix = "TracerPid:";
    size_t pos = statusContent.find(kPrefix);
    if (pos == std::string_view::npos) {
      return std::nullopt;
    }
    pos += kPrefix.size();
    // Skip whitespace between the label and the value.
    while (pos < statusContent.size() &&
           std::isspace(static_cast<unsigned char>(statusContent[pos]))) {
      ++pos;
    }
    int value = 0;
    auto [end, ec] = std::from_chars(
      statusContent.data() + pos,
      statusContent.data() + statusContent.size(),
      value
    );
    if (ec != std::errc{}) {
      return std::nullopt;
    }
    (void) end;
    return value;
  }

  std::optional<bool> parseSelinuxEnforce(std::string_view enforceContent) noexcept {
    // `/sys/fs/selinux/enforce` contains a single "0" or "1". Trim whitespace.
    size_t pos = 0;
    while (pos < enforceContent.size() &&
           std::isspace(static_cast<unsigned char>(enforceContent[pos]))) {
      ++pos;
    }
    if (pos >= enforceContent.size()) {
      return std::nullopt;
    }
    char c = enforceContent[pos];
    if (c == '1') {
      return true;  // enforcing
    }
    if (c == '0') {
      return false; // permissive
    }
    return std::nullopt;
  }

} // namespace margelo::nitro::rootjaildetect
