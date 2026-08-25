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
#include <iterator>
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

    // A parsed mountinfo line. The mount point is always the 5th
    // whitespace-delimited field; the filesystem type and mount source follow
    // the literal `-` separator that terminates the variable-length
    // optional-fields run (`shared`, `master`, `propagate_from`, `unbindable`),
    // so they are located relative to that separator, never by fixed column.
    // `superOptions` is the raw remainder after the source field (overlayfs
    // `lowerdir=`/`upperdir=`/`workdir=` live there).
    struct MountinfoLine {
      std::string_view mountPoint;
      std::string_view fsType;
      std::string_view source;
      std::string_view superOptions;
      bool valid = false;
    };

    MountinfoLine parseMountinfoLine(std::string_view line) noexcept {
      MountinfoLine parsed;
      std::vector<std::string_view> fields;
      size_t pos = 0;
      while (pos < line.size()) {
        while (pos < line.size() &&
               std::isspace(static_cast<unsigned char>(line[pos]))) {
          ++pos;
        }
        if (pos >= line.size()) {
          break;
        }
        const size_t start = pos;
        while (pos < line.size() &&
               !std::isspace(static_cast<unsigned char>(line[pos]))) {
          ++pos;
        }
        fields.push_back(line.substr(start, pos - start));
      }

      constexpr size_t kMountPointField = 4;
      if (fields.size() <= kMountPointField) {
        return parsed;
      }
      parsed.mountPoint = fields[kMountPointField];

      size_t separator = kMountPointField + 1;
      while (separator < fields.size() && fields[separator] != "-") {
        ++separator;
      }
      if (separator + 2 < fields.size()) {
        parsed.fsType = fields[separator + 1];
        parsed.source = fields[separator + 2];
        if (separator + 3 < fields.size()) {
          // The super-options are everything from the first field after the
          // source to the end of the line (joined as-is; separators within
          // are commas, which the callers parse themselves).
          parsed.superOptions = line.substr(
            static_cast<size_t>(fields[separator + 3].data() - line.data())
          );
        }
        parsed.valid = true;
      }
      return parsed;
    }

    // Extract the value of a `key=` mount super-option. The key must sit on an
    // option *boundary*: start of the super-options blob or directly after an
    // unescaped comma (the option separator). A key name occurring inside
    // another option's value (e.g. `lowerdir=/x/myupperdir=/y`) must not match,
    // otherwise classification keys off fabricated directories. The value ends
    // at the next unescaped comma (a `\,` sequence is libmount escaping for a
    // literal comma inside the value, not an option separator); a comma only
    // terminates the value when it is not itself escaped.
    std::string_view optionValue(std::string_view superOptions, std::string_view key) noexcept {
      size_t searchFrom = 0;
      while (searchFrom <= superOptions.size()) {
        const size_t keyStart = superOptions.find(key, searchFrom);
        if (keyStart == std::string_view::npos) {
          return {};
        }
        const bool afterStart = keyStart == 0;
        const bool afterUnescapedComma =
          keyStart > 0 && superOptions[keyStart - 1] == ',' &&
          (keyStart < 2 || superOptions[keyStart - 2] != '\\');
        if (afterStart || afterUnescapedComma) {
          const size_t valueStart = keyStart + key.size();
          size_t end = valueStart;
          while (end < superOptions.size()) {
            if (superOptions[end] == ',' && superOptions[end - 1] != '\\') {
              break;
            }
            ++end;
          }
          return superOptions.substr(valueStart, end - valueStart);
        }
        searchFrom = keyStart + 1;
      }
      return {};
    }

    // Split a colon-separated overlayfs directory list (`lowerdir=/a:/b:/c`; the
    // separator is `:` per kernel Documentation/filesystems/overlayfs.rst —
    // Android system paths never contain colons). Empty components are dropped.
    void splitOverlayDirs(std::string_view value, std::vector<std::string_view>& out) noexcept {
      size_t start = 0;
      while (start <= value.size()) {
        const size_t colon = value.find(':', start);
        const size_t end = colon == std::string_view::npos ? value.size() : colon;
        if (end > start) {
          out.push_back(value.substr(start, end - start));
        }
        if (colon == std::string_view::npos) {
          break;
        }
        start = colon + 1;
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
        // Only truly unnamed mappings count. ART/JIT exposes *named* anonymous
        // regions on stock devices (e.g. `[anon:dalvik-jit-code-cache]`,
        // `[anon:libc_malloc]`); counting those produced false positives on
        // clean builds. Injection that mmaps RWX without a name still surfaces
        // here, which is the intended heuristic.
        const bool anonymous = region->pathname.empty();
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

  std::vector<ProcFinding> scanDenyListUnmountFingerprint(
    std::string_view selfMountinfoContent
  ) noexcept {
    // Structural residue detector for unmount-style root hiding (Magisk
    // DenyList and equivalents like KernelSU unmount modules).
    //
    // What the evidence supports (verified against Magisk master, Aug 2026):
    // modern Magisk v24+ `revert_unmount()` (native/src/core/mount.rs, invoked
    // post-`unshare(CLONE_NEWNS)` under DO_REVERT_UNMOUNT) unmounts every
    // mount whose source is "magisk" or whose root starts with /adb/modules —
    // *including* the Magisk tmpfs itself. A correctly cleaned modern
    // namespace therefore contains zero magisk-token lines; this signal is an
    // expected no-fire there and must never be marketed as DenyList-proof.
    //
    // What actually leaves a fingerprint:
    //   Indicator A (structural residue) — >= 2 *distinct* canonical system
    //   paths mounted as `tmpfs`, regardless of source. Old MagiskHide left
    //   tmpfs "stoppers"; incomplete modern cleanups (EBUSY inner unmounts),
    //   third-party unmount modules, and Magisk forks (Kitsune) leave the
    //   same shape with whatever source string they used — including
    //   randomized ones, which is why the source token is no longer required.
    //   Stock Android backs these six paths with block devices (ext4/erofs/
    //   f2fs), and stock tmpfs targets (work profiles, scoped storage, /apex,
    //   /dev) live outside the allowlist, so the >=2-distinct exact-match
    //   gate is the false-positive guard.
    //   Indicator B (surviving artifacts) — any line still carrying a magisk
    //   token (source, /adb/modules root, .magisk mirror path). B alone never
    //   fires here: explicit-artifact signals already cover visible mounts at
    //   higher weights, and double-counting the same evidence would inflate
    //   the score. B only enriches the evidence when A fires ("partial cleanup
    //   of an otherwise visible framework").
    //
    // Weight is LOW/5 (hypothesis class, reliability 0.40) until the
    // on-device measurement program records clean-corpus fixtures and a
    // reproducible true positive; see the detection policy in CLAUDE.md.
    //
    // Mountinfo format: "ID parent maj:min root mountpoint options [optional ...] - fstype source super_options"
    // Field parsing is delegated to `parseMountinfoLine` (see the anonymous
    // namespace): the mount point is field 5, and the filesystem type/source
    // are located relative to the `-` separator so optional fields never shift
    // the parse.

    // Canonical system paths that are block-device-backed on stock Android.
    constexpr std::string_view kSystemPaths[] = {
      "/system", "/vendor", "/product", "/system_ext", "/odm", "/oem",
    };

    std::vector<std::string_view> matchedPaths;
    bool residualMagiskArtifacts = false;

    size_t lineStart = 0;
    while (lineStart <= selfMountinfoContent.size()) {
      const size_t lineEnd = selfMountinfoContent.find('\n', lineStart);
      const std::string_view line = selfMountinfoContent.substr(
        lineStart,
        (lineEnd == std::string_view::npos ? selfMountinfoContent.size() : lineEnd) - lineStart
      );
      if (!line.empty()) {
        // Indicator B: a surviving magisk artifact anywhere on the line. Checked
        // on the raw line so malformed-but-informative lines still count as
        // residue; it can only enrich evidence, never fire on its own.
        if (containsCI(line, "magisk") || containsCI(line, "/adb/modules") ||
            containsCI(line, ".magisk")) {
          residualMagiskArtifacts = true;
        }
        const MountinfoLine parsed = parseMountinfoLine(line);
        if (parsed.valid) {
          const bool isTmpfs = parsed.fsType == "tmpfs";
          const bool isSystemPath = std::find_if(
            std::begin(kSystemPaths), std::end(kSystemPaths),
            [&parsed](std::string_view candidate) {
              return parsed.mountPoint == candidate;
            }
          ) != std::end(kSystemPaths);
          if (isTmpfs && isSystemPath) {
            // Count distinct paths so two identical mounts of the same path
            // cannot satisfy the structural gate on their own.
            if (std::find(matchedPaths.begin(), matchedPaths.end(), parsed.mountPoint) ==
                matchedPaths.end()) {
              matchedPaths.push_back(parsed.mountPoint);
            }
          }
        }
      }
      if (lineEnd == std::string_view::npos) {
        break;
      }
      lineStart = lineEnd + 1;
    }

    if (matchedPaths.size() >= 2) {
      std::string evidence = "tmpfs-over-system-paths=";
      for (size_t i = 0; i < matchedPaths.size(); ++i) {
        if (i > 0) {
          evidence.push_back(',');
        }
        evidence += matchedPaths[i];
      }
      if (residualMagiskArtifacts) {
        evidence += ";residual-magisk-artifacts";
      }
      return {ProcFinding{SignalId::ANDROID_MOUNT_DENYLIST_UNMOUNT, std::move(evidence)}};
    }
    return {};
  }

  std::vector<ProcFinding> scanMountsForOverlayFs(std::string_view mountinfoContent) noexcept {
    // An `overlay`/`overlayfs` super-block mounted over a canonical system
    // partition means the system image has been overlaid: `adb remount` on an
    // unlocked bootloader, GSI/DSU installs, or a systemless-overlay root
    // setup (KernelSU/APatch meta-overlayfs modules commonly overlay at `/`,
    // which this exact-root rule intentionally does not match).
    //
    // "Never stock" is FALSE as an absolute claim: stock Xiaomi HyperOS/MIUI
    // ships OEM resource-layering overlays backed by /mnt/vendor/mi_ext and
    // /product/pangu (fstab evidence, Aug 2026; also AnyCheck issue #19,
    // 2026-06-28). Two rules keep those devices out:
    //   1. Subpath mountpoints (/system/app, /product/overlay, ...) never fire
    //      — the exact-partition-root rule. This is a documented decision, not
    //      an accident: the Xiaomi corpus motivates it.
    //   2. When backing directories ARE inspectable (lowerdir/upperdir/workdir
    //      in super-options), overlays backed *entirely* by known OEM
    //      prefixes are suppressed. The suppression list is fail-closed
    //      toward fewer detections; additions require a real-device corpus
    //      sample (see kOemBackingPrefixes).
    //
    // Classification when it does fire:
    //   - any user-writable-backed component (/data, /storage, /sdcard) →
    //     strongest form (meta-module / overlayfs-module root), flagged in
    //     the evidence as `;user-writable-backing`;
    //   - block/vendor-backed or uninspectable super-options → developer
    //     remount / GSI class.
    // Both fire the same signal id at MEDIUM weight ("modified environment",
    // not root proof); a single match is enough because one overlaid system
    // partition is already meaningful. Weight is 10 (reliability 0.55) until
    // the on-device measurement program signs off; see CLAUDE.md policy.
    constexpr std::string_view kSystemPaths[] = {
      "/system", "/vendor", "/product", "/system_ext", "/odm", "/oem",
    };
    // Suppression-only OEM backing prefixes. Additions REQUIRE a real-device
    // corpus sample; never add speculatively.
    static constexpr std::string_view kOemBackingPrefixes[] = {
      "/mnt/vendor/mi_ext/", // Xiaomi HyperOS/MIUI dynamic-resource delivery
      "/product/pangu/",     // Xiaomi OEM resource layering
    };
    static constexpr std::string_view kUserWritablePrefixes[] = {
      "/data/", "/storage/", "/sdcard/",
    };

    std::vector<std::string_view> matchedPaths;
    bool userWritableBacking = false;

    size_t lineStart = 0;
    while (lineStart <= mountinfoContent.size()) {
      const size_t lineEnd = mountinfoContent.find('\n', lineStart);
      const std::string_view line = mountinfoContent.substr(
        lineStart,
        (lineEnd == std::string_view::npos ? mountinfoContent.size() : lineEnd) - lineStart
      );
      if (!line.empty()) {
        const MountinfoLine parsed = parseMountinfoLine(line);
        if (parsed.valid &&
            (parsed.fsType == "overlay" || parsed.fsType == "overlayfs")) {
          const bool isSystemPath = std::find_if(
            std::begin(kSystemPaths), std::end(kSystemPaths),
            [&parsed](std::string_view candidate) {
              return parsed.mountPoint == candidate;
            }
          ) != std::end(kSystemPaths);
          if (isSystemPath) {
            // Classify by backing when the overlay exposes its directories.
            std::vector<std::string_view> components;
            splitOverlayDirs(optionValue(parsed.superOptions, "lowerdir="), components);
            components.push_back(optionValue(parsed.superOptions, "upperdir="));
            components.push_back(optionValue(parsed.superOptions, "workdir="));
            // Drop absent keys (empty extractions).
            std::erase_if(components, [](std::string_view component) {
              return component.empty();
            });
            bool oemSuppressed = false;
            if (!components.empty()) {
              oemSuppressed = std::all_of(
                components.begin(), components.end(),
                [](std::string_view component) {
                  return std::any_of(
                    std::begin(kOemBackingPrefixes), std::end(kOemBackingPrefixes),
                    [component](std::string_view prefix) {
                      return component.starts_with(prefix);
                    }
                  );
                }
              );
              if (!oemSuppressed) {
                userWritableBacking = userWritableBacking || std::any_of(
                  components.begin(), components.end(),
                  [](std::string_view component) {
                    return std::any_of(
                      std::begin(kUserWritablePrefixes), std::end(kUserWritablePrefixes),
                      [component](std::string_view prefix) {
                        return component.starts_with(prefix);
                      }
                    );
                  }
                );
              }
            }
            // Stock OEM resource layering is a non-finding by design; every
            // other exact-root overlay fires. Deduplicate: stacked overlays of
            // the same path are one finding (mirrors the DenyList scanner's
            // distinct-path handling).
            if (!oemSuppressed &&
                std::find(matchedPaths.begin(), matchedPaths.end(), parsed.mountPoint) ==
                  matchedPaths.end()) {
              matchedPaths.push_back(parsed.mountPoint);
            }
          }
        }
      }
      if (lineEnd == std::string_view::npos) {
        break;
      }
      lineStart = lineEnd + 1;
    }

    if (!matchedPaths.empty()) {
      std::string evidence = "overlay-over-system-paths=";
      for (size_t i = 0; i < matchedPaths.size(); ++i) {
        if (i > 0) {
          evidence.push_back(',');
        }
        evidence += matchedPaths[i];
      }
      if (userWritableBacking) {
        evidence += ";user-writable-backing";
      }
      return {ProcFinding{SignalId::ANDROID_MOUNT_OVERLAYFS, std::move(evidence)}};
    }
    return {};
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
