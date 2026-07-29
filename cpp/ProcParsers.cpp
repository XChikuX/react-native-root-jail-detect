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

  std::optional<std::string> readFileIfExists(std::string_view path) noexcept {
    try {
      std::ifstream stream(std::string(path), std::ios::binary);
      if (!stream.is_open()) {
        return std::nullopt;
      }
      std::ostringstream buffer;
      buffer << stream.rdbuf();
      std::string contents = buffer.str();
      if (stream.bad()) {
        return std::nullopt;
      }
      return contents;
    } catch (...) {
      // Any I/O failure is treated as "no data". A missing/unreadable `/proc`
      // entry must never become evidence of compromise.
      return std::nullopt;
    }
  }

  std::vector<ProcFinding> scanMapsForHooks(std::string_view mapsContent) noexcept {
    std::vector<ProcFinding> findings;
    std::vector<std::string_view> seen;
    scanLines(mapsContent, K_HOOK_PATTERNS, sizeof(K_HOOK_PATTERNS) / sizeof(K_HOOK_PATTERNS[0]),
              findings, seen, /*usePathnameOnly=*/true);
    return findings;
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

  std::vector<ProcFinding> scanNamespaceOnlyMountArtifacts(
    std::string_view selfMountinfoContent,
    std::string_view initMountinfoContent
  ) noexcept {
    std::vector<ProcFinding> findings;
    // A different mount namespace is normal for Android apps. Only report a
    // known root token that is visible to this process and absent from PID 1.
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
