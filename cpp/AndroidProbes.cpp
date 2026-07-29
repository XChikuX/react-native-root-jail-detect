///
/// AndroidProbes.cpp
///

#include "AndroidProbes.hpp"
#include "SignalCatalog.hpp"

#if defined(__ANDROID__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cstring>
#include <string>

namespace margelo::nitro::rootjaildetect {

  namespace {

    // Known root-manager application/data directories. These are conventionally
    // created by Magisk and similar managers; presence is a medium signal, not
    // proof, because paths can be hidden or renamed.
    constexpr std::string_view K_ROOT_MANAGER_DIRS[] = {
      "/data/adb/magisk",
      "/data/adb/modules",
      "/sbin/magisk",
      "/data/data/com.topjohnwu.magisk",
      "/system/app/Superuser.apk",
      "/system/xbin/daemonsu",
    };

    // Conventional `su` binary locations. Existence is a low signal because `su`
    // is trivially hidden or hooked by modern root frameworks.
    constexpr std::string_view K_SU_BINARIES[] = {
      "/system/bin/su",
      "/system/xbin/su",
      "/sbin/su",
      "/system/sd/xbin/su",
      "/system/bin/failsafe/su",
      "/data/local/xbin/su",
      "/data/local/bin/su",
      "/data/local/su",
      "/su/bin/su",
    };

#if defined(__ANDROID__)
    bool pathExists(std::string_view path) noexcept {
      struct stat st {};
      // Use `stat(2)` directly. `access(2)` would also work but `stat` returns
      // enough information to treat files and directories uniformly.
      std::string nullTerminated(path);
      return ::stat(nullTerminated.c_str(), &st) == 0;
    }

    bool pathCanBeOpened(std::string_view path) noexcept {
      std::string nullTerminated(path);
      const int descriptor = ::open(nullTerminated.c_str(), O_RDONLY | O_CLOEXEC);
      if (descriptor < 0) {
        return false;
      }
      ::close(descriptor);
      return true;
    }

    // Read a system property into a small stack buffer. Returns an empty string
    // when the property is unset or the read fails; callers treat empty as
    // "unavailable", never as a detection.
    std::string readProperty(std::string_view key) noexcept {
      std::string nullTerminated(key);
      char value[PROP_VALUE_MAX] = {0};
      int length = __system_property_get(nullTerminated.c_str(), value);
      if (length <= 0) {
        return std::string();
      }
      return std::string(value, static_cast<size_t>(length));
    }

    bool equalsCI(std::string_view a, std::string_view b) noexcept {
      if (a.size() != b.size()) {
        return false;
      }
      for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
          return false;
        }
      }
      return true;
    }

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
#endif // defined(__ANDROID__)

    void recordOnce(std::vector<ProcFinding>& out, std::vector<std::string_view>& seen,
                    std::string_view signalId, std::string evidence) {
      if (std::find(seen.begin(), seen.end(), signalId) != seen.end()) {
        return;
      }
      seen.push_back(signalId);
      out.push_back(ProcFinding{signalId, std::move(evidence)});
    }

  } // namespace

  std::vector<ProcFinding> probeRootPaths() noexcept {
    std::vector<ProcFinding> findings;
    std::vector<std::string_view> seen;
#if defined(__ANDROID__)
    for (std::string_view dir : K_ROOT_MANAGER_DIRS) {
      if (pathExists(dir) || pathCanBeOpened(dir)) {
        recordOnce(findings, seen, SignalId::ANDROID_ROOT_MANAGER_DIR, std::string(dir));
      }
    }
    for (std::string_view su : K_SU_BINARIES) {
      if (pathExists(su) || pathCanBeOpened(su)) {
        recordOnce(findings, seen, SignalId::ANDROID_SU_BINARY, std::string(su));
      }
    }
#else
    // Outside Android (unit tests on a non-Android host) there is nothing to
    // probe; return an empty set so the function is safe to compile anywhere.
    (void) K_ROOT_MANAGER_DIRS;
    (void) K_SU_BINARIES;
#endif
    return findings;
  }

  std::vector<ProcFinding> probeBuildProperties() noexcept {
    std::vector<ProcFinding> findings;
    std::vector<std::string_view> seen;
#if defined(__ANDROID__)
    // Build tags: `test-keys` indicates an unofficial (userdebug/eng) build and
    // is common on custom ROMs. Low severity on its own.
    std::string buildTags = readProperty("ro.build.tags");
    if (!buildTags.empty() && containsCI(buildTags, "test-keys")) {
      recordOnce(findings, seen, SignalId::ANDROID_BUILD_TEST_KEYS, "ro.build.tags=test-keys");
    }

    const std::string hardware = readProperty("ro.hardware");
    const std::string product = readProperty("ro.product.name");
    const std::string fingerprint = readProperty("ro.build.fingerprint");
    if (containsCI(hardware, "goldfish") || containsCI(hardware, "ranchu") ||
        containsCI(product, "sdk_gphone") || containsCI(product, "emulator") ||
        containsCI(fingerprint, "generic")) {
      recordOnce(findings, seen, SignalId::ANDROID_EMULATOR, "android-emulator-property");
    }

    // Verified boot state: `orange`/`unlocked` means the bootloader is
    // unlocked. Medium signal but not definitive proof of root on its own.
    std::string bootState = readProperty("ro.boot.verifiedbootstate");
    if (!bootState.empty() && (equalsCI(bootState, "orange") || equalsCI(bootState, "unlocked"))) {
      recordOnce(findings, seen, SignalId::ANDROID_BOOTLOADER_UNLOCKED,
                 "ro.boot.verifiedbootstate=" + bootState);
    } else {
      // Older devices expose lock state through `flash.locked` instead.
      std::string flashLocked = readProperty("ro.boot.flash.locked");
      if (equalsCI(flashLocked, "0")) {
        recordOnce(findings, seen, SignalId::ANDROID_BOOTLOADER_UNLOCKED, "ro.boot.flash.locked=0");
      }
    }

    // Debug / insecure build properties. These are real but hidden by Shamiko
    // and common on userdebug/eng devices. Emit low-weight signals with explicit
    // caveats; never block on them alone. `ro.build.selinux` is intentionally
    // NOT used because it is unreliable (can be 0 while enforcing, often empty).
    std::string debuggable = readProperty("ro.debuggable");
    if (!debuggable.empty() && debuggable != "0") {
      recordOnce(findings, seen, SignalId::ANDROID_DEBUG_BUILD,
                 "ro.debuggable=" + debuggable);
    }
    std::string adbRoot = readProperty("service.adb.root");
    if (!adbRoot.empty() && adbRoot != "0") {
      recordOnce(findings, seen, SignalId::ANDROID_ADB_ROOT,
                 "service.adb.root=" + adbRoot);
    }
    std::string roSecure = readProperty("ro.secure");
    if (!roSecure.empty() && roSecure == "0") {
      recordOnce(findings, seen, SignalId::ANDROID_RO_SECURE_ZERO,
                 "ro.secure=0");
    }
#endif
    return findings;
  }

} // namespace margelo::nitro::rootjaildetect
