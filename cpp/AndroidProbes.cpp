///
/// AndroidProbes.cpp
///

#include "AndroidProbes.hpp"
#include "SignalCatalog.hpp"

#if defined(__ANDROID__)
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
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

    std::string lower(std::string_view value) {
      std::string result(value);
      for (char& c : result) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return result;
    }

    bool hasSuffixCI(std::string_view value, std::string_view suffix) noexcept {
      return value.size() >= suffix.size() &&
        containsCI(value.substr(value.size() - suffix.size()), suffix);
    }

    // Walk the process PATH looking for an executable with the given name.
    // No shell is spawned: a `popen("which ...")` would fork on every detection
    // pass (including every watchdog tick), has no timeout if the shell is
    // wedged, and trusts a hookable `/system/bin/sh`. `access(X_OK)` per PATH
    // entry is bounded, allocation-light, and hookable only via the same
    // syscall level every other filesystem probe here already relies on.
    bool pathListsExecutable(std::string_view executable) noexcept {
      const char* rawPath = ::getenv("PATH");
      if (rawPath == nullptr) {
        return false;
      }
      const std::string_view path(rawPath);
      size_t start = 0;
      for (size_t i = 0; i <= path.size(); ++i) {
        if (i != path.size() && path[i] != ':') {
          continue;
        }
        const std::string_view dir = path.substr(start, i - start);
        start = i + 1;
        if (dir.empty()) {
          continue;
        }
        const std::string candidate = std::string(dir) + "/" + std::string(executable);
        if (::access(candidate.c_str(), X_OK) == 0) {
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

  std::vector<ProcFinding> probeSystemAttributes() noexcept {
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

    SystemAttributes attributes{
      debuggable,
      readProperty("ro.build.type"),
      roSecure,
      bootState,
      readProperty("ro.boot.vbmeta.device_state"),
      fingerprint,
      buildTags,
      readProperty("persist.magisk.hide"),
      readProperty("ro.magisk.disable"),
      readProperty("init.svc.magisk_daemon"),
      readProperty("init.svc.magisk_pfs"),
    };
    for (const ProcFinding& finding : parseSystemAttributeInconsistencies(attributes)) {
      recordOnce(findings, seen, finding.signalId, finding.evidence);
    }

    const std::string zygisk = readProperty("ro.zygisk.version");
    const std::string assistant = readProperty("ro.zygisk.assistant.version");
    const std::string assistantEnabled = readProperty("persist.zygisk.assistant");
    const std::string next = readProperty("ro.zygisk.next.version");
    const std::string rezygisk = readProperty("ro.rezygisk.version");
    if (!zygisk.empty()) {
      recordOnce(findings, seen, SignalId::ANDROID_ZYGISK_VARIANT_OFFICIAL,
                 "ro.zygisk.version-present");
    }
    if (!assistant.empty() || !assistantEnabled.empty()) {
      recordOnce(findings, seen, SignalId::ANDROID_ZYGISK_VARIANT_ASSISTANT,
                 "zygisk-assistant-property-present");
    }
    if (!next.empty()) {
      recordOnce(findings, seen, SignalId::ANDROID_ZYGISK_VARIANT_NEXT,
                 "ro.zygisk.next.version-present");
    }
    if (!rezygisk.empty()) {
      recordOnce(findings, seen, SignalId::ANDROID_ZYGISK_VARIANT_REZYGISK,
                 "ro.rezygisk.version-present");
    }
#endif
    return findings;
  }

  std::vector<ProcFinding> probeBuildProperties() noexcept {
    return probeSystemAttributes();
  }

  ModuleProbeResult probeMagiskModules(
    std::chrono::steady_clock::time_point deadline
  ) noexcept {
    ModuleProbeResult result;
#if defined(__ANDROID__)
    DIR* directory = ::opendir("/data/adb/modules");
    if (directory == nullptr) {
      return result;
    }
    result.available = true;
    std::vector<std::string_view> seen;
    size_t moduleCount = 0;
    constexpr size_t kMaxModules = 128;
    while (moduleCount < kMaxModules) {
      if (std::chrono::steady_clock::now() >= deadline) {
        break;
      }
      dirent* entry = ::readdir(directory);
      if (entry == nullptr) {
        break;
      }
      const std::string_view name(entry->d_name);
      if (name == "." || name == "..") {
        continue;
      }
      const std::string directoryPath = "/data/adb/modules/" + std::string(name);
      struct stat info {};
      if (::stat(directoryPath.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        continue;
      }
      ++moduleCount;
      const std::string propPath = directoryPath + "/module.prop";
      const auto props = readFileIfExists(propPath, deadline, 16 * 1024);
      if (!props) {
        continue;
      }
      const std::vector<MagiskModule> modules = parseMagiskModulesProps(*props);
      const std::string identity = modules.empty() ? std::string(name) :
        modules.front().id + " " + modules.front().name;
      const std::string normalized = lower(identity);
      recordOnce(result.findings, seen, SignalId::ANDROID_MODULES_MAGISK,
                 "readable-magisk-module-tree");
      if (containsCI(normalized, "zygisk-assistant") || containsCI(normalized, "shamiko") ||
          containsCI(normalized, "magiskhide") || containsCI(normalized, "hide-my-applist")) {
        recordOnce(result.findings, seen, SignalId::ANDROID_MODULES_HIDING,
                   "hiding-module-manifest-present");
      }
      if (containsCI(normalized, "playintegrityfix") || containsCI(normalized, "play-integrity-fix") ||
          containsCI(normalized, "tricky_store") || containsCI(normalized, "trickystore")) {
        recordOnce(result.findings, seen, SignalId::ANDROID_MODULES_SPOOFING,
                   "integrity-module-manifest-present");
      }
    }
    ::closedir(directory);
#endif
    return result;
  }

  ModuleProbeResult probeMagiskModules() noexcept {
    return probeMagiskModules(std::chrono::steady_clock::time_point::max());
  }

  std::vector<ProcFinding> probeAddonD() noexcept {
    std::vector<ProcFinding> findings;
#if defined(__ANDROID__)
    bool found = pathExists("/system/addon.d/99-magisk.sh");
    DIR* directory = ::opendir("/system/addon.d");
    if (directory != nullptr) {
      while (dirent* entry = ::readdir(directory)) {
        const std::string_view name(entry->d_name);
        if (name != "." && name != ".." && hasSuffixCI(name, ".sh")) {
          found = true;
          break;
        }
      }
      ::closedir(directory);
    }
    if (found) {
      findings.push_back(ProcFinding{SignalId::ANDROID_ADDON_D_MAGISK, "addon.d-shell-script-present"});
    }
#endif
    return findings;
  }

  std::vector<ProcFinding> probeInstallRecovery() noexcept {
    std::vector<ProcFinding> findings;
#if defined(__ANDROID__)
    if (pathExists("/system/bin/install-recovery.sh")) {
      findings.push_back(ProcFinding{SignalId::ANDROID_INSTALL_RECOVERY, "install-recovery-script-present"});
    }
#endif
    return findings;
  }

  std::vector<ProcFinding> probeHostsFile() noexcept {
    std::vector<ProcFinding> findings;
#if defined(__ANDROID__)
    if (::access("/system/etc/hosts", W_OK) == 0) {
      findings.push_back(ProcFinding{SignalId::ANDROID_HOSTS_WRITABLE, "system-hosts-writable"});
    }
#endif
    return findings;
  }

  std::vector<ProcFinding> probeCustomRom() noexcept {
    std::vector<ProcFinding> findings;
#if defined(__ANDROID__)
    std::vector<std::string_view> seen;
    const std::string lineageVersion = readProperty("ro.lineage.version");
    const std::string lineageDisplayVersion = readProperty("ro.lineage.display.version");
    const std::string lineageLegacy = readProperty("lineage.version");
    const std::string displayId = readProperty("ro.build.display.id");
    const std::string crdroid = readProperty("ro.crdroid.version");
    const std::string evolution = readProperty("ro.evolution.version");
    const std::string pixel = readProperty("ro.pixelexperience.version");
    const std::string modVersion = readProperty("ro.modversion");
    const bool lineage = !lineageVersion.empty() || !lineageDisplayVersion.empty() ||
      !lineageLegacy.empty() || containsCI(displayId, "lineage_");
    const bool custom = lineage || !crdroid.empty() || !evolution.empty() ||
      !pixel.empty() || !modVersion.empty() || containsCI(displayId, "crdroid_") ||
      containsCI(displayId, "evolutionx_") || containsCI(displayId, "pixel_");
    if (custom) {
      recordOnce(findings, seen, SignalId::ANDROID_CUSTOM_ROM, "custom-rom-marker-present");
    }
    if (lineage) {
      recordOnce(findings, seen, SignalId::ANDROID_LINEAGE,
                 lineageVersion.empty() ? "lineage-marker-present" : "lineage-version-present");
    }
#endif
    return findings;
  }

  std::vector<ProcFinding> probeLspdCache() noexcept {
    std::vector<ProcFinding> findings;
#if defined(__ANDROID__)
    constexpr std::string_view kMarkers[] = {
      "/data/adb/lspd",
      "/data/adb/modules/lsposed",
      "/data/adb/modules/zygisk-lsposed",
    };
    for (const std::string_view marker : kMarkers) {
      if (pathExists(marker)) {
        findings.push_back(ProcFinding{SignalId::ANDROID_LSPOSED_CACHE, "lsposed-cache-or-module-present"});
        break;
      }
    }
    if (findings.empty()) {
      DIR* users = ::opendir("/data/user/0");
      if (users != nullptr) {
        size_t checkedUsers = 0;
        while (checkedUsers < 64) {
          dirent* user = ::readdir(users);
          if (user == nullptr) {
            break;
          }
          const std::string_view userName(user->d_name);
          if (userName == "." || userName == "..") {
            continue;
          }
          ++checkedUsers;
          const std::string cachePath = "/data/user/0/" + std::string(userName) + "/cache";
          DIR* cache = ::opendir(cachePath.c_str());
          if (cache == nullptr) {
            continue;
          }
          while (dirent* entry = ::readdir(cache)) {
            const std::string_view cacheName(entry->d_name);
            if (cacheName.size() >= 4 && cacheName.substr(0, 4) == "lspd") {
              findings.push_back(ProcFinding{SignalId::ANDROID_LSPOSED_CACHE, "lsposed-cache-marker-present"});
              break;
            }
          }
          ::closedir(cache);
          if (!findings.empty()) {
            break;
          }
        }
        ::closedir(users);
      }
    }
#endif
    return findings;
  }

  std::vector<ProcFinding> probeSystemDirectoryWrite() noexcept {
    std::vector<ProcFinding> findings;
#if defined(__ANDROID__)
    constexpr std::string_view kDirectories[] = {
      "/system/etc/",
      "/vendor/etc/",
      "/product/etc/",
    };
    const std::string suffix = ".anti_jb_probe_" + std::to_string(static_cast<long long>(::getpid()));
    for (const std::string_view directory : kDirectories) {
      const std::string path = std::string(directory) + suffix;
      std::ofstream file(path, std::ios::out | std::ios::trunc);
      if (!file.is_open()) {
        continue;
      }
      file << "probe";
      file.close();
      ::remove(path.c_str());
      findings.push_back(ProcFinding{
        SignalId::ANDROID_SANDBOX_WRITE_SYSTEM_DIR,
        "system-directory-write-succeeded",
      });
      break;
    }
#endif
    return findings;
  }

  std::vector<ProcFinding> probeEnvironmentAndCommands() noexcept {
    std::vector<ProcFinding> findings;
#if defined(__ANDROID__)
    const char* rawPath = ::getenv("PATH");
    if (rawPath != nullptr) {
      const std::string_view path(rawPath);
      // Only Magisk-layout directories are flagged. `/sbin`, `/product/bin`,
      // and `/system_ext/bin` legitimately appear in the default PATH of older
      // and OEM builds, so matching them was a false-positive source.
      if (containsCI(path, "/data/adb/") || containsCI(path, "/debug_ramdisk")) {
        findings.push_back(ProcFinding{
          SignalId::ANDROID_ENV_PATH_MAGISK,
          "candidate-magisk-path-entry",
        });
      }
    }
    if (pathListsExecutable("su")) {
      findings.push_back(ProcFinding{SignalId::ANDROID_CMDLINE_SU_EXEC, "su-executable-in-path"});
    }
    if (pathListsExecutable("magisk")) {
      findings.push_back(ProcFinding{SignalId::ANDROID_CMDLINE_MAGISK_EXEC, "magisk-executable-in-path"});
    }
#endif
    return findings;
  }

} // namespace margelo::nitro::rootjaildetect
