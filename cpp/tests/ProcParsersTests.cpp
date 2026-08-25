///
/// ProcParsersTests.cpp
///
/// Host-side fixture suite for the pure `/proc` parsers. Compiled by
/// `bun run native-test` with `-DROOTJAILDETECT_HOST_TEST`, which swaps the
/// nitrogen-generated enums for shape-agreeing stand-ins (see
/// `SignalCatalog.hpp` / `Scoring.hpp`). This file owns `main()` and delegates
/// the larger sub-suites:
///   - `runDenyListFingerprintTests()` (DenyListFingerprintTests.cpp)
///   - `runOverlayFsTests()`          (OverlayFsTests.cpp)
///   - `runMountCorpusTests()`        (MountCorpusTests.cpp)
///   - `runScoringTests()`            (ScoringTests.cpp)
///

#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"

#include <cassert>
#include <string_view>

using namespace margelo::nitro::rootjaildetect;

void runDenyListFingerprintTests();
void runOverlayFsTests();
void runMountCorpusTests();
void runScoringTests();

int main() {
  // ---- `/proc/self/maps`: hook artifacts ----------------------------------
  {
    constexpr std::string_view maps =
      "1000-2000 r-xp 00000000 00:00 0\n"
      "3000-4000 r-xp 00000000 00:00 0\n"
      "5000-6000 r--p 00000000 00:00 0 /system/lib64/libzygisk.so\n";
    const auto anonymous = parseMapsForAnonymousInjection(maps);
    assert(anonymous.size() == 1);
    assert(anonymous.front().signalId == SignalId::ANDROID_MAPS_ANON_INJECTION);
    assert(scanMapsForHooks(maps).front().signalId == SignalId::ANDROID_MAPS_ZYGISK);
  }

  // Named anonymous regions (ART JIT, libc malloc) are normal on stock ART
  // and must NOT trip the anon-injection heuristic.
  {
    constexpr std::string_view stockArtMaps =
      "1000-2000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]\n"
      "3000-4000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]\n";
    assert(parseMapsForAnonymousInjection(stockArtMaps).empty());
  }

  // Each hook family maps to its own signal id.
  {
    constexpr std::string_view fridaMaps =
      "1000-2000 r-xp 00000000 00:00 0 /data/local/tmp/frida-agent.so\n";
    assert(scanMapsForHooks(fridaMaps).front().signalId == SignalId::ANDROID_MAPS_FRIDA);
  }
  {
    constexpr std::string_view lsposedMaps =
      "1000-2000 r-xp 00000000 00:00 0 /data/adb/modules/lsposed/lib64/liblsposed.so\n";
    assert(scanMapsForHooks(lsposedMaps).front().signalId == SignalId::ANDROID_MAPS_LSPOSED);
  }
  {
    constexpr std::string_view xposedMaps =
      "1000-2000 r-xp 00000000 00:00 0 /system/lib64/libxposed_art.so\n";
    assert(scanMapsForHooks(xposedMaps).front().signalId == SignalId::ANDROID_MAPS_LSPOSED);
  }
  {
    constexpr std::string_view riruMaps =
      "1000-2000 r-xp 00000000 00:00 0 /data/adb/riru/lib64/libriru.so\n";
    assert(scanMapsForHooks(riruMaps).front().signalId == SignalId::ANDROID_MAPS_RIRU);
  }

  // Multiple tokens for the same hook family deduplicate to one finding.
  {
    constexpr std::string_view multiZygiskMaps =
      "1000-2000 r-xp 00000000 00:00 0 /system/lib64/libzygisk.so\n"
      "3000-4000 r-xp 00000000 00:00 0 /system/lib64/magisk-zisk.so\n"
      "5000-6000 r-xp 00000000 00:00 0 /system/lib64/libzygisk_x.so\n";
    const auto findings = scanMapsForHooks(multiZygiskMaps);
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_MAPS_ZYGISK);
  }

  // Clean maps and empty input produce nothing.
  {
    constexpr std::string_view cleanMaps =
      "1000-2000 r-xp 00000000 00:00 0 /system/lib64/libc.so\n"
      "3000-4000 r-xp 00000000 00:00 0 /system/lib64/libart.so\n";
    assert(scanMapsForHooks(cleanMaps).empty());
    assert(scanMapsForHooks("").empty());
  }

  // ---- `/proc/self/maps`: anonymous-executable injection ------------------
  // A single executable anonymous VMA is ignored (ART/JIT produces one on
  // stock devices); a cluster of two fires.
  {
    constexpr std::string_view singleAnon =
      "1000-2000 r-xp 00000000 00:00 0\n";
    assert(parseMapsForAnonymousInjection(singleAnon).empty());
  }
  {
    constexpr std::string_view clusterAnon =
      "1000-2000 r-xp 00000000 00:00 0\n"
      "3000-4000 r-xp 00000000 00:00 0\n";
    const auto findings = parseMapsForAnonymousInjection(clusterAnon);
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_MAPS_ANON_INJECTION);
  }
  assert(parseMapsForAnonymousInjection("").empty());

  // ---- Mount metadata: root artifacts -------------------------------------
  {
    constexpr std::string_view mountinfo =
      "1 1 0:1 / /system rw,relatime - tmpfs magisk rw\n";
    const auto findings = scanMountsForRootArtifacts(mountinfo, "");
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_MOUNT_MAGISK);
  }
  // kernelsu / apatch / `/data/adb` share the `ANDROID_MOUNT_MAGISK` signal id
  // by design and deduplicate against an already-seen magisk token.
  {
    constexpr std::string_view mountinfo =
      "1 1 0:1 / /system rw - tmpfs magisk rw\n"
      "2 1 0:2 / /vendor rw - overlay kernelsu rw\n"
      "3 1 0:3 / /product rw - tmpfs apatch rw\n"
      "4 1 0:4 / /data/adb rw - ext4 /dev/block/dm-1\n";
    const auto findings = scanMountsForRootArtifacts(mountinfo, "");
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_MOUNT_MAGISK);
  }
  // The `/proc/self/mounts` input is scanned too, and findings deduplicate
  // across both inputs.
  {
    constexpr std::string_view mounts =
      "/dev/block/dm-0 /system ext4 rw 0 0\n"
      "magisk /debug_ramdisk tmpfs rw 0 0\n";
    const auto findings = scanMountsForRootArtifacts("", mounts);
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_MOUNT_MAGISK);
  }
  {
    constexpr std::string_view mountinfo =
      "1 1 0:1 / /system rw - tmpfs magisk rw\n";
    constexpr std::string_view mounts =
      "magisk /debug_ramdisk tmpfs rw 0 0\n";
    const auto findings = scanMountsForRootArtifacts(mountinfo, mounts);
    assert(findings.size() == 1);
  }
  {
    constexpr std::string_view clean =
      "1 1 0:1 / /system rw,relatime - ext4 /dev/block/dm-0\n";
    assert(scanMountsForRootArtifacts(clean, "").empty());
    assert(scanMountsForRootArtifacts("", "").empty());
  }

  // ---- Mount metadata: Magisk chain ---------------------------------------
  // The chain heuristic requires >= 3 suspicious layers.
  {
    constexpr std::string_view twoLayers =
      "1 1 0:1 / /system rw - overlay overlay\n"
      "2 1 0:2 / /debug_ramdisk rw - magisk magisk\n";
    assert(scanMountsForMagiskChain(twoLayers).empty());
  }
  {
    constexpr std::string_view threeLayers =
      "1 1 0:1 / /system rw - overlay overlay\n"
      "2 1 0:2 / /debug_ramdisk rw - magisk magisk\n"
      "3 1 0:3 / /sbin rw - magisk magisk\n";
    const auto findings = scanMountsForMagiskChain(threeLayers);
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_MOUNT_MAGISK_CHAIN);
    assert(findings.front().evidence == "layered-suspicious-mounts=3");
  }
  // Token matching is case-insensitive.
  {
    constexpr std::string_view upperLayers =
      "1 1 0:1 / /system rw - MAGISK MAGISK\n"
      "2 1 0:2 / /debug_ramdisk rw - MAGISK MAGISK\n"
      "3 1 0:3 / /sbin rw - MAGISK MAGISK\n";
    assert(scanMountsForMagiskChain(upperLayers).size() == 1);
  }
  assert(scanMountsForMagiskChain("").empty());

  // ---- Mount metadata: namespace-only artifacts ---------------------------
  // Known root tokens visible in the app namespace but absent from init's are
  // reported under `ANDROID_MOUNT_OVERLAY`; shared tokens are not.
  {
    constexpr std::string_view self =
      "1 1 0:1 / /debug_ramdisk rw - tmpfs magisk rw\n";
    constexpr std::string_view init =
      "1 1 0:1 / /system rw - ext4 /dev/block/dm-0\n";
    const auto findings = scanNamespaceOnlyMountArtifacts(self, init);
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_MOUNT_OVERLAY);
  }
  {
    constexpr std::string_view self =
      "1 1 0:1 / /debug_ramdisk rw - tmpfs magisk rw\n";
    constexpr std::string_view init =
      "1 1 0:1 / /system rw - tmpfs magisk rw\n";
    assert(scanNamespaceOnlyMountArtifacts(self, init).empty());
  }
  {
    constexpr std::string_view self =
      "1 1 0:1 / /system rw - ext4 /dev/block/dm-0\n";
    constexpr std::string_view init =
      "1 1 0:1 / /system rw - ext4 /dev/block/dm-0\n";
    assert(scanNamespaceOnlyMountArtifacts(self, init).empty());
  }

  // ---- Magisk `module.prop` documents -------------------------------------
  {
    constexpr std::string_view moduleProps =
      "id=zygisk-assistant\n"
      "name=Zygisk Assistant\n"
      "version=1.0\n"
      "author=fixture\n\n"
      "id=tricky_store\n"
      "name=Tricky Store\n";
    const auto modules = parseMagiskModulesProps(moduleProps);
    assert(modules.size() == 2);
    assert(modules.front().id == "zygisk-assistant");
    assert(modules.front().name == "Zygisk Assistant");
    assert(modules.front().version == "1.0");
    assert(modules.front().author == "fixture");
    assert(modules.back().id == "tricky_store");
    assert(modules.back().name == "Tricky Store");
  }
  assert(parseMagiskModulesProps("").empty());
  // A document with a name but no id is still reported.
  {
    constexpr std::string_view nameOnly = "name=Anonymous Module\n";
    const auto modules = parseMagiskModulesProps(nameOnly);
    assert(modules.size() == 1);
    assert(modules.front().name == "Anonymous Module");
  }
  // A document with neither id nor name is dropped.
  {
    constexpr std::string_view versionOnly = "version=1.0\nauthor=nobody\n";
    assert(parseMagiskModulesProps(versionOnly).empty());
  }
  // Keys are trimmed; values keep their content.
  {
    constexpr std::string_view padded = "  id  =  spaced  \nname = N\n";
    const auto modules = parseMagiskModulesProps(padded);
    assert(modules.size() == 1);
    assert(modules.front().id == "spaced");
    assert(modules.front().name == "N");
  }

  // ---- System-property cross-checks ---------------------------------------
  {
    const auto inconsistencies = parseSystemAttributeInconsistencies(SystemAttributes{
      "0",
      "userdebug",
      "1",
      "green",
      "unlocked",
      "device/user/release-keys",
      "test-keys",
      "",
      "1",
      "",
      "",
    });
    assert(inconsistencies.size() == 4);
  }
  // A fully consistent, stock-looking attribute set produces nothing.
  {
    const auto clean = parseSystemAttributeInconsistencies(SystemAttributes{
      "0",
      "user",
      "1",
      "green",
      "locked",
      "device/user/release-keys",
      "release-keys",
      "",
      "",
      "",
      "",
    });
    assert(clean.empty());
  }
  // debuggable=1 with secure=1 is an inconsistency (dev-build hiding).
  {
    const auto findings = parseSystemAttributeInconsistencies(SystemAttributes{
      "1", "user", "1", "green", "locked", "device/user/release-keys",
      "release-keys", "", "", "", "",
    });
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_PROPS_INCONSISTENT_DEBUGGABLE);
  }
  // Verified-boot state is compared case-insensitively.
  {
    const auto findings = parseSystemAttributeInconsistencies(SystemAttributes{
      "0", "user", "1", "GREEN", "UNLOCKED", "device/user/release-keys",
      "release-keys", "", "", "", "",
    });
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_PROPS_INCONSISTENT_VERIFIEDBOOT);
  }
  // Fingerprint/tag disagreement and user-vs-userdebug disagreement both map
  // to the same fingerprint id and deduplicate. (debuggable=1 + secure=0 keeps
  // the debuggable rules quiet so this fixture isolates the fingerprint id.)
  {
    const auto findings = parseSystemAttributeInconsistencies(SystemAttributes{
      "1", "userdebug", "0", "green", "locked", "device/user/release-keys",
      "test-keys", "", "", "", "",
    });
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_PROPS_INCONSISTENT_FINGERPRINT);
  }
  // Any Magisk-specific property is a distinct signal.
  {
    const auto findings = parseSystemAttributeInconsistencies(SystemAttributes{
      "0", "user", "1", "green", "locked", "device/user/release-keys",
      "release-keys", "", "", "running", "",
    });
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_MAGISK_DISABLE_PROP);
  }
  // The map overload forwards the same keys.
  {
    const auto findings = parseSystemAttributeInconsistencies(std::map<std::string, std::string>{
      {"ro.debuggable", "1"},
      {"ro.secure", "1"},
    });
    assert(findings.size() == 1);
    assert(findings.front().signalId == SignalId::ANDROID_PROPS_INCONSISTENT_DEBUGGABLE);
  }

  // ---- `/proc/self/status`: TracerPid -------------------------------------
  assert(parseTracerPid("TracerPid:\t1234\nOther: 1\n") == std::optional<int>(1234));
  assert(parseTracerPid("TracerPid:\t0\n") == std::optional<int>(0));
  assert(parseTracerPid("TracerPid:  42 \n") == std::optional<int>(42));
  assert(parseTracerPid("Name:\tapp\nUid:\t1000\n") == std::nullopt);
  assert(parseTracerPid("TracerPid:\tabc\n") == std::nullopt);
  assert(parseTracerPid("") == std::nullopt);

  // ---- `/sys/fs/selinux/enforce` ------------------------------------------
  assert(parseSelinuxEnforce("1") == std::optional<bool>(true));
  assert(parseSelinuxEnforce("0") == std::optional<bool>(false));
  assert(parseSelinuxEnforce(" 1\n") == std::optional<bool>(true));
  assert(parseSelinuxEnforce("0\n") == std::optional<bool>(false));
  assert(parseSelinuxEnforce("x") == std::nullopt);
  assert(parseSelinuxEnforce("") == std::nullopt);

  // ---- Mount metadata: overlay-filesystem coverage lives in
  // OverlayFsTests.cpp; DenyList coverage in DenyListFingerprintTests.cpp;
  // the clean-device corpus in MountCorpusTests.cpp. ----------------------

  assert(scanMountsForOverlayFs("").empty());

  // ---- Signal catalog spot checks -----------------------------------------
  {
    const auto anonSpec = lookupSignal(SignalId::ANDROID_MAPS_ANON_INJECTION);
    assert(anonSpec.has_value());
    assert(anonSpec->score == 10.0);

    const auto denyListSpec = lookupSignal(SignalId::ANDROID_MOUNT_DENYLIST_UNMOUNT);
    assert(denyListSpec.has_value());
    assert(denyListSpec->score == 5.0);
    assert(denyListSpec->severity == Severity::LOW);
    assert(denyListSpec->reliability == 0.40);

    const auto overlayFsSpec = lookupSignal(SignalId::ANDROID_MOUNT_OVERLAYFS);
    assert(overlayFsSpec.has_value());
    assert(overlayFsSpec->score == 10.0);
    assert(overlayFsSpec->severity == Severity::MEDIUM);
    assert(overlayFsSpec->reliability == 0.55);

    // Unknown ids have no catalog entry (never a positive finding).
    assert(!lookupSignal("android.unknown.future_id").has_value());
  }

  // ---- Sub-suites ----------------------------------------------------------
  runDenyListFingerprintTests();
  runOverlayFsTests();
  runMountCorpusTests();
  runScoringTests();

  return 0;
}
