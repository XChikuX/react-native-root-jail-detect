///
/// IOSMatcherTests.cpp
///
/// Host-side fixture coverage for the pure iOS matching logic in
/// `IOSMatchers.hpp` (WS-I-D): the artifact-probe table/classification and
/// the dyld loaded-image matcher. Pure and deterministic — no filesystem, no
/// dyld APIs — so the iOS detection logic is finally testable without
/// hardware (the structural gap that let the v0.12.0 fabricated paths and
/// case-sensitive dyld matching ship).
///
/// Corpora mirror the Android suite's discipline:
///   - Clean corpus: stock iOS image paths and non-artifact paths must not
///     classify and must not match.
///   - Rooted corpus: rootless layout (symlink targets, TweakInject), rootful
///     classic artifacts, including mixed-case and renamed variants.
///   - Evasion corpus: roothide-shaped `.jbroot` references are PINNED
///     EXPECTED NEGATIVES for the path table (documented ceiling) and
///     expected positives for the loaded-image provenance rule; benign
///     lookalikes must not fire.
///

#include "IOSMatchers.hpp"
#include "SignalCatalog.hpp"

#include <algorithm>
#include <cassert>
#include <string_view>
#include <vector>

using namespace margelo::nitro::rootjaildetect;

void runIOSMatcherTests() {
  // ---- Probe table sanity ---------------------------------------------------
  // Every probe classifies to its declared class; table paths are unique.
  {
    std::vector<std::string_view> seen;
    for (const IOSArtifactProbe& probe : IOS_ARTIFACT_PROBES) {
      assert(classifyIOSArtifactPath(probe.path) == probe.clazz);
      assert(std::find(seen.begin(), seen.end(), probe.path) == seen.end());
      seen.push_back(probe.path);
    }
    // The removed/unverified literals must NOT be probed (pinned: the
    // fabricated TrollStore paths, the unverifiable marker files, and the
    // bare /private/preboot/<name> forms are gone).
    assert(classifyIOSArtifactPath("/var/containers/Bundle/trollstoreapp") ==
           IOSArtifactClass::NONE);
    assert(classifyIOSArtifactPath("/var/containers/Bundle/.trollstoreappinstalled") ==
           IOSArtifactClass::NONE);
    assert(classifyIOSArtifactPath("/var/jb/.installed_dopamine") == IOSArtifactClass::NONE);
    assert(classifyIOSArtifactPath("/var/jb/.installed_palera1n") == IOSArtifactClass::NONE);
    assert(classifyIOSArtifactPath("/private/preboot/jb") == IOSArtifactClass::NONE);
    assert(classifyIOSArtifactPath("/private/preboot/dopamine") == IOSArtifactClass::NONE);
    assert(classifyIOSArtifactPath("/private/preboot/palera1n") == IOSArtifactClass::NONE);
  }

  // ---- Artifact classification ----------------------------------------------
  // Rootless convention (iOS 15+): exact table paths only.
  assert(classifyIOSArtifactPath("/var/jb") == IOSArtifactClass::ROOTLESS);
  assert(classifyIOSArtifactPath("/private/jb") == IOSArtifactClass::ROOTLESS);
  assert(classifyIOSArtifactPath("/var/jb/usr/lib/TweakInject.dylib") ==
         IOSArtifactClass::ROOTLESS);

  // Classic rootful artifacts.
  assert(classifyIOSArtifactPath("/Applications/Cydia.app") == IOSArtifactClass::CLASSIC);
  assert(classifyIOSArtifactPath("/Applications/Sileo.app") == IOSArtifactClass::CLASSIC);
  assert(classifyIOSArtifactPath("/Applications/Zebra.app") == IOSArtifactClass::CLASSIC);
  assert(classifyIOSArtifactPath("/Library/MobileSubstrate/MobileSubstrate.dylib") ==
         IOSArtifactClass::CLASSIC);
  assert(classifyIOSArtifactPath("/.procursus_strapped") == IOSArtifactClass::CLASSIC);

  // Clean corpus: stock paths and lookalikes never classify.
  assert(classifyIOSArtifactPath("/") == IOSArtifactClass::NONE);
  assert(classifyIOSArtifactPath("/System/Library/CoreServices/SpringBoard.app") ==
         IOSArtifactClass::NONE);
  assert(classifyIOSArtifactPath("/private/var/containers/Bundle/Application/ABC/app.app") ==
         IOSArtifactClass::NONE);
  assert(classifyIOSArtifactPath("/private/preboot/12345678-AB/jb/usr/bin") ==
         IOSArtifactClass::NONE); // the REAL randomized layout — table is exact-match
  assert(classifyIOSArtifactPath("/var/jbx") == IOSArtifactClass::NONE);
  assert(classifyIOSArtifactPath("/var/jb/other/file") == IOSArtifactClass::NONE);
  assert(classifyIOSArtifactPath("") == IOSArtifactClass::NONE);

  // PINNED EXPECTED NEGATIVE (documented ceiling): roothide randomizes its
  // bootstrap under `/var/containers/Bundle/Application/.jbroot-<brand>` and
  // deliberately avoids `/private/preboot`. Path-table detection against a
  // hidden roothide bootstrap is a permanent FN; do not "fix" this fixture —
  // only loaded-image provenance (below) can catch active roothide tweaks.
  assert(classifyIOSArtifactPath(
           "/var/containers/Bundle/Application/.jbroot-FA89B1D3A589") ==
         IOSArtifactClass::NONE);

  // ---- dyld image matching ---------------------------------------------------
  // Hooking-framework tokens, case-insensitive (v0.12.0 missed mixed case).
  {
    const IOSImageVerdict v = matchLoadedImage(
      "/private/var/jb/usr/lib/TweakInject/ElleKit.dylib");
    assert(v.hook && !v.frida);
  }
  assert(matchLoadedImage("/usr/lib/ELLEKIT.dylib").hook);
  assert(matchLoadedImage("/usr/lib/ElleKit.dylib").hook);
  assert(matchLoadedImage("/Library/MobileSubstrate/MobileSubstrate.dylib").hook);
  assert(matchLoadedImage("/usr/lib/CydiaSubstrate").hook);
  assert(matchLoadedImage("/usr/lib/libhooker.dylib").hook);
  assert(matchLoadedImage("/usr/lib/Substitute.framework/Substitute").hook);
  assert(matchLoadedImage("/usr/lib/rosalie.dylib").hook);
  assert(matchLoadedImage("/usr/lib/cynject.dylib").hook);

  // Frida / renamed gadget class.
  assert(matchLoadedImage("/usr/lib/frida-gadget.dylib").frida);
  assert(matchLoadedImage("/Frameworks/FridaR.dylib").frida);
  assert(matchLoadedImage("/usr/lib/libgadget.dylib").frida);
  assert(matchLoadedImage("/usr/lib/renamed-gadget.dylib").frida);
  {
    const IOSImageVerdict v = matchLoadedImage("/usr/lib/libgadget.dylib");
    assert(v.frida && !v.hook);
  }

  // Provenance rules: loaded from the rootless bootstrap tree or referencing
  // a roothide `.jbroot` symlink — catches fully renamed frameworks.
  assert(matchLoadedImage("/private/var/jb/usr/lib/SomeRenamedLib.dylib").hook);
  assert(matchLoadedImage(
           "/var/containers/Bundle/Application/.jbroot-5745/usr/lib/lib.dylib").hook);
  assert(matchLoadedImage(
           "@loader_path/.jbroot/usr/lib/libroothide.dylib").hook);
  {
    const IOSImageVerdict v = matchLoadedImage("/private/var/jb/usr/lib/totally_benign_name.dylib");
    assert(v.hook && !v.frida);
  }

  // Clean corpus: stock image paths never match.
  assert(!matchLoadedImage("/System/Library/Frameworks/UIKit.framework/UIKit").hook);
  assert(!matchLoadedImage("/usr/lib/system/libsystem_c.dylib").hook);
  assert(!matchLoadedImage(
           "/private/var/containers/Bundle/Application/UUID/App.app/App").hook);
  assert(!matchLoadedImage("/Developer/Library/InjectedLibraries/RLHubProtocol.dylib").hook);

  // Benign lookalikes must not fire: `legitgadget` contains neither the
  // `libgadget` nor the `gadget.dylib` token; `libRosaliaCore` is one letter
  // away from the `rosalie` token and must not match (guards against sloppy
  // substring widening).
  assert(!matchLoadedImage("/Frameworks/legitgadget.framework/legitgadget").frida);
  assert(!matchLoadedImage("/Frameworks/legitgadget.framework/legitgadget").hook);
  assert(!matchLoadedImage("/usr/lib/libRosaliaCore.dylib").hook);
  assert(!matchLoadedImage("/usr/lib/libSubstitutonManager.dylib").hook);
  assert(!matchLoadedImage("").hook && !matchLoadedImage("").frida);

  // ---- Catalog spot checks (parked signals keep policy-compliant weights) ---
  {
    const auto trollstore = lookupSignal(SignalId::IOS_SIDeload_TROLLSTORE);
    assert(trollstore.has_value());
    assert(trollstore->score == 5.0);
    assert(trollstore->severity == Severity::LOW);
    assert(trollstore->reliability == 0.35 && trollstore->reliability < 0.8);

    // Rootless + classic both firing (hybrid device) reaches exactly the
    // default minScore (40.0) — two independent artifact classes, reviewed.
    const auto rootless = lookupSignal(SignalId::IOS_JAILBREAK_ROOTLESS);
    const auto classic = lookupSignal(SignalId::IOS_JAILBREAK_ARTIFACT);
    assert(rootless.has_value() && classic.has_value());
    assert(rootless->score + classic->score == 40.0);
  }
}
