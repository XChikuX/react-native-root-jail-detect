///
/// DenyListFingerprintTests.cpp
///
/// Exhaustive fixture coverage for `scanDenyListUnmountFingerprint()` — the
/// parser behind the `android.mount.denylist_unmount` signal. The parser is
/// pure and deterministic, so every behavior below is exercisable on the host
/// without a device.
///
/// The parser's contract (structural residue detector):
///   - Indicator A (gate): fire when >= 2 *distinct* canonical system paths
///     (`/system`, `/vendor`, `/product`, `/system_ext`, `/odm`, `/oem`) show
///     a `tmpfs` filesystem type — **regardless of mount source** (legacy
///     MagiskHide stoppers used `magisk` sources; modern partial cleanups and
///     forks use randomized or `debug_ramdisk` sources).
///   - Indicator B (evidence enrichment only): surviving magisk tokens on any
///     line (source, `/adb/modules` root, `.magisk` path) append
///     `;residual-magisk-artifacts` to the evidence. B alone never fires —
///     visible artifacts belong to the explicit-mount signals.
///   - locate the filesystem type/source relative to the `-` separator so
///     optional mountinfo fields (`shared`, `master`, ...) never shift parsing,
///   - never throw, never match non-canonical or inexact paths, and never
///     confuse other fields with the mount source.
///

#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"

#include <cassert>
#include <string_view>

using namespace margelo::nitro::rootjaildetect;

void runDenyListFingerprintTests() {
  const std::string_view signalId = SignalId::ANDROID_MOUNT_DENYLIST_UNMOUNT;

  // ---- Positives: Indicator A, source-independent --------------------------

  // BEHAVIORAL PIN (v0.13.0): two bare tmpfs-over-system mounts with
  // randomized/debug sources fire. v0.12.0 required a magisk-named source and
  // was structurally blind to exactly these cleanups.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - tmpfs debug_ramdisk rw,mode=755\n"
      "38 30 0:3 / /vendor rw,relatime - tmpfs 7f3a9c1e2b rw,mode=755\n"
      "39 30 0:4 / /data rw,relatime - ext4 /dev/block/dm-3\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
    assert(findings.front().evidence == "tmpfs-over-system-paths=/system,/vendor");
  }

  // Legacy MagiskHide shape: magisk-named sources still fire (no detection loss
  // for old frameworks/Android versions) and add the residual marker.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - tmpfs magisk rw,mode=755\n"
      "38 30 0:3 / /vendor rw,relatime - tmpfs core/magisk rw,mode=755\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
    assert(findings.front().evidence ==
           "tmpfs-over-system-paths=/system,/vendor;residual-magisk-artifacts");
  }

  // Partial cleanup (Kitsune-style): tmpfs stoppers left behind AND surviving
  // /adb/modules bind lines. One deduplicated finding, combined evidence.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - tmpfs random_stop_1 rw\n"
      "38 30 0:3 / /vendor rw,relatime - tmpfs none rw\n"
      "39 30 0:4 /adb/modules/ksu /system/app/Mod x rw - ext4 /dev/block/dm-1 rw\n"
      "40 30 0:5 / /.magisk/mirror/system x rw - ext4 /dev/block/dm-2 rw\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence ==
           "tmpfs-over-system-paths=/system,/vendor;residual-magisk-artifacts");
  }

  // Optional fields (`shared`, `master`) shift the separator. Fixed-column
  // parsing would read the separator as the filesystem type and never fire.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime shared:1 master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime shared:2 master:2 - tmpfs 0 rw,mode=755\n"
      "38 30 0:3 / /vendor rw,relatime shared:3 - tmpfs 0 rw,mode=755\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence == "tmpfs-over-system-paths=/system,/vendor");
  }

  // `unbindable` / `propagate_from:` optional fields in varying counts.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw unbindable - tmpfs xyz rw\n"
      "38 30 0:3 / /product rw propagate_from:12 - tmpfs xyz rw\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence == "tmpfs-over-system-paths=/system,/product");
  }

  // All six canonical paths match; evidence lists every path in first-seen order.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs a rw\n"
      "38 30 0:3 / /vendor rw - tmpfs b rw\n"
      "39 30 0:4 / /product rw - tmpfs c rw\n"
      "40 30 0:5 / /system_ext rw - tmpfs d rw\n"
      "41 30 0:6 / /odm rw - tmpfs e rw\n"
      "42 30 0:7 / /oem rw - tmpfs f rw\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence ==
           "tmpfs-over-system-paths=/system,/vendor,/product,/system_ext,/odm,/oem");
  }

  // Case-insensitive magisk token (Indicator B only enriches evidence).
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs MAGISK rw\n"
      "38 30 0:3 / /vendor rw - tmpfs Magisk rw\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence ==
           "tmpfs-over-system-paths=/system,/vendor;residual-magisk-artifacts");
  }

  // CRLF line endings: the trailing `\r` lands in super-options, which the
  // parser never reads, so the fingerprint still resolves.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime - tmpfs q1 rw,mode=755\r\n"
      "38 30 0:3 / /vendor rw,relatime - tmpfs q2 rw,mode=755\r\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
  }

  // No trailing newline on the final line is still parsed.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs z rw\n"
      "38 30 0:3 / /vendor rw - tmpfs z rw";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
  }

  // ---- Negatives ----------------------------------------------------------

  // Empty and whitespace-only input.
  assert(scanDenyListUnmountFingerprint("").empty());
  assert(scanDenyListUnmountFingerprint("\n\n\n").empty());
  assert(scanDenyListUnmountFingerprint("   \n  \n").empty());

  // Stock device: system paths backed by real block devices.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - ext4 /dev/block/dm-1\n"
      "38 30 0:3 / /vendor rw,relatime - erofs /dev/block/dm-2\n"
      "39 30 0:4 / /data rw,relatime - ext4 /dev/block/dm-3\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // HONEST EXPECTED-NEGATIVE (documented FN): a *correctly cleaned* modern
  // Magisk v24+ DenyList namespace. `revert_unmount()` removes every
  // framework mount including the Magisk tmpfs, so neither indicator is
  // present. This signal is not DenyList-proof by design; do not "fix" this
  // fixture to fire.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - erofs /dev/block/dm-1\n"
      "38 30 0:3 / /vendor rw,relatime - erofs /dev/block/dm-2\n"
      "39 30 0:4 / /product rw,relatime - erofs /dev/block/dm-3\n"
      "40 30 0:5 / /apex rw,relatime - tmpfs apex rw\n"
      "41 30 0:6 / /dev rw,relatime - tmpfs none rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // One tmpfs-over-system path: below the two-path gate, even with a magisk source.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime - tmpfs magisk rw,mode=755\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Same path twice: the gate requires *distinct* paths.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime - tmpfs magisk rw,mode=755\n"
      "38 30 0:3 / /system rw,relatime - tmpfs magisk rw,mode=755\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // tmpfs over non-canonical paths must never match, even with a magisk source
  // (stock tmpfs targets: /apex, /dev, /sbin, /debug_ramdisk, /data, /).
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /sbin rw - tmpfs magisk rw\n"
      "38 30 0:3 / /debug_ramdisk rw - tmpfs magisk rw\n"
      "39 30 0:4 / /apex rw - tmpfs apex rw\n"
      "40 30 0:5 / /data rw - tmpfs none rw\n"
      "41 30 0:6 / / rw - tmpfs root rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Paths that merely *prefix* a canonical path are not exact matches.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /systemfoo rw - tmpfs x rw\n"
      "38 30 0:3 / /vendorx rw - tmpfs x rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Trailing-slash variants are not exact matches either.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system/ rw - tmpfs x rw\n"
      "38 30 0:3 / /vendor/ rw - tmpfs x rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Non-tmpfs filesystems over system paths: not the structural-residue shape
  // (overlay/ext4 with any source is another scanner's domain).
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - overlay overlay rw\n"
      "38 30 0:3 / /vendor rw - ext4 /dev/block/dm-1 rw\n"
      "39 30 0:4 / /product rw - f2fs /dev/block/dm-2 rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Indicator B alone never fires: explicit magisk artifacts with no
  // tmpfs-over-system residue are the explicit-mount signal's domain.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - ext4 /dev/block/dm-1 rw\n"
      "38 30 0:3 /adb/modules/mod /system/app/Mod x rw - ext4 /dev/block/dm-1 rw\n"
      "39 30 0:4 / /.magisk/mirror/system x rw - ext4 /dev/block/dm-2 rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // `magisk` in mount options / optional fields / super-options, with no
  // Indicator A: no fire (the token is evidence enrichment only).
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,magisk - ext4 /dev/block/dm-1 rw\n"
      "38 30 0:3 / /vendor rw shared:magisk - ext4 /dev/block/dm-2 rw,magisk=1\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Malformed lines (missing separator, truncated) never fire and never throw.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime\n"
      "38 30 0:3 / /vendor rw,relatime - tmpfs\n"
      "39 30 0:4 / /product rw,relatime - tmpfs z\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }
}
