///
/// DenyListFingerprintTests.cpp
///
/// Exhaustive fixture coverage for `scanDenyListUnmountFingerprint()` — the
/// parser behind the `android.mount.denylist_unmount` signal. The parser is
/// pure and deterministic, so every behavior below is exercisable on the host
/// without a device.
///
/// The parser's contract:
///   - fire only when >= 2 *distinct* canonical system paths show a `tmpfs`
///     filesystem type whose mount source mentions `magisk` (case-insensitive,
///     which also matches `core/magisk`),
///   - locate the filesystem type/source relative to the `-` separator so
///     optional mountinfo fields (`shared`, `master`, ...) never shift parsing,
///   - never throw, never match non-system paths, never match non-tmpfs
///     filesystems, and never confuse the mount source with other fields.
///

#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"

#include <cassert>
#include <string_view>

using namespace margelo::nitro::rootjaildetect;

void runDenyListFingerprintTests() {
  const std::string_view signalId = SignalId::ANDROID_MOUNT_DENYLIST_UNMOUNT;

  // ---- Positives ----------------------------------------------------------

  // Minimal fingerprint: two tmpfs-over-system mounts with magisk sources.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - tmpfs magisk rw,mode=755\n"
      "38 30 0:3 / /vendor rw,relatime - tmpfs core/magisk rw,mode=755\n"
      "39 30 0:4 / /data rw,relatime - ext4 /dev/block/dm-3\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
    assert(findings.front().evidence == "tmpfs-over-system-paths=/system,/vendor");
  }

  // Optional fields (`shared`, `master`) shift the separator. Fixed-column
  // parsing would read the separator as the filesystem type and never fire.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime shared:1 master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime shared:2 master:2 - tmpfs magisk rw,mode=755\n"
      "38 30 0:3 / /vendor rw,relatime shared:3 - tmpfs core/magisk rw,mode=755\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
    assert(findings.front().evidence == "tmpfs-over-system-paths=/system,/vendor");
  }

  // Case-insensitive source match and >2 paths; evidence lists every path.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs MAGISK rw\n"
      "38 30 0:3 / /vendor rw - tmpfs Magisk rw\n"
      "39 30 0:4 / /product rw - tmpfs core/MAGISK rw\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
    assert(findings.front().evidence ==
           "tmpfs-over-system-paths=/system,/vendor,/product");
  }

  // All six canonical paths match; evidence is deduplicated per path.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs magisk rw\n"
      "38 30 0:3 / /vendor rw - tmpfs magisk rw\n"
      "39 30 0:4 / /product rw - tmpfs magisk rw\n"
      "40 30 0:5 / /system_ext rw - tmpfs magisk rw\n"
      "41 30 0:6 / /odm rw - tmpfs magisk rw\n"
      "42 30 0:7 / /oem rw - tmpfs magisk rw\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence ==
           "tmpfs-over-system-paths=/system,/vendor,/product,/system_ext,/odm,/oem");
  }

  // CRLF line endings: the trailing `\r` lands in super-options, which the
  // parser never reads, so the fingerprint still resolves.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime - tmpfs magisk rw,mode=755\r\n"
      "38 30 0:3 / /vendor rw,relatime - tmpfs core/magisk rw,mode=755\r\n";
    const auto findings = scanDenyListUnmountFingerprint(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
  }

  // No trailing newline on the final line is still parsed.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs magisk rw\n"
      "38 30 0:3 / /vendor rw - tmpfs magisk rw";
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
      "38 30 0:3 / /vendor rw,relatime - ext4 /dev/block/dm-2\n"
      "39 30 0:4 / /data rw,relatime - ext4 /dev/block/dm-3\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // One tmpfs-over-system with magisk source: below the two-path gate.
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
  // (these are the pre-DenyList visible-overlay mounts or unrelated mounts).
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /sbin rw - tmpfs magisk rw\n"
      "38 30 0:3 / /debug_ramdisk rw - tmpfs magisk rw\n"
      "39 30 0:4 / /apex rw - tmpfs magisk rw\n"
      "40 30 0:5 / /data rw - tmpfs magisk rw\n"
      "41 30 0:6 / / rw - tmpfs magisk rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Paths that merely *prefix* a canonical path are not exact matches.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /systemfoo rw - tmpfs magisk rw\n"
      "38 30 0:3 / /vendorx rw - tmpfs magisk rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Trailing-slash variants are not exact matches either.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system/ rw - tmpfs magisk rw\n"
      "38 30 0:3 / /vendor/ rw - tmpfs magisk rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // tmpfs over system paths with a non-magisk source (stock scoped storage,
  // work profiles, randomized sources).
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs system rw\n"
      "38 30 0:3 / /vendor rw - tmpfs none rw\n"
      "39 30 0:4 / /product rw - tmpfs tmpfs rw\n"
      "40 30 0:5 / /system_ext rw - tmpfs a1b2c3d4 rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Non-tmpfs filesystems over system paths with a magisk source: that is the
  // explicit-artifact signal's domain, not the fingerprint's.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - overlay magisk rw\n"
      "38 30 0:3 / /vendor rw - ext4 magisk rw\n"
      "39 30 0:4 / /product rw - f2fs magisk rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // `magisk` appearing in the mount *options* or optional fields must not be
  // mistaken for a magisk mount source.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,magisk - tmpfs system rw\n"
      "38 30 0:3 / /vendor rw shared:magisk - tmpfs none rw\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // `magisk` appearing only in super-options must not match either.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs system rw,magisk=1\n"
      "38 30 0:3 / /vendor rw - tmpfs none rw,magisk=1\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }

  // Malformed lines (missing separator, truncated) must be skipped safely.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime\n"
      "38 30 0:3 / /vendor rw,relatime - tmpfs\n"
      "39 30 0:4 / /product rw,relatime - tmpfs magisk\n";
    assert(scanDenyListUnmountFingerprint(mountinfo).empty());
  }
}
