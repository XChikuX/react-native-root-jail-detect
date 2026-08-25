///
/// OverlayFsTests.cpp
///
/// Exhaustive fixture coverage for `scanMountsForOverlayFs()` — the parser
/// behind the `android.mount.overlayfs` signal (WS-D classification rules).
/// Pure and deterministic; every rule row is pinned with fixtures.
///
/// Classification contract:
///   - Only EXACT canonical partition-root mountpoints (`/system`, `/vendor`,
///     `/product`, `/system_ext`, `/odm`, `/oem`) can fire; subpath mounts
///     (`/system/app`, ...) never fire (Xiaomi OEM layering corpus).
///   - Overlays whose every lowerdir/upperdir/workdir component carries a
///     known OEM backing prefix are suppressed (stock resource layering).
///   - Any user-writable-backed component (`/data`, `/storage`, `/sdcard`)
///     fires with the `;user-writable-backing` evidence flag.
///   - Block/vendor-backed or uninspectable overlays fire (adb remount / GSI).
///   - Evidence paths are deduplicated (stacked overlays of one path = 1).
///

#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"

#include <cassert>
#include <string_view>

using namespace margelo::nitro::rootjaildetect;

void runOverlayFsTests() {
  const std::string_view signalId = SignalId::ANDROID_MOUNT_OVERLAYFS;

  // ---- Positives ----------------------------------------------------------

  // Strongest form: user-writable (/data) backing at an exact partition root —
  // the meta-module / overlayfs-module root class. Evidence carries the flag.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - overlay overlay "
      "rw,lowerdir=/system_root/system:/data/adb/overlay,upperdir=/data/adb/overlay_up\n"
      "38 30 0:3 / /data rw,relatime - ext4 /dev/block/dm-3\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
    assert(findings.front().evidence ==
           "overlay-over-system-paths=/system;user-writable-backing");
  }

  // User-writable backing detected via /storage and /sdcard prefixes too.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /vendor rw - overlay overlay rw,lowerdir=/sdcard/Mods/vendor\n"
      "38 30 0:3 / /product rw - overlay overlay rw,lowerdir=/storage/emulated/0/mod\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence ==
           "overlay-over-system-paths=/vendor,/product;user-writable-backing");
  }

  // adb-remount style: block/vendor-backed lowerdir, no user-writable part.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime - overlay overlay "
      "rw,lowerdir=/mnt/scratch/system:/system_root/system\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence == "overlay-over-system-paths=/system");
  }

  // Uninspectable super-options (no lowerdir/upperdir/workdir at all): fires
  // in the remount/GSI class rather than being guessed at.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime - overlay /dev/block/sda6 rw\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence == "overlay-over-system-paths=/system");
  }

  // Both `overlay` and `overlayfs` spellings; optional fields shift the
  // separator; multiple paths all listed in the evidence.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime shared:1 - overlay overlay rw\n"
      "38 30 0:3 / /vendor rw,relatime shared:2 master:2 - overlayfs overlay rw\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence == "overlay-over-system-paths=/system,/vendor");
  }

  // Stacked duplicate overlays of the same path are deduplicated (F3.3 fix).
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - overlay overlay rw,lowerdir=/a\n"
      "38 30 0:3 / /system rw - overlay overlay rw,lowerdir=/b\n"
      "39 30 0:4 / /system rw - overlay overlay rw,lowerdir=/c\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence == "overlay-over-system-paths=/system");
  }

  // Escaped comma inside a lowerdir value: the value must not be truncated
  // at the `\,`, and following options must still parse.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - overlay overlay "
      "rw,lowerdir=/a\\,b:/c,upperdir=/mnt/up\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence == "overlay-over-system-paths=/system");
  }

  // ---- Negatives ----------------------------------------------------------

  assert(scanMountsForOverlayFs("").empty());
  assert(scanMountsForOverlayFs("\n\n").empty());

  // Xiaomi HyperOS/MIUI stock shape (AnyCheck #19, 2026-06-28): OEM overlays
  // live at SUBPATHS — never fire under the exact-root rule.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - erofs /dev/block/dm-1\n"
      "38 30 0:3 / /product rw,relatime - erofs /dev/block/dm-2\n"
      "39 30 0:4 / /product/app rw,relatime - overlay overlay "
      "ro,lowerdir=/mnt/vendor/mi_ext/product/app:/product/app\n"
      "40 30 0:5 / /product/priv-app rw,relatime - overlay overlay "
      "ro,lowerdir=/mnt/vendor/mi_ext/product/priv-app:/product/priv-app\n"
      "41 30 0:6 / /system/app rw,relatime - overlay overlay "
      "ro,lowerdir=/mnt/vendor/mi_ext/system/app:/product/pangu/system/app:/system/app\n"
      "42 30 0:7 / /system_ext/etc/permissions rw,relatime - overlay overlay "
      "ro,lowerdir=/mnt/vendor/mi_ext/system_ext/etc/permissions:/system_ext/etc/permissions\n";
    assert(scanMountsForOverlayFs(mountinfo).empty());
  }

  // Hypothetical OEM overlay AT an exact partition root: fully OEM-backed →
  // suppressed (the suppression list is the guard, not just the subpath rule).
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /product rw - overlay overlay "
      "ro,lowerdir=/mnt/vendor/mi_ext/product:/product/pangu/product\n";
    assert(scanMountsForOverlayFs(mountinfo).empty());
  }

  // Mixed backing (one OEM component + one block component) is NOT
  // suppressed: only fully-OEM-backed overlays are stock.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - overlay overlay "
      "ro,lowerdir=/mnt/vendor/mi_ext/system:/system_root/system\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().evidence == "overlay-over-system-paths=/system");
  }

  // Stock device: system partitions backed by block devices — nothing fires.
  {
    constexpr std::string_view mountinfo =
      "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
      "37 30 0:2 / /system rw,relatime - erofs /dev/block/dm-1 rw\n"
      "38 30 0:3 / /vendor rw,relatime - ext4 /dev/block/dm-2 rw\n"
      "39 30 0:4 / /product rw,relatime - f2fs /dev/block/dm-3 rw\n";
    assert(scanMountsForOverlayFs(mountinfo).empty());
  }

  // Overlay over *non-system* paths (container/docker-style on /data, /sbin,
  // /debug_ramdisk, /) is not a system-image modification — must not fire.
  // (KSU meta-overlayfs at `/` is a documented accepted FN of the exact-root
  // rule; the subpath rule exists because of the stock Xiaomi corpus.)
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /data rw,relatime - overlay overlay rw\n"
      "38 30 0:3 / /sbin rw,relatime - overlay overlay rw\n"
      "39 30 0:4 / /debug_ramdisk rw,relatime - overlay overlay rw\n"
      "40 30 0:5 / / rw,relatime - overlay overlay rw,lowerdir=/systemrl:/data/adb/ksu\n";
    assert(scanMountsForOverlayFs(mountinfo).empty());
  }

  // tmpfs over /system is the structural-residue scanner's domain, not this one.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - tmpfs magisk rw\n"
      "38 30 0:3 / /vendor rw - tmpfs magisk rw\n";
    assert(scanMountsForOverlayFs(mountinfo).empty());
  }

  // Paths that merely prefix a canonical path, or add a trailing slash, never fire.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /systemfoo rw - overlay overlay rw\n"
      "38 30 0:3 / /system/ rw - overlay overlay rw\n";
    assert(scanMountsForOverlayFs(mountinfo).empty());
  }

  // Malformed lines (missing separator, truncated before fstype/source) are
  // skipped safely.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw,relatime\n"
      "38 30 0:3 / /vendor rw,relatime - overlay\n"
      "39 30 0:4 / /product rw,relatime -\n";
    assert(scanMountsForOverlayFs(mountinfo).empty());
  }

  // CRLF input: the trailing `\r` rides along in super-options; parsing holds.
  {
    constexpr std::string_view mountinfo =
      "37 30 0:2 / /system rw - overlay overlay rw,lowerdir=/a\r\n"
      "38 30 0:3 / /vendor rw - ext4 /dev/block/dm-1 rw\r\n";
    const auto findings = scanMountsForOverlayFs(mountinfo);
    assert(findings.size() == 1);
    assert(findings.front().signalId == signalId);
  }
}
