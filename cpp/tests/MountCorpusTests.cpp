///
/// MountCorpusTests.cpp
///
/// Clean-device corpus for the two mount scanners (WS-E). Every fixture is a
/// synthetic-but-shape-accurate `/proc/self/mountinfo` for a STOCK, unrooted
/// device class; each must yield ZERO findings from BOTH
/// `scanDenyListUnmountFingerprint()` and `scanMountsForOverlayFs()`.
///
/// Provenance: all fixtures are synthetic compositions built from public
/// evidence (AOSP emulator mount layout, dm-linear/erofs system-as-root
/// shapes, Xiaomi fstab overlay lines) — no real user data. Sources:
///   - Xiaomi HyperOS/MIUI OEM overlay fstab entries (verified Aug 2026 via
///     public fstab dumps; also AnyCheck issue #19, 2026-06-28).
///   - AOSP emulator/goldfish mount layout.
/// When the on-device measurement program (WS-F) captures real mountinfo
/// dumps, transplant them here verbatim with device/OS/date provenance.
///

#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"

#include <cassert>
#include <string_view>

using namespace margelo::nitro::rootjaildetect;

namespace {

  void assertNoMountFindings(std::string_view label, std::string_view mountinfo) {
    const auto denyList = scanDenyListUnmountFingerprint(mountinfo);
    assert(denyList.empty()); (void)denyList;
    const auto overlayFs = scanMountsForOverlayFs(mountinfo);
    assert(overlayFs.empty()); (void)overlayFs;
    (void)label;
  }

} // namespace

void runMountCorpusTests() {
  // Stock Pixel-style (system-as-root, dm-linear ext4/erofs, APEX tmpfs
  // outside the canonical six, /apex binds).
  assertNoMountFindings(
    "stock-pixel",
    "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
    "37 30 0:2 / /system rw,relatime shared:1 - erofs /dev/block/dm-1\n"
    "38 30 0:3 / /vendor rw,relatime shared:2 - erofs /dev/block/dm-2\n"
    "39 30 0:4 / /product rw,relatime shared:3 - erofs /dev/block/dm-4\n"
    "40 30 0:5 / /system_ext rw,relatime shared:4 - erofs /dev/block/dm-5\n"
    "41 30 0:6 / /apex rw,relatime - tmpfs apex rw\n"
    "42 30 0:7 /com.android.art /apex/com.android.art rw,relatime master:5 - ext4 /dev/block/dm-6\n"
    "43 30 0:8 / /data rw,relatime - f2fs /dev/block/dm-7\n"
    "44 30 0:9 / /dev rw,relatime - tmpfs none rw\n");

  // Stock Samsung One UI shape (extra /vnd/xxx mounts outside the allowlist).
  assertNoMountFindings(
    "stock-samsung",
    "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
    "37 30 0:2 / /system rw,relatime - erofs /dev/block/dm-1\n"
    "38 30 0:3 / /vendor rw,relatime - erofs /dev/block/dm-2\n"
    "39 30 0:4 / /product rw,relatime - erofs /dev/block/dm-3\n"
    "40 30 0:5 / /odm rw,relatime - erofs /dev/block/dm-4\n"
    "41 30 0:6 / /vendor/etc rw,relatime master:6 - erofs /dev/block/dm-2\n"
    "42 30 0:7 / /data rw,relatime - f2fs /dev/block/dm-8\n");

  // Stock Xiaomi HyperOS/MIUI shape INCLUDING the OEM overlay layers at
  // subpaths (mi_ext/pangu-backed). Mandatory clean case for both scanners.
  assertNoMountFindings(
    "stock-xiaomi-hyperos",
    "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n"
    "37 30 0:2 / /system rw,relatime - erofs /dev/block/dm-1\n"
    "38 30 0:3 / /vendor rw,relatime - erofs /dev/block/dm-2\n"
    "39 30 0:4 / /product rw,relatime - erofs /dev/block/dm-3\n"
    "40 30 0:5 / /mnt/vendor/mi_ext rw,relatime - erofs /dev/block/dm-9\n"
    "41 30 0:6 / /product/app rw,relatime - overlay overlay "
    "ro,lowerdir=/mnt/vendor/mi_ext/product/app:/product/app\n"
    "42 30 0:7 / /product/priv-app rw,relatime - overlay overlay "
    "ro,lowerdir=/mnt/vendor/mi_ext/product/priv-app:/product/priv-app\n"
    "43 30 0:8 / /system/app rw,relatime - overlay overlay "
    "ro,lowerdir=/mnt/vendor/mi_ext/system/app:/product/pangu/system/app:/system/app\n"
    "44 30 0:9 / /system_ext/etc/permissions rw,relatime - overlay overlay "
    "ro,lowerdir=/mnt/vendor/mi_ext/system_ext/etc/permissions:/system_ext/etc/permissions\n"
    "45 30 0:10 / /data rw,relatime - f2fs /dev/block/dm-8\n");

  // AOSP emulator shape: qemu block devices, extra tmpfs mounts (/dev, /mnt,
  // /storage) — all outside the six-path allowlist.
  assertNoMountFindings(
    "aosp-emulator",
    "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/vda1\n"
    "37 30 0:2 / /system rw,relatime - ext4 /dev/block/vda2\n"
    "38 30 0:3 / /vendor rw,relatime - ext4 /dev/block/vdb1\n"
    "39 30 0:4 / /product rw,relatime - ext4 /dev/block/vdb2\n"
    "40 30 0:5 / /dev rw,relatime - tmpfs none rw\n"
    "41 30 0:6 / /mnt rw,relatime - tmpfs none rw\n"
    "42 30 0:7 / /storage rw,relatime - tmpfs none rw\n"
    "43 30 0:8 / /data rw,relatime - ext4 /dev/block/vdc\n");

  // Adversarial input robustness: >1000-line input within the read budget cap,
  // truncated final line, CRLF mix — no crash, no finding on stock content.
  {
    std::string large;
    large.reserve(64 * 1024);
    for (int i = 0; i < 1200; ++i) {
      large += "36 30 0:1 / / rw,relatime master:1 - ext4 /dev/block/dm-0\n";
    }
    large += "37 30 0:2 / /system rw,relatime - erofs /dev/block/dm-1\r\n";
    large += "38 30 0:3 / /vendor rw,relatime - erofs /dev/block/dm-"; // truncated
    assert(scanDenyListUnmountFingerprint(large).empty());
    assert(scanMountsForOverlayFs(large).empty());
  }
}
