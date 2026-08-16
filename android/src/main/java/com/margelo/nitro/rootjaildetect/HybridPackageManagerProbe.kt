package com.margelo.nitro.rootjaildetect

import android.content.pm.PackageManager
import androidx.annotation.Keep
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.NitroModules

/**
 * Android edge HybridObject for PackageManager enumeration of known root packages.
 *
 * This implementation queries the Android PackageManager for installed packages
 * that are commonly associated with root access (Magisk, SuperSU, KingRoot, etc.).
 */
@DoNotStrip
@Keep
class HybridPackageManagerProbe : HybridPackageManagerProbeSpec() {

  override fun getInstalledRootPackages(): Array<String> {
    return queryPackages(knownRootPackages)
  }

  override fun getInstalledHidingPackages(): Array<String> {
    return queryPackages(hostileHidingPackages)
  }

  override fun getInstalledRiskyPackages(): Array<String> {
    return queryPackages(riskyApps)
  }

  private val knownRootPackages = mapOf(
      "com.topjohnwu.magisk" to "Magisk",
      "me.weishu.kernelsu" to "KernelSU",
      "me.bmax.apatch" to "APatch",
      "eu.chainfire.supersu" to "SuperSU",
      "com.noshufou.android.su" to "Superuser (ClockworkMod)",
      "com.kingroot.kinguser" to "KingRoot",
      "com.koushikdutta.superuser" to "Superuser (Koush)",
      "com.ramdroid.appquarantine" to "App Quarantine",
      "com.thirdparty.superuser" to "Superuser",
      "com.yellowes.su" to "YellowesSU",
      "com.zhiqupk.root.global" to "ZhiQuPK",
      "com.alephzain.framaroot" to "Framaroot",
      "com.kingo.root" to "KingoRoot",
      "com.smedialink.oneclickroot" to "OneClickRoot",
    )

  private val hostileHidingPackages = mapOf(
      "com.tsng.hidemyapplist" to "Hide My Applist",
      "org.meowcat.edxposed.manager" to "EdXposed Manager",
      "com.solohsu.android.edxp.manager" to "EdXposed Manager",
      "de.robv.android.xposed.installer" to "Xposed Installer",
      "com.saurik.substrate" to "MobileSubstrate",
      "org.lsposed.manager" to "LSPosed Manager",
      "io.github.lsposed.manager" to "LSPosed Manager",
      "com.zachspong.temprootremovejb" to "TempRootRemove",
      "com.amphoras.hidemyroot" to "Hide My Root",
    )

  private val riskyApps = mapOf(
      "com.koushikdutta.rommanager" to "ROM Manager",
      "com.dimonvideo.luckypatcher" to "Lucky Patcher",
      "com.chelpus.luckypatcher" to "Lucky Patcher",
      "com.blackmartalpha" to "BlackMart Alpha",
      "org.blackmart.market" to "BlackMart",
      "com.xmodgame" to "Xmodgames",
      "com.cih.game_cih" to "GameCIH",
      "cc.madkite.freedom" to "Freedom",
      "com.ramdroid.appquarantinepro" to "App Quarantine Pro",
    )

  private fun queryPackages(packages: Map<String, String>): Array<String> {
    val context = NitroModules.applicationContext ?: return emptyArray()
    val packageManager = context.packageManager
    val installedPackages = mutableListOf<String>()
    for ((packageName, _) in packages) {
      try {
        packageManager.getPackageInfo(packageName, 0)
        installedPackages.add(packageName)
      } catch (e: PackageManager.NameNotFoundException) {
        // Package not installed, continue
      } catch (e: SecurityException) {
        // Package visibility or host policy can deny the query.
      }
    }
    return installedPackages.toTypedArray()
  }
}
