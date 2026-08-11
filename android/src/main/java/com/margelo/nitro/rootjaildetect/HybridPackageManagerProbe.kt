package com.margelo.nitro.rootjaildetect

import android.content.Context
import android.content.pm.PackageManager
import androidx.annotation.Keep
import com.facebook.proguard.annotations.DoNotStrip

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
    val context = getApplicationContext()
    if (context == null) {
      return emptyArray()
    }

    val packageManager = context.packageManager
    val rootPackages = mutableListOf<String>()

    // Known root management packages
    val knownRootPackages = mapOf(
      "com.topjohnwu.magisk" to "Magisk",
      "eu.chainfire.supersu" to "SuperSU",
      "com.noshufou.android.su" to "Superuser (ClockworkMod)",
      "com.kingroot.kinguser" to "KingRoot",
      "com.koushikdutta.superuser" to "Superuser (Koush)",
      "com.ramdroid.appquarantine" to "App Quarantine"
    )

    for ((packageName, _) in knownRootPackages) {
      try {
        packageManager.getPackageInfo(packageName, 0)
        // Package is installed
        rootPackages.add(packageName)
      } catch (e: PackageManager.NameNotFoundException) {
        // Package not installed, continue
      }
    }

    return rootPackages.toTypedArray()
  }

  /**
   * Get the application context via ActivityThread reflection.
   * This is a common pattern when we don't have direct access to Context.
   */
  private fun getApplicationContext(): Context? {
    try {
      val activityThreadClass = Class.forName("android.app.ActivityThread")
      val currentActivityThreadMethod = activityThreadClass.getDeclaredMethod("currentActivityThread")
      currentActivityThreadMethod.isAccessible = true
      val activityThread = currentActivityThreadMethod.invoke(null)
      val getApplicationMethod = activityThreadClass.getDeclaredMethod("getApplication")
      getApplicationMethod.isAccessible = true
      val application = getApplicationMethod.invoke(activityThread)
      return application as? Context
    } catch (e: Exception) {
      return null
    }
  }
}
