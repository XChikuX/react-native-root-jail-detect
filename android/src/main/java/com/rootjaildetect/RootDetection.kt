package com.rootjaildetect

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File
import java.io.BufferedReader
import java.io.InputStreamReader

class RootDetection(private val context: Context) {

    companion object {
        // Common root management apps
        private val ROOT_APPS = arrayOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.rootking",
            "com.alephzain.framaroot"
        )

        // Common binary paths
        private val SU_BINARY_PATHS = arrayOf(
            "/data/local/",
            "/data/local/bin/",
            "/data/local/xbin/",
            "/sbin/",
            "/su/bin/",
            "/system/bin/",
            "/system/bin/.ext/",
            "/system/bin/failsafe/",
            "/system/sd/xbin/",
            "/system/usr/we-need-root/",
            "/system/xbin/",
            "/cache/",
            "/data/",
            "/dev/"
        )

        // Dangerous system properties
        private val DANGEROUS_PROPS = mapOf(
            "[ro.debuggable]" to "[1]",
            "[ro.secure]" to "[0]"
        )

        // Root-related files and directories
        private val ROOT_CLOAKING_PATHS = arrayOf(
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu"
        )
    }

    /**
     * Main method to check if device is rooted
     * Uses multiple detection techniques for better accuracy
     */
    fun isDeviceRooted(): Boolean {
        return checkRootMethod1() ||
               checkRootMethod2() ||
               checkRootMethod3() ||
               checkRootMethod4() ||
               checkRootMethod5() ||
               checkRootMethod6() ||
               checkRootMethod7()
    }

    /**
     * Check #1: Test for SU binary in common paths
     */
    private fun checkRootMethod1(): Boolean {
        SU_BINARY_PATHS.forEach { path ->
            val suFile = File(path + "su")
            if (suFile.exists()) {
                return true
            }
        }
        return false
    }

    /**
     * Check #2: Check for installed root management apps
     */
    private fun checkRootMethod2(): Boolean {
        ROOT_APPS.forEach { packageName ->
            try {
                context.packageManager.getPackageInfo(packageName, 0)
                return true
            } catch (e: PackageManager.NameNotFoundException) {
                // Package not found, continue
            }
        }
        return false
    }

    /**
     * Check #3: Check Build tags for test-keys
     */
    private fun checkRootMethod3(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    /**
     * Check #4: Try to execute 'su' command
     */
    private fun checkRootMethod4(): Boolean {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val bufferedReader = BufferedReader(InputStreamReader(process.inputStream))
            bufferedReader.readLine() != null
        } catch (e: Exception) {
            false
        } finally {
            process?.destroy()
        }
    }

    /**
     * Check #5: Check for dangerous system properties
     */
    private fun checkRootMethod5(): Boolean {
        var process: Process? = null
        try {
            process = Runtime.getRuntime().exec("getprop")
            val bufferedReader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            while (bufferedReader.readLine().also { line = it } != null) {
                DANGEROUS_PROPS.forEach { (key, value) ->
                    if (line?.contains(key) == true && line?.contains(value) == true) {
                        return true
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore
        } finally {
            process?.destroy()
        }
        return false
    }

    /**
     * Check #6: Check for RW paths that should be RO
     */
    private fun checkRootMethod6(): Boolean {
        var process: Process? = null
        try {
            process = Runtime.getRuntime().exec("mount")
            val bufferedReader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            while (bufferedReader.readLine().also { line = it } != null) {
                val args = line?.split(" ") ?: continue
                if (args.size < 4) continue
                
                val mountPoint = args[1]
                val mountType = args[2]
                val mountOptions = args[3]

                // Check if /system is mounted as rw
                if (mountPoint == "/system" && 
                    mountOptions.contains("rw")) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Ignore
        } finally {
            process?.destroy()
        }
        return false
    }

    /**
     * Check #7: Check for root cloaking files
     */
    private fun checkRootMethod7(): Boolean {
        ROOT_CLOAKING_PATHS.forEach { path ->
            if (File(path).exists()) {
                return true
            }
        }
        return false
    }

    /**
     * Additional check: Verify if running in emulator
     * Emulators are often rooted by default
     */
    fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic") ||
                "google_sdk" == Build.PRODUCT)
    }

    /**
     * Additional check: Verify if debugger
     * is attached or not
     */
    fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected()
    }
}