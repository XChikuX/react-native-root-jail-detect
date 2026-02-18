package com.rootjaildetect

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * RootDetection
 *
 * Provides multiple heuristics to detect whether an Android device
 * is rooted, running in an emulator, or being debugged.
 *
 * Designed for security-sensitive applications and SDKs.
 */
class RootDetection(private val context: Context) {

    companion object {

        /**
         * List of well-known root management applications.
         */
        private val ROOT_MANAGEMENT_PACKAGES = arrayOf(
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

        /**
         * Common filesystem locations where the "su" binary may exist.
         */
        private val SU_BINARY_DIRECTORIES = arrayOf(
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

        /**
         * System properties that indicate an insecure or rooted device.
         */
        private val DANGEROUS_SYSTEM_PROPERTIES = mapOf(
            "[ro.debuggable]" to "[1]",
            "[ro.secure]" to "[0]",
            "[service.adb.root]" to "[1]"
        )

        /**
         * Files and directories commonly used by root hiding frameworks.
         */
        private val ROOT_CLOAKING_FILE_PATHS = arrayOf(
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu"
        )
    }

    /**
     * Determines whether the current device is rooted.
     *
     * Combines multiple independent detection techniques
     * to improve accuracy and reduce false negatives.
     *
     * @return true if the device is likely rooted, false otherwise
     */
    fun isDeviceRooted(): Boolean {
        return hasSuBinaryInCommonDirectories() ||
                hasInstalledRootManagementApps() ||
                hasTestKeysInBuildTags() ||
                canExecuteSuCommand() ||
                hasDangerousSystemProperties() ||
                hasWritableSystemPartition() ||
                hasRootCloakingFiles()
    }

    /**
     * Checks for the presence of the "su" binary in common directories.
     *
     * Rooted devices usually expose this binary.
     */
    private fun hasSuBinaryInCommonDirectories(): Boolean {
        SU_BINARY_DIRECTORIES.forEach { directory ->
            val suFile = File(directory + "su")
            if (suFile.exists()) {
                return true
            }
        }
        return false
    }

    /**
     * Checks whether known root management applications are installed.
     *
     * Presence of these apps strongly indicates rooting.
     */
    private fun hasInstalledRootManagementApps(): Boolean {
        ROOT_MANAGEMENT_PACKAGES.forEach { packageName ->
            try {
                context.packageManager.getPackageInfo(packageName, 0)
                return true
            } catch (_: PackageManager.NameNotFoundException) {
                // App not installed, continue checking
            }
        }
        return false
    }

    /**
     * Verifies whether the device build contains "test-keys".
     *
     * Custom ROMs and rooted devices often use test keys.
     */
    private fun hasTestKeysInBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    /**
     * Attempts to locate the "su" binary using shell commands.
     *
     * Successful execution indicates root access.
     */
    private fun canExecuteSuCommand(): Boolean {
        var process: Process? = null

        return try {
            process = Runtime.getRuntime()
                .exec(arrayOf("/system/xbin/which", "su"))

            val reader = BufferedReader(
                InputStreamReader(process.inputStream)
            )

            reader.readLine() != null

        } catch (_: Exception) {
            false
        } finally {
            process?.destroy()
        }
    }

    /**
     * Reads system properties and checks for insecure configurations.
     *
     * Certain properties are modified on rooted devices.
     */
    private fun hasDangerousSystemProperties(): Boolean {
        var process: Process? = null

        try {
            process = Runtime.getRuntime().exec("getprop")

            val reader = BufferedReader(
                InputStreamReader(process.inputStream)
            )

            var line: String?

            while (reader.readLine().also { line = it } != null) {

                DANGEROUS_SYSTEM_PROPERTIES.forEach { (key, value) ->
                    if (line?.contains(key) == true &&
                        line?.contains(value) == true
                    ) {
                        return true
                    }
                }
            }

        } catch (_: Exception) {
            // Ignore failures
        } finally {
            process?.destroy()
        }

        return false
    }

    /**
     * Checks whether critical system partitions are mounted as writable.
     *
     * On non-rooted devices, /system should be read-only.
     */
    private fun hasWritableSystemPartition(): Boolean {
        var process: Process? = null

        try {
            process = Runtime.getRuntime().exec("mount")

            val reader = BufferedReader(
                InputStreamReader(process.inputStream)
            )

            var line: String?

            while (reader.readLine().also { line = it } != null) {

                val parts = line?.split(" ") ?: continue

                if (parts.size < 4) continue

                val mountPoint = parts[1]
                val mountOptions = parts[3]

                if (mountPoint == "/system" &&
                    mountOptions.contains("rw")
                ) {
                    return true
                }
            }

        } catch (_: Exception) {
            // Ignore failures
        } finally {
            process?.destroy()
        }

        return false
    }

    /**
     * Searches for files commonly used to hide or manage root.
     *
     * These files are rarely present on stock devices.
     */
    private fun hasRootCloakingFiles(): Boolean {
        ROOT_CLOAKING_FILE_PATHS.forEach { path ->
            if (File(path).exists()) {
                return true
            }
        }
        return false
    }

    /**
     * Determines whether the application is running inside an emulator.
     *
     * Many emulators run with root privileges by default.
     *
     * @return true if running on an emulator
     */
    fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.BRAND.startsWith("generic") &&
                Build.DEVICE.startsWith("generic") ||
                Build.PRODUCT == "google_sdk" ||
                Build.PRODUCT.contains("sdk") ||
                Build.PRODUCT.contains("simulator"))
    }

    /**
     * Checks whether a debugger is currently attached to the process.
     *
     * Useful for detecting reverse engineering and runtime inspection.
     *
     * @return true if debugging is active
     */
    fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected() ||
                Debug.waitingForDebugger()
    }
}
