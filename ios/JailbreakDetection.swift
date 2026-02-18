import Foundation
import UIKit
import MachO
import Darwin

/**
 JailbreakDetection

 Provides multiple heuristics to determine whether an iOS device
 is jailbroken, running in a simulator, or being debugged.

 Designed for security-sensitive and SDK-based applications.
 */
@objc
class JailbreakDetection: NSObject {

    // MARK: - Known Jailbreak File Paths

    /**
     List of filesystem paths commonly associated with jailbroken devices.
     */
    private static let jailbreakFilePaths: [String] = [

        // Package Managers
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Icy.app",
        "/Applications/RockApp.app",

        // Classic Jailbreak Apps
        "/Applications/blackra1n.app",
        "/Applications/MxTube.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Applications/IntelliScreen.app",
        "/Applications/FakeCarrier.app",
        "/Applications/FlyJB.app",

        // Shell / SSH
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/sshd",
        "/usr/sbin/sshd",
        "/usr/libexec/sftp-server",
        "/etc/ssh/sshd_config",
        "/usr/libexec/ssh-keysign",
        "/usr/bin/ssh",

        // APT / DPKG
        "/etc/apt",
        "/var/cache/apt",
        "/var/log/apt",
        "/var/lib/cydia",
        "/var/lib/dpkg",
        "/private/var/lib/apt",
        "/private/var/cache/apt",
        "/private/var/lib/cydia",
        "/etc/apt/sources.list.d",

        // Logs
        "/private/var/tmp/cydia.log",
        "/var/log/syslog",
        "/private/var/log/syslog",

        // Substrate / Injection
        "/Library/MobileSubstrate",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/CydiaSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",

        // Tweaks
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist",
        "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist",

        // Launch Daemons
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",

        // Modern Jailbreaks
        "/.bootstrapped_electra",
        "/.cydia_no_stash",
        "/.installed_unc0ver",
        "/.installed_dopamine",

        "/jb",
        "/jb/lzma",
        "/jb/jailbreakd.plist",
        "/jb/offsets.plist",
        "/jb/amfid_payload.dylib",
        "/jb/libjailbreak.dylib",

        "/usr/lib/libjailbreak.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/libsubstitute.dylib",

        // checkra1n / palera1n
        "/var/binpack",
        "/var/binpack/Applications/loader.app",

        // Frida
        "/usr/sbin/frida-server",
        "/usr/bin/frida-server",
        "/usr/lib/frida",

        // Bypass Tools
        "/Library/PreferenceBundles/LibertyPref.bundle",
        "/Library/PreferenceBundles/ShadowPreferences.bundle",
        "/Library/PreferenceBundles/ABypassPrefs.bundle",
        "/Library/PreferenceBundles/FlyJBPrefs.bundle",

        "/Library/BawAppie/ABypass",
        "/var/mobile/Library/Preferences/ABPattern",
        "/var/mobile/Library/Preferences/me.jjolano.shadow.plist",

        // Preference Libraries
        "/Library/PreferenceBundles/Cephei.bundle",
        "/Library/PreferenceBundles/SubstitutePrefs.bundle",
        "/Library/PreferenceBundles/libhbangprefs.bundle",

        // User Data
        "/private/var/stash",
        "/private/var/Users",
        "/private/var/mobile/Library/SBSettings/Themes"
    ]

    // MARK: - Jailbreak URL Schemes

    /**
     URL schemes used by popular jailbreak-related applications.
     */
    private static let jailbreakURLSchemes: [String] = [
        "activator://",
        "undecimus://",
        "sileo://",
        "zbra://",
        "filza://",
        "cydia://"
    ]

    // MARK: - Primary Jailbreak Detection

    /**
     Determines whether the device is jailbroken.

     Uses multiple independent detection techniques
     to reduce false negatives.

     - Returns: true if the device is likely jailbroken
     */
    @objc
    static func isDeviceJailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return hasJailbreakFiles() ||
               canWriteToRestrictedDirectory() ||
               canOpenJailbreakURLSchemes() ||
               hasSuspiciousSymbolicLinks() ||
               hasInjectedDynamicLibraries() ||
               hasSuspiciousEnvironmentVariables() ||
               canReadFstabFile() ||
               canAccessRestrictedSystemPaths()
        #endif
    }

    // MARK: - Individual Detection Heuristics

    /**
     Checks for known jailbreak-related files and directories.
     */
    private static func hasJailbreakFiles() -> Bool {
        for path in jailbreakFilePaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }

    /**
     Attempts to write into restricted system directories.
     */
    private static func canWriteToRestrictedDirectory() -> Bool {
        let testPath = "/private/jailbreak_test.txt"

        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }

    /**
     Checks whether jailbreak-related URL schemes can be opened.
     */
    private static func canOpenJailbreakURLSchemes() -> Bool {

        guard let application =
                UIApplication.value(forKey: "sharedApplication") as? UIApplication
        else {
            return false
        }

        for scheme in jailbreakURLSchemes {

            guard let url = URL(string: scheme) else { continue }

            if application.canOpenURL(url) {
                return true
            }
        }

        return false
    }

    /**
     Detects symbolic links in protected system directories.
     */
    private static func hasSuspiciousSymbolicLinks() -> Bool {

        let protectedPaths = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]

        for path in protectedPaths {

            do {
                let attributes =
                    try FileManager.default.attributesOfItem(atPath: path)

                if let type = attributes[.type] as? FileAttributeType,
                   type == .typeSymbolicLink {
                    return true
                }

            } catch {
                continue
            }
        }

        return false
    }

    /**
     Scans loaded dynamic libraries for suspicious injection frameworks.
     */
    private static func hasInjectedDynamicLibraries() -> Bool {

        let suspiciousLibraries = [
            "MobileSubstrate",
            "SubstrateLoader",
            "Substitute",
            "libhooker",
            "TweakInject",
            "SSLKillSwitch",
            "Frida",
            "libcycript",
            "Shadow",
            "ABypass",
            "FlyJB",
            "RocketBootstrap",
            "PreferenceLoader",
            "systemhook",
            "/.file"
        ]

        for i in 0..<_dyld_image_count() {

            guard let imageName = _dyld_get_image_name(i) else {
                continue
            }

            let imagePath = String(cString: imageName).lowercased()

            for library in suspiciousLibraries {

                if imagePath.contains(library.lowercased()) {
                    return true
                }
            }
        }

        return false
    }

    /**
     Checks for environment variables used for dynamic injection.
     */
    private static func hasSuspiciousEnvironmentVariables() -> Bool {

        let environment = ProcessInfo.processInfo.environment
        let suspiciousVariables = [
            "DYLD_INSERT_LIBRARIES",
            "_MSSafeMode"
        ]

        for variable in suspiciousVariables {

            if environment[variable] != nil {
                return true
            }
        }

        return false
    }

    /**
     Attempts to read the fstab configuration file.
     */
    private static func canReadFstabFile() -> Bool {

        let fstabPath = "/etc/fstab"

        do {
            let contents =
                try String(contentsOfFile: fstabPath, encoding: .utf8)

            return !contents.isEmpty

        } catch {
            return false
        }
    }

    /**
     Attempts to access restricted system paths using stat().
     */
    private static func canAccessRestrictedSystemPaths() -> Bool {

        let restrictedPaths = [
            "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/libexec/cydia",
            "/usr/bin/cycript",
            "/usr/local/bin/cycript",
            "/usr/lib/libcycript.dylib"
        ]

        for path in restrictedPaths {

            var statInfo = stat()

            if stat(path, &statInfo) == 0 {
                return true
            }
        }

        return false
    }

    // MARK: - Simulator Detection

    /**
     Determines whether the app is running on a simulator.

     - Returns: true if running in simulator
     */
    @objc
    static func isSimulator() -> Bool {
        return isCompiledForSimulator() ||
               isRunningInSimulatorEnvironment()
    }

    /**
     Checks simulator environment variables at runtime.
     */
    private static func isRunningInSimulatorEnvironment() -> Bool {
        return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
    }

    /**
     Checks whether the app was compiled for simulator.
     */
    private static func isCompiledForSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    // MARK: - Debugger Detection

    /**
     Determines whether a debugger is currently attached.

     Uses sysctl to inspect process tracing flags.

     - Returns: true if debugging is active
     */
    @objc
    static func isDebuggerAttached() -> Bool {

        var debuggerDetected = false

        var name: [Int32] = [
            CTL_KERN,
            KERN_PROC,
            KERN_PROC_PID,
            getpid()
        ]

        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size

        let success = name.withUnsafeMutableBytes { buffer -> Bool in

            guard let baseAddress =
                    buffer.bindMemory(to: Int32.self).baseAddress
            else {
                return false
            }

            return sysctl(
                baseAddress,
                4,
                &info,
                &size,
                nil,
                0
            ) != -1
        }

        if !success {
            debuggerDetected = false
        }

        if !debuggerDetected &&
            (info.kp_proc.p_flag & P_TRACED) != 0 {

            debuggerDetected = true
        }

        return debuggerDetected
    }
}
