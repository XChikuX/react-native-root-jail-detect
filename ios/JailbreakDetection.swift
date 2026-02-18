import Foundation
import UIKit
import MachO

@objc
class JailbreakDetection: NSObject {
    
    // MARK: - Jailbreak Detection Paths
    
    private static let jailbreakPaths: [String] = [
        "/Applications/Cydia.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt/",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/tmp/cydia.log",
        "/private/var/stash",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/usr/libexec/cydia/firmware.sh",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/var/cache/apt",
        "/var/lib/cydia",
        "/var/log/syslog",
        "/bin/sh",
        "/etc/ssh/sshd_config",
        "/usr/libexec/ssh-keysign",
        "/etc/apt/sources.list.d/electra.list",
        "/etc/apt/sources.list.d/sileo.sources",
        "/.bootstrapped_electra",
        "/usr/lib/libjailbreak.dylib",
        "/jb/lzma",
        "/.cydia_no_stash",
        "/.installed_unc0ver",
        "/.installed_dopamine",
        "/jb/offsets.plist",
        "/usr/share/jailbreak/injectme.plist",
        "/etc/apt/undecimus/undecimus.list",
        "/var/lib/dpkg/info/mobilesubstrate.md5sums",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist"
    ]
    
    private static let jailbreakSchemes: [String] = [
        "cydia://package/com.example.package",
        "sileo://package/com.example.package",
        "zbra://package/com.example.package",
        "filza://",
        "activator://"
    ]
    
    // MARK: - Main Detection Method
    
    @objc
    static func isDeviceJailbroken() -> Bool {
        #if targetEnvironment(simulator)
            return false
        #else
            return checkJailbreakMethod1() ||
                   checkJailbreakMethod2() ||
                   checkJailbreakMethod3() ||
                   checkJailbreakMethod4() ||
                   checkJailbreakMethod5() ||
                   checkJailbreakMethod6() ||
                   checkJailbreakMethod7() ||
                   checkJailbreakMethod8()
        #endif
    }
    
    // MARK: - Detection Methods
    
    /// Check #1: Test for existence of jailbreak files
    private static func checkJailbreakMethod1() -> Bool {
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    /// Check #2: Check if we can write to system directories
    private static func checkJailbreakMethod2() -> Bool {
        let testPath = "/private/jailbreak_test.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
    
    /// Check #3: Check if app can open Cydia URL scheme
    private static func checkJailbreakMethod3() -> Bool {
        guard let application = UIApplication.value(forKey: "sharedApplication") as? UIApplication else {
            return false
        }
        
        for scheme in jailbreakSchemes {
            if let url = URL(string: scheme) {
                if application.canOpenURL(url) {
                    return true
                }
            }
        }
        return false
    }
    
    /// Check #4: Check for symbolic links
    private static func checkJailbreakMethod4() -> Bool {
        let paths = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]
        
        for path in paths {
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: path)
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
    
    /// Check #5: Check for suspicious dylib loading
    private static func checkJailbreakMethod5() -> Bool {
        let suspiciousLibraries = [
            "SubstrateLoader.dylib",
            "SSLKillSwitch2.dylib",
            "SSLKillSwitch.dylib",
            "MobileSubstrate.dylib",
            "TweakInject.dylib",
            "CydiaSubstrate",
            "cynject",
            "CustomWidgetIcons",
            "PreferenceLoader",
            "RocketBootstrap",
            "WeeLoader",
            "/.file"
        ]
        
        for i in 0..<_dyld_image_count() {
            guard let imageName = _dyld_get_image_name(i) else {
                continue
            }
            
            let name = String(cString: imageName)
            for library in suspiciousLibraries {
                if name.lowercased().contains(library.lowercased()) {
                    return true
                }
            }
        }
        
        return false
    }
    
    /// Check #6: Check system environment variables
    private static func checkJailbreakMethod6() -> Bool {
        let environment = ProcessInfo.processInfo.environment
        let suspiciousVars = ["DYLD_INSERT_LIBRARIES", "_MSSafeMode"]
        
        for variable in suspiciousVars {
            if environment[variable] != nil {
                return true
            }
        }
        
        return false
    }
    
    /// Check #7: Check if /etc/fstab exists (should not on non-jailbroken devices)
    private static func checkJailbreakMethod7() -> Bool {
        let fstabPath = "/etc/fstab"
        
        do {
            let contents = try String(contentsOfFile: fstabPath, encoding: .utf8)
            // If we can read fstab, device might be jailbroken
            return !contents.isEmpty
        } catch {
            // Normal behavior - can't read fstab
            return false
        }
    }
    
    /// Check #8: Check for suspicious process behavior
    private static func checkJailbreakMethod8() -> Bool {
        // Check if we can stat() system directories that should be restricted
        let restrictedPaths = [
            "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/libexec/cydia",
            "/usr/bin/cycript",
            "/usr/local/bin/cycript",
            "/usr/lib/libcycript.dylib"
        ]
        
        for path in restrictedPaths {
            var stat_info = stat()
            if stat(path, &stat_info) == 0 {
                return true
            }
        }
        
        return false
    }
    
    // MARK: - Additional Checks
    
    /// Check if running in simulator
    @objc
    static func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
            return true
        #else
            return false
        #endif
    }
    
    /// Check for debugger attachment
    @objc
    static func isDebuggerAttached() -> Bool {
        var debuggerIsAttached = false

        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info: kinfo_proc = kinfo_proc()
        var info_size = MemoryLayout<kinfo_proc>.size

        let success = name.withUnsafeMutableBytes { (nameBytePtr: UnsafeMutableRawBufferPointer) -> Bool in
            guard let nameBytesBlindMemory = nameBytePtr.bindMemory(to: Int32.self).baseAddress else { return false }
            return -1 != sysctl(nameBytesBlindMemory, 4, &info, &info_size, nil, 0)
        }

        if !success {
            debuggerIsAttached = false
        }

        if !debuggerIsAttached && (info.kp_proc.p_flag & P_TRACED) != 0 {
            debuggerIsAttached = true
        }

        return debuggerIsAttached
    }
}
