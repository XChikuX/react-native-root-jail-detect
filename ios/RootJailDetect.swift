import Foundation
import React

@objc(RootJailDetect)
class RootJailDetect: NSObject {
    
    /// Expose the module to React Native
    @objc static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    /// Check if device is compromised (jailbroken)
    @objc func isDeviceCompromised(_ resolve:  RCTPromiseResolveBlock,
                                   reject: @escaping RCTPromiseRejectBlock) {
        let isJailbroken = JailbreakDetection.isDeviceJailbroken()
        resolve(isJailbroken)
    }
    
    /// Optional: Check if running in simulator
    @objc func isSimulator(_ resolve: @escaping RCTPromiseResolveBlock,
                          reject: @escaping RCTPromiseRejectBlock) {
        let isSim = JailbreakDetection.isSimulator()
        resolve(isSim)
    }
    
    /// Optional: Check if debugger is attached
    @objc func isDebuggerAttached(_ resolve: @escaping RCTPromiseResolveBlock,
                                 reject: @escaping RCTPromiseRejectBlock) {
        let isAttached = JailbreakDetection.isDebuggerAttached()
        resolve(isAttached)
    }
}
