import Foundation
import React

/**
 * RootJailDetect
 *
 * React Native native module that exposes iOS device
 * security checks (jailbreak detection, simulator detection,
 * and debugger detection) to the JavaScript layer.
 *
 * This class acts as a bridge between React Native
 * and native security utilities.
 */
@objc(RootJailDetect)
class RootJailDetect: NSObject {

    /**
     * Indicates whether the module must be initialized
     * on the main (UI) thread.
     *
     * Returning false allows React Native to initialize
     * this module on a background thread, improving performance.
     *
     * @return false to allow background initialization
     */
    @objc static func requiresMainQueueSetup() -> Bool {
        return false
    }

    /**
     * Checks whether the current device is compromised (jailbroken).
     *
     * Internally invokes native jailbreak-detection heuristics
     * and returns the result asynchronously via a Promise.
     *
     * @param resolve Promise resolver that receives true if the
     *                device is jailbroken, false otherwise
     * @param reject  Promise rejecter used when an error occurs
     */
    @objc func isDeviceCompromised(
        _ resolve: RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        let isJailbroken = JailbreakDetection.isDeviceJailbroken()
        resolve(isJailbroken)
    }

    /**
     * Determines whether the application is running
     * inside an iOS simulator environment.
     *
     * Simulators are often used for testing and may not
     * reflect real-device security conditions.
     *
     * @param resolve Promise resolver that receives true if
     *                running in simulator, false otherwise
     * @param reject  Promise rejecter used when an error occurs
     */
    @objc func isSimulator(
        _ resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        let isSim = JailbreakDetection.isSimulator()
        resolve(isSim)
    }

    /**
     * Checks whether a debugger is currently attached
     * to the running application process.
     *
     * This helps detect runtime inspection,
     * reverse engineering, and debugging attempts.
     *
     * @param resolve Promise resolver that receives true if
     *                a debugger is attached, false otherwise
     * @param reject  Promise rejecter used when an error occurs
     */
    @objc func isDebuggerAttached(
        _ resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        let isAttached = JailbreakDetection.isDebuggerAttached()
        resolve(isAttached)
    }
}
