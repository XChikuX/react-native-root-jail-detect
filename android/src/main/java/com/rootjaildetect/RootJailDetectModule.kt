package com.rootjaildetect

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext

/**
 * RootJailDetectModule
 *
 * React Native native module that exposes device security checks
 * (root detection, emulator detection, and debugger detection)
 * to the JavaScript layer.
 *
 * This module acts as a bridge between React Native and
 * native Android security APIs.
 */
class RootJailDetectModule(reactContext: ReactApplicationContext) :
    NativeRootJailDetectSpec(reactContext) {

    /**
     * Internal instance of RootDetection responsible for
     * performing low-level security checks.
     */
    private val rootDetection = RootDetection(reactContext)

    /**
     * Checks whether the current device is compromised (rooted).
     *
     * This method is exposed to the JavaScript layer and executes
     * multiple native root-detection heuristics internally.
     *
     * The result is returned asynchronously via a Promise.
     *
     * @param promise Promise that resolves to true if the device is rooted,
     *                or false if the device appears secure.
     */
    override fun isDeviceCompromised(promise: Promise) {
        try {
            val isRooted = rootDetection.isDeviceRooted()
            promise.resolve(isRooted)
        } catch (e: Exception) {
            promise.reject(
                "ERROR",
                "Failed to check device security: ${e.message}",
                e
            )
        }
    }

    /**
     * Determines whether the application is running inside
     * an Android emulator environment.
     *
     * Emulators are frequently rooted by default and may
     * represent higher security risk in production systems.
     *
     * The result is returned asynchronously via a Promise.
     *
     * @param promise Promise that resolves to true if running
     *                on an emulator, false otherwise.
     */
    override fun isEmulator(promise: Promise) {
        try {
            val isEmu = rootDetection.isEmulator()
            promise.resolve(isEmu)
        } catch (e: Exception) {
            promise.reject(
                "ERROR",
                "Failed to check emulator status: ${e.message}",
                e
            )
        }
    }

    /**
     * Checks whether a debugger is currently attached
     * to the running application process.
     *
     * This helps detect debugging, reverse engineering,
     * and runtime inspection attempts.
     *
     * The result is returned asynchronously via a Promise.
     *
     * @param promise Promise that resolves to true if a debugger
     *                is attached, false otherwise.
     */
    override fun isDebuggerAttached(promise: Promise) {
        try {
            val isDebuggerAttached = rootDetection.isDebuggerAttached()
            promise.resolve(isDebuggerAttached)
        } catch (e: Exception) {
            promise.reject(
                "ERROR",
                "Failed to check debugger status: ${e.message}",
                e
            )
        }
    }

    companion object {

        /**
         * Name of the native module exposed to React Native.
         *
         * This value is used internally by the React Native
         * bridge for module registration and lookup.
         */
        const val NAME = NativeRootJailDetectSpec.NAME
    }
}
