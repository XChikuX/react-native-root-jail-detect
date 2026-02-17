package com.rootjaildetect

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.Promise 

class RootJailDetectModule(reactContext: ReactApplicationContext) :
  NativeRootJailDetectSpec(reactContext) {
  
  private val rootDetection = RootDetection(reactContext)

    /**
     * Exposed method to check if device is compromised (rooted)
     * Returns a Promise that resolves to boolean
     */
    override fun isDeviceCompromised(promise: Promise) {
        try {
            val isRooted = rootDetection.isDeviceRooted()
            promise.resolve(isRooted)
        } catch (e: Exception) {
            promise.reject("ERROR", "Failed to check device security: ${e.message}", e)
        }
    }

    /**
     * Optional: Check if running in emulator
     */
    override fun isEmulator(promise: Promise) {
        try {
            val isEmu = rootDetection.isEmulator()
            promise.resolve(isEmu)
        } catch (e: Exception) {
            promise.reject("ERROR", "Failed to check emulator status: ${e.message}", e)
        }
    }

    /**
     * Optional: Check if debugger is attached
     */
    override fun isDebuggerAttached(promise: Promise) {
        try {
            val isDebuggerAttached = rootDetection.isDebuggerAttached()
            promise.resolve(isDebuggerAttached)
        } catch (e: Exception) {
            promise.reject("ERROR", "Failed to check debugger status: ${e.message}", e)
        }
    }

  companion object {
    const val NAME = NativeRootJailDetectSpec.NAME
  }
}
