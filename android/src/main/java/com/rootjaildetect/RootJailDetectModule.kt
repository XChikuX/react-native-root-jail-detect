package com.rootjaildetect

import com.facebook.react.bridge.ReactApplicationContext

class RootJailDetectModule(reactContext: ReactApplicationContext) :
  NativeRootJailDetectSpec(reactContext) {

  override fun multiply(a: Double, b: Double): Double {
    return a * b
  }

  companion object {
    const val NAME = NativeRootJailDetectSpec.NAME
  }
}
