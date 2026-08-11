# Keep all native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the Nitro edge HybridObjects and generated specs. JNI instantiates
# these by their fully qualified name (see nitrogen/generated/android/
# RootJailDetectOnLoad.cpp), so obfuscation or repackaging breaks the bridge.
-keep class com.margelo.nitro.rootjaildetect.** { *; }

# Do NOT use -repackageclasses here: it renames the Kotlin
# HybridPackageManagerProbe and the generated Hybrid*Spec classes, which are
# looked up by name through JNI at runtime.
