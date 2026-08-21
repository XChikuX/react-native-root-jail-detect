# Consumer ProGuard/R8 rules for @psync/anti-jailbreak.
#
# These rules are bundled into the published AAR and applied automatically
# during the consuming app's R8/ProGuard pass. The JNI bridge instantiates
# the Kotlin HybridObjects and generated specs by fully-qualified name, so
# obfuscation or repackaging breaks native registration.

# Keep all native methods.
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the Nitro edge HybridObjects and generated specs.
-keep class com.margelo.nitro.rootjaildetect.** { *; }

# Do NOT repackage classes here: it would rename the Kotlin probe and the
# generated Hybrid*Spec classes that JNI looks up at runtime.
