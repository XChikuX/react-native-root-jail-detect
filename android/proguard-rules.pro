# Keep all native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep device security module
-keep class com.rootjaildetect.** { *; }

# Obfuscate security checks
-repackageclasses 'o'
-allowaccessmodification