/**
 * undef-platform-macros.h
 *
 * Force-included before every translation unit in the `RootJailDetect` CMake
 * target (see `target_compile_options(... -include ...)` in CMakeLists.txt).
 *
 * The Android NDK toolchain injects `-DANDROID` on the compiler command line.
 * The Nitrogen-generated `Platform.hpp` declares `enum class Platform { ANDROID,
 * IOS }`, so the `ANDROID` macro collides with the `ANDROID` enumerator
 * (`Platform::ANDROID` expands to `Platform::1`). Undefine it so the generated
 * enum compiles.
 *
 * Platform detection throughout this library uses `__ANDROID__` (with
 * underscores), never the bare `ANDROID` macro, so undefining it is safe.
 */
#undef ANDROID
