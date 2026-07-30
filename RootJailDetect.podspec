require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "RootJailDetect"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]
  s.source       = { :git => "https://github.com/psync/anti-jailbreak.git", :tag => "#{s.version}" }

  s.platforms    = { :ios => min_ios_version_supported }

  # Shared C++ implementations include conservative iOS sandbox, dyld, and
  # debugger probes alongside the Android detection core.
  #
  # `cpp/cpp-adapter.cpp` is the Android-only `JNI_OnLoad` entry point (it
  # pulls in `<jni.h>`/`<fbjni/fbjni.h>`, which don't exist on iOS). iOS
  # registration is handled by the Nitrogen-generated `RootJailDetectAutolinking.mm`,
  # so exclude it from the iOS build.
  s.source_files = [
    "ios/**/*.{h,m,mm,swift}",
    "cpp/**/*.{hpp,cpp}",
  ]
  s.exclude_files = [
    "cpp/cpp-adapter.cpp",
  ]

  # Pull in Nitrogen-generated specs, bridges, C++20 / Swift-C++ interop config,
  # and the `NitroModules` dependency. Must be loaded after `s.source_files`
  # is configured because it appends to that list.
  load 'nitrogen/generated/ios/RootJailDetect+autolinking.rb'
  add_nitrogen_files(s)
end
