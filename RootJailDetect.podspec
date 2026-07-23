require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "RootJailDetect"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]
  s.source       = { :git => "https://github.com/rushikeshpandit/react-native-root-jail-detect.git", :tag => "#{s.version}" }

  s.platforms    = { :ios => min_ios_version_supported }

  # Hand-written iOS edge HybridObjects (Swift). Currently empty for the PR 1
  # Nitro skeleton; PR 3 adds sandbox, dyld, URL-scheme, and debugger checks as
  # Swift edge HybridObjects that the shared C++ core calls through their
  # generated spec API. Shared C++ implementations live in cpp/ and are also
  # compiled into this pod so iOS and Android share one detection core.
  s.source_files = [
    "ios/**/*.{h,m,mm,swift}",
    "cpp/**/*.{hpp,cpp}",
  ]

  # Pull in Nitrogen-generated specs, bridges, C++20 / Swift-C++ interop config,
  # and the `NitroModules` dependency. Must be loaded after `s.source_files`
  # is configured because it appends to that list.
  load 'nitrogen/generated/ios/RootJailDetect+autolinking.rb'
  add_nitrogen_files(s)
end
