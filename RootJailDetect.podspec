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
