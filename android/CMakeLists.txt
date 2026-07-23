cmake_minimum_required(VERSION 3.22.1)
project(RootJailDetect LANGUAGES C CXX)

# Standard C++ settings for React Native native libraries.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Must match `androidCxxLibName` in nitro.json so the generated
# RootJailDetect+autolinking.cmake (which targets this same library) can add
# its generated sources and link dependencies to it.
add_library(
  RootJailDetect
  SHARED
  # Shared, hand-written C++ HybridObject implementations. The generated
  # spec glue and OnLoad registration are pulled in by the autolinking
  # cmake file included below.
  ../../cpp/HybridRootJailDetect.cpp
  ../../cpp/HybridSecurityWatchdog.cpp
)

# Hand-written implementations live in cpp/ at the package root.
target_include_directories(
  RootJailDetect
  PRIVATE
  ../../cpp
)

# Pull in generated spec sources, include paths, folly flags, and the
# NitroModules + React Native prefab dependencies.
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/RootJailDetect+autolinking.cmake)
