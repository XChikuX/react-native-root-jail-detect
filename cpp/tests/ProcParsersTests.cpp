#include "ProcParsers.hpp"
#include "SignalCatalog.hpp"

#include <cassert>
#include <string_view>

using namespace margelo::nitro::rootjaildetect;

int main() {
  constexpr std::string_view maps =
    "1000-2000 r-xp 00000000 00:00 0\n"
    "3000-4000 r-xp 00000000 00:00 0\n"
    "5000-6000 r--p 00000000 00:00 0 /system/lib64/libzygisk.so\n";
  const auto anonymous = parseMapsForAnonymousInjection(maps);
  assert(anonymous.size() == 1);
  assert(anonymous.front().signalId == SignalId::ANDROID_MAPS_ANON_INJECTION);
  assert(scanMapsForHooks(maps).front().signalId == SignalId::ANDROID_MAPS_ZYGISK);

  // Named anonymous regions (ART JIT, libc malloc) are normal on stock ART
  // and must NOT trip the anon-injection heuristic.
  constexpr std::string_view stockArtMaps =
    "1000-2000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]\n"
    "3000-4000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]\n";
  assert(parseMapsForAnonymousInjection(stockArtMaps).empty());

  constexpr std::string_view mounts =
    "1 1 0:1 / /product rw,relatime - overlay overlay\n"
    "2 1 0:2 / /debug_ramdisk rw,relatime - overlay overlay\n"
    "3 1 0:3 / /sbin rw,relatime - magisk magisk\n";
  assert(scanMountsForMagiskChain(mounts).size() == 1);

  constexpr std::string_view moduleProps =
    "id=zygisk-assistant\n"
    "name=Zygisk Assistant\n"
    "version=1.0\n"
    "author=fixture\n\n"
    "id=tricky_store\n"
    "name=Tricky Store\n";
  const auto modules = parseMagiskModulesProps(moduleProps);
  assert(modules.size() == 2);
  assert(modules.front().id == "zygisk-assistant");
  assert(modules.back().name == "Tricky Store");

  const auto inconsistencies = parseSystemAttributeInconsistencies(SystemAttributes{
    "0",
    "userdebug",
    "1",
    "green",
    "unlocked",
    "device/user/release-keys",
    "test-keys",
    "",
    "1",
    "",
    "",
  });
  assert(inconsistencies.size() == 4);

  const auto anonSpec = lookupSignal(SignalId::ANDROID_MAPS_ANON_INJECTION);
  assert(anonSpec.has_value());
  assert(anonSpec->score == 10.0);

  return 0;
}
