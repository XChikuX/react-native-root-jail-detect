package rootjaildetect.example

import android.app.Application
import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.defaults.DefaultReactHost.getDefaultReactHost
import com.margelo.nitro.rootjaildetect.RootJailDetectOnLoad

class MainApplication : Application(), ReactApplication {

  override val reactHost: ReactHost by lazy {
    getDefaultReactHost(
      context = applicationContext,
      packageList =
        PackageList(this).packages.apply {
          // Packages that cannot be autolinked yet can be added manually here, for example:
          // add(MyReactNativePackage())
        },
    )
  }

  override fun onCreate() {
    super.onCreate()
    // Nitro Modules must be loaded before React Native bootstraps so the
    // HybridObjectRegistry contains RootJailDetect/SecurityWatchdog/UrlSchemeProbe
    // by the time JS calls NitroModules.createHybridObject(...). The generated
    // Kotlin shim loads the C++ library and registers all native HybridObjects.
    RootJailDetectOnLoad.initializeNative()
    loadReactNative(this)
  }
}
