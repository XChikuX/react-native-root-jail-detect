# Expo

This package contains native code. It cannot run in Expo Go. Use `expo prebuild`
with a custom development client or EAS Build.

```sh
bun add @psync/anti-jailbreak react-native-nitro-modules
npx expo prebuild
npx expo run:android
```

Add the plugin to app configuration when your project does not automatically
resolve package plugins:

```json
{ "expo": { "plugins": ["@psync/anti-jailbreak"] } }
```

The plugin adds narrowly scoped Android package visibility for known
root-management packages. It does not request `QUERY_ALL_PACKAGES`. Native
checks require the New Architecture and an Android/iOS binary rebuilt after
installation. Configure Play Integrity in the host app and verify all tokens on
