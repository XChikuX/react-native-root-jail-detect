# Published package contents (`package.json` files field)

`@psync/anti-jailbreak` ships to npm with these paths included:

```
src, lib, android, ios, cpp, nitro.json, nitrogen/generated,
app.plugin.js, react-native.config.js, *.podspec
```

Excluded from npm: `ios/build`, `android/build`, `android/gradle{,.bat,_w}`, `android/local.properties`, `__tests__`, `__fixtures__`, `__mocks__`, dotfiles.

**`nitrogen/generated/` is BOTH committed AND shipped.** Consumers must build without running nitrogen — that's the whole point. `.gitignore` has the corresponding negation; don't remove the commit step in `release-it` `after:bump` (which stages `example/ios/Podfile.lock`).

## `lib/` (build output)

Produced by `bob build` (`build` script). Has:

- `lib/module/index.js` — published ESM source for `main`.
- `lib/typescript/src/index.d.ts` — type declarations under `types`.

**Don't add logic to `lib/`** — only consumer-facing `src/` and rebuild.

## npm peerDependencies

- `react`, `react-native`, `react-native-nitro-modules>=0.35.10`, `@expo/config-plugins` (optional via `peerDependenciesMeta`).
- The Expo config plugin is optional — bare React Native apps with no `expo` dependency never load `app.plugin.js`. `app-plugin.test.ts` pins the lazy-require pattern so a future refactor that hoists `require('@expo/config-plugins')` to module scope would break CI.

## Publishing flow (`release-it`)

`bun run release` is the only sanctioned path. Two hooks:

- `before:bump`: preflight + Android bundleDebug (must pass before version bump)
- `after:bump`: pods refresh + Podfile.lock staged in release commit (ensures lockfile tracks the new released version, not the previous one)

Manual `npm publish` would skip the gates. Don't.

## Authorship / publish metadata

- Repository: `psync/anti-jailbreak` (current) vs fork (`XChikuX/react-native-root-jail-detect`) — both URLs in `package.json`.
- Author: Srikanth Gopalakrishnan `<oss@psync.club>` (current).
- License: MIT.
- `homepage: https://github.com/psync/anti-jailbreak#readme`