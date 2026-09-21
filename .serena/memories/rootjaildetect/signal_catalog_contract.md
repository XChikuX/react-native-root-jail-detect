# SignalCatalog contract (PUBLIC)

## Signal ids are public contract

Once an id appears in `cpp/SignalCatalog.hpp` (via the `SignalId::*` constants), it cannot be:

- **Renamed** — call sites use the raw string id to reason about what fired. Renaming is a breaking change.
- **Reused for a different meaning** — even if weight/severity tuning is allowed.
- **Removed silently** — remove the id from `SignalCatalog.hpp` AND `src/wrappers.ts` `signalReasons` map AND any `*.test.tsx`/Jest catalog expectation at the same time, with a CHANGELOG note.

New ids added over the project lifetime live as additions, never mutations of existing ids.

## Signal catalog is a flat `if`-chain, not a map

`cpp/SignalCatalog.cpp` `lookupSignal()` uses a flat `if (id == SignalId::X) return ...; if (id == SignalId::Y) return ...;` pattern. Reasons:

- Avoids static-initialization-order fiasco with a `std::unordered_map`.
- Reads top-to-bottom exactly like the documentation.
- Adding a signal = one new `if` line; weights mirror README's Signal Catalog section — keep them in sync.

## Weights mirror README's Signal Catalog table

If you change a weight in `lookupSignal()`, the README table needs the same change. **No script enforces this** — review the diff.

## Weight floors and rationale

- **High-severity** (≥25): `ANDROID_MOUNT_MAGISK` 35, `ANDROID_MAPS_*` 30, `ANDROID_SELINUX_PERMISSIVE` 25, etc.
- **Medium-severity**: `ANDROID_EMULATOR` 20, `ANDROID_BOOTLOADER_UNLOCKED` 20, etc.
- **Low-severity**: debug build signals at 5 (high FP on legitimate dev builds, hidden by Shamiko).
- Debugger signals at 0 (`ANDROID_DEBUGGER_TRACERPID`) — informational only; folded into `CompromiseAssessment.debuggerDetected`, NOT into `.compromised` unless `treatDebuggerAsCompromise` is true.

## `unavailable: true` signals — domain semantics

`DetectionSignal.unavailable = true` is checked in `Scoring.hpp` `aggregateSignals()` — never counts toward the score, never raises confidence. Reserved for checks that could not run because `timeoutMs` expired or a probe failed. **Strict semantics**: `unavailable` is "no data", never "no compromise" and never "compromised". Documented in `getDetectionReasons()` test cases that filter them out.

## Parking signals (no active probe, kept for forward compat)

- `ios.sideload.trollstore` — low 5, reliability 0.35 (parked; see CLAUDE.md iOS detection policy)
- `ios.jailbreak.dopamine`, `ios.jailbreak.palera1n` — also parked

Parked ids stay in `lookupSignal()` (so callers don't crash on lookups), keep their weight/severity locked at hypothesis values, and the v0.13.0 iOS plan tells reviewers to never claim coverage they don't have. Re-arming requires a verified observable AND a clean-corpus fixture pinning the FP floor.

## Per-id reliability + Scoring rules

`Scoring.hpp` `aggregateSignals()`:

- Per-id dedup (first occurrence wins, later ones dropped — see `ScoringTests.cpp`)
- Summed, clamped to `[0, 100]`
- Defensive floor at 0 (negative weights can never underflow)
- Confidence ladder: EMPTY→LOW, single-LOW→LOW, single-MEDIUM→MEDIUM, two-MEDIUM→HIGH (independent corroboration), single-HIGH→MEDIUM, two-HIGH→HIGH, two-HIGH across two categories with score≥80→EXTREME