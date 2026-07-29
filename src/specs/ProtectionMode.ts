/**
 * Action taken by the {@linkcode SecurityWatchdog} when it observes a
 * compromised device during a periodic check.
 *
 * Important threading note: the watchdog runs each check on its own background
 * thread, which cannot synchronously throw into the JavaScript runtime. As a
 * result `THROW_EXCEPTION` fired from the watchdog is **demoted to a logged
 * warning** (it does not reject any Promise and does not surface in JS). It is
 * retained in the union for API completeness and for any future JS-side event
 * mechanism; today only `LOG_ONLY` and `TERMINATE` behave as named.
 *
 * To react to a compromised device from JavaScript, poll
 * {@linkcode RootJailDetect.checkDetailed} or call the legacy
 * `isDeviceCompromised()` wrapper on the JS thread and throw there.
 *
 * `LOG_ONLY` is safe for automated tests and routine use. `TERMINATE` is
 * destructive (it ends the host process) and must never be exercised in
 * automated tests or routine manual validation.
 *
 * @see {@linkcode SecurityWatchdogOptions.protectionMode}
 * @see {@linkcode SecurityWatchdog.start}
 */
export type ProtectionMode = 'LOG_ONLY' | 'THROW_EXCEPTION' | 'TERMINATE';
