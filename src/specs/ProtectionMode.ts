/**
 * Action taken by the {@linkcode SecurityWatchdog} when it observes a
 * compromised device during a periodic check.
 *
 * `LOG_ONLY` is safe for automated tests and routine use. `THROW_EXCEPTION`
 * and `TERMINATE` are destructive: they disrupt or end the host application
 * and must never be exercised in automated tests or routine manual validation.
 *
 * @see {@linkcode SecurityWatchdogOptions.protectionMode}
 * @see {@linkcode SecurityWatchdog.start}
 */
export type ProtectionMode = 'LOG_ONLY' | 'THROW_EXCEPTION' | 'TERMINATE';
