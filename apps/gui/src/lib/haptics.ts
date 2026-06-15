/**
 * Light haptic tap feedback.
 *
 * Uses the Web Vibration API, which the Android WebView honours (needs the
 * `VIBRATE` manifest permission). On desktop `navigator.vibrate` is absent, so
 * this is a no-op. Keep durations tiny — a short tick that mirrors the system
 * button feel, not a buzz.
 */
export function haptic(ms = 8): void {
  try {
    const nav = navigator as Navigator & { vibrate?: (pattern: number) => boolean };
    nav.vibrate?.(ms);
  } catch {
    /* unsupported / blocked — ignore */
  }
}
