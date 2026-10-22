# Distribute the macOS app with Developer ID, not the Mac App Store

Lock Mode must intercept system shortcuts (Cmd+Tab, Cmd+Space, Mission Control) before macOS handles them, which needs an active event tap and the Accessibility permission. Sandboxed Mac App Store apps cannot get that, so we ship a notarized Developer ID build outside the store. The future iPadOS app goes through the App Store and uses the platform's own hardware-keyboard APIs instead.
