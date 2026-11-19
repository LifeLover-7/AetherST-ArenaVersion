package io.github.immaghzbad.aetherst.shared.ui.components

import androidx.compose.runtime.Composable

/**
 * Platform-aware Proton VPN WebView component.
 * On Android: Renders an embedded full-screen WebView intercepting blob: download URLs.
 * On Desktop: Launches system browser and provides clipboard / paste auto-detector.
 */
@Composable
expect fun ProtonVpnWebView(
    url: String = "https://account.protonvpn.com/downloads",
    onConfigExtracted: (String) -> Unit,
    onClose: () -> Unit
)

/**
 * Platform-aware Firefox Account (FxA) In-App WebView component.
 * Opens the official Mozilla Accounts sign-in flow inside an embedded WebView (supporting
 * 2FA, CAPTCHA, and 6-digit email verification codes) and automatically intercepts the
 * authenticated FxA sessionToken / OAuth token.
 */
@Composable
expect fun FirefoxVpnWebView(
    url: String = "https://accounts.firefox.com/signin",
    onTokenExtracted: (email: String, sessionOrOAuthToken: String) -> Unit,
    onClose: () -> Unit
)
