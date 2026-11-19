package io.github.immaghzbad.aetherst.shared.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Login
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.immaghzbad.aetherst.shared.i18n.LocalAppStrings
import io.github.immaghzbad.aetherst.shared.i18n.StringsFa
import io.github.immaghzbad.aetherst.shared.net.FirefoxVpnExitTunnel
import io.github.immaghzbad.aetherst.shared.net.FxaVerificationRequiredException
import io.github.immaghzbad.aetherst.shared.ui.theme.AppPalette
import io.github.immaghzbad.aetherst.shared.util.CountryNames
import kotlinx.coroutines.launch

@Composable
fun FirefoxVpnDialog(
    initialAccount: String,
    initialToken: String,
    initialCountry: String,
    initialPort: Int,
    onSave: (account: String, token: String, country: String, port: Int) -> Unit,
    onDismiss: () -> Unit
) {
    val strings = LocalAppStrings.current
    val isFa = strings is StringsFa
    val scope = rememberCoroutineScope()

    var account by remember { mutableStateOf(initialAccount) }
    var password by remember { mutableStateOf("") }
    var token by remember { mutableStateOf(initialToken) }
    var country by remember { mutableStateOf(if (initialCountry.isNotBlank()) initialCountry.trim() else "de") }
    var port by remember { mutableStateOf(if (initialPort > 0) initialPort.toString() else "10810") }

    var showFirefoxWebView by remember { mutableStateOf(false) }
    var pendingSessionToken by remember { mutableStateOf<String?>(null) }
    var emailVerifyCode by remember { mutableStateOf("") }

    var isSigningIn by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var isErrorStatus by remember { mutableStateOf(false) }

    var serverOptions by remember { mutableStateOf(FirefoxVpnExitTunnel.BUILTIN_SERVER_OPTIONS) }
    var isFetchingServers by remember { mutableStateOf(false) }

    if (showFirefoxWebView) {
        FirefoxVpnWebView(
            url = "https://accounts.firefox.com/signin",
            onTokenExtracted = { extractedEmail, rawSessionOrOAuth ->
                showFirefoxWebView = false
                if (extractedEmail.isNotBlank()) {
                    account = extractedEmail
                }
                isSigningIn = true
                isErrorStatus = false
                statusMessage = "در حال تبدیل نشست فایرفاکس به توکن ProxyPass..."
                scope.launch {
                    val result = FirefoxVpnExitTunnel.exchangeSessionOrOAuthForProxyPass(
                        rawTokenOrJson = rawSessionOrOAuth
                    )
                    isSigningIn = false
                    result.onSuccess { fetchedToken ->
                        token = fetchedToken
                        pendingSessionToken = null
                        isErrorStatus = false
                        statusMessage = "✅ ورود از طریق WebView انجام شد و نشست فایرفاکس ذخیره گردید! سرور مورد نظر را از بخش پایین انتخاب و روی Save بزنید."
                    }.onFailure { err ->
                        isErrorStatus = true
                        statusMessage = "خطا در دریافت توکن از نشست WebView: ${err.message}"
                    }
                }
            },
            onClose = { showFirefoxWebView = false }
        )
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth(0.92f)
                .clip(RoundedCornerShape(24.dp))
                .border(1.dp, Color(0xFF262C3D), RoundedCornerShape(24.dp)),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0F1117)),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                // Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0xFFFF944D)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.VpnKey, null, tint = Color.White, modifier = Modifier.size(20.dp))
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = strings.EXIT_NODE_FIREFOX_DIALOG_TITLE,
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp
                        )
                        Text(
                            text = strings.EXIT_NODE_FIREFOX_VPN_DESC,
                            color = AppPalette.textSecondary,
                            fontSize = 11.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Section 1: In-App WebView Sign-In (Recommended) + Direct Sign-In
                Text(
                    text = "1. ورود به حساب فایرفاکس (دریافت خودکار توکن ProxyPass)",
                    color = Color(0xFFFF944D),
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 12.sp
                )
                Spacer(modifier = Modifier.height(8.dp))

                Button(
                    onClick = { showFirefoxWebView = true },
                    enabled = !isSigningIn,
                    modifier = Modifier.fillMaxWidth().height(46.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF7139))
                ) {
                    Icon(Icons.Default.OpenInBrowser, null, modifier = Modifier.size(18.dp), tint = Color.White)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "ورود با پنجره درون‌برنامه‌ای فایرفاکس (WebView)",
                        fontSize = 12.5.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                IosInputField(
                    label = strings.EXIT_NODE_FIREFOX_ACCOUNT,
                    value = account,
                    onValueChange = { account = it },
                    placeholder = "firefox-user@example.com",
                    testTag = "input_firefox_account",
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(8.dp))

                IosInputField(
                    label = "Firefox Account Password (ورود مستقیم)",
                    value = password,
                    onValueChange = { password = it },
                    placeholder = "Enter password (or use WebView button above)",
                    testTag = "input_firefox_password",
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(10.dp))

                Button(
                    onClick = {
                        if (isSigningIn) return@Button
                        isSigningIn = true
                        statusMessage = "Signing in to Firefox Accounts & fetching ProxyPass..."
                        isErrorStatus = false
                        scope.launch {
                            val result = FirefoxVpnExitTunnel.signInWithFirefoxAccount(
                                email = account,
                                password = password
                            )
                            isSigningIn = false
                            result.onSuccess { fetchedToken ->
                                token = fetchedToken
                                password = ""
                                pendingSessionToken = null
                                isErrorStatus = false
                                statusMessage = "✅ ProxyPass token fetched successfully! Select your server below and tap Save."
                            }.onFailure { err ->
                                if (err is FxaVerificationRequiredException) {
                                    pendingSessionToken = err.sessionTokenHex
                                    isErrorStatus = false
                                    statusMessage = "📩 کد تایید ۶ رقمی ارسال‌شده به ایمیل را در کادر زیر وارد کنید:"
                                } else {
                                    isErrorStatus = true
                                    statusMessage = err.message ?: "Sign-in failed."
                                }
                            }
                        }
                    },
                    enabled = !isSigningIn && account.isNotBlank() && password.isNotBlank(),
                    modifier = Modifier.fillMaxWidth().height(42.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
                ) {
                    if (isSigningIn) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            color = Color.White,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Authenticating...", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    } else {
                        Icon(Icons.AutoMirrored.Filled.Login, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Direct Sign In with Email & Password", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }

                // 2-Step Email Verification Code Box (shown automatically when FxA requires OTP)
                AnimatedVisibility(visible = pendingSessionToken != null) {
                    Column(modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) {
                        IosInputField(
                            label = "کد تایید ایمیل فایرفاکس (6-Digit Verification Code)",
                            value = emailVerifyCode,
                            onValueChange = { emailVerifyCode = it },
                            placeholder = "123456",
                            keyboardType = KeyboardType.Number,
                            testTag = "input_firefox_otp",
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                val sess = pendingSessionToken ?: return@Button
                                if (isSigningIn) return@Button
                                isSigningIn = true
                                isErrorStatus = false
                                statusMessage = "Verifying code & fetching ProxyPass token..."
                                scope.launch {
                                    val res = FirefoxVpnExitTunnel.verifySessionEmailCodeAndFetchToken(
                                        sessionTokenHex = sess,
                                        code = emailVerifyCode
                                    )
                                    isSigningIn = false
                                    res.onSuccess { fetchedToken ->
                                        token = fetchedToken
                                        pendingSessionToken = null
                                        emailVerifyCode = ""
                                        password = ""
                                        isErrorStatus = false
                                        statusMessage = "✅ کد تایید شد و توکن ProxyPass دریافت گردید!"
                                    }.onFailure { err ->
                                        isErrorStatus = true
                                        statusMessage = err.message ?: "Code verification failed."
                                    }
                                }
                            },
                            enabled = !isSigningIn && emailVerifyCode.trim().length >= 4,
                            modifier = Modifier.fillMaxWidth().height(40.dp),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981))
                        ) {
                            Icon(Icons.Default.CheckCircle, null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("تایید کد و دریافت توکن (Verify Code)", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                val currentMsg = statusMessage
                if (currentMsg != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = currentMsg,
                        color = if (isErrorStatus) Color(0xFFF87171) else Color(0xFF4ADE80),
                        fontSize = 11.sp,
                        lineHeight = 15.sp
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))
                HorizontalDivider(color = Color(0xFF1E293B), thickness = 1.dp)
                Spacer(modifier = Modifier.height(14.dp))

                // Section 2: Server & Country Picker + Token Settings
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = if (isFa) "2. انتخاب سرور و کشور خروجی فایرفاکس" else "2. Select Firefox VPN Exit Server",
                        color = Color(0xFFFF944D),
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.sp
                    )
                    TextButton(
                        onClick = {
                            if (isFetchingServers) return@TextButton
                            isFetchingServers = true
                            scope.launch {
                                val fetched = FirefoxVpnExitTunnel.fetchLiveServerOptions()
                                serverOptions = fetched
                                isFetchingServers = false
                                val liveCount = (fetched.size - FirefoxVpnExitTunnel.BUILTIN_SERVER_OPTIONS.size).coerceAtLeast(0)
                                statusMessage = if (liveCount > 0) {
                                    "✅ لیست سرورهای زنده موزیلا بروزرسانی شد ($liveCount سرور اختصاصی اضافه شد)."
                                } else {
                                    "✅ لیست ۲۵ کشور رسمی موزیلا آماده انتخاب است."
                                }
                                isErrorStatus = false
                            }
                        },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = null,
                            tint = Color(0xFF38BDF8),
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = if (isFetchingServers) (if (isFa) "در حال دریافت..." else "Fetching...") else (if (isFa) "دریافت سرورهای زنده" else "Fetch Live Servers"),
                            color = Color(0xFF38BDF8),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                // Quick-Select Popular Country Chips with Flags
                val quickCountries = listOf(
                    "de" to (if (isFa) "آلمان" else "Germany"),
                    "nl" to (if (isFa) "هلند" else "Netherlands"),
                    "us" to (if (isFa) "آمریکا" else "USA"),
                    "gb" to (if (isFa) "انگلیس" else "UK"),
                    "fr" to (if (isFa) "فرانسه" else "France"),
                    "ch" to (if (isFa) "سوئیس" else "Swiss"),
                    "se" to (if (isFa) "سوئد" else "Sweden"),
                    "fi" to (if (isFa) "فنلاند" else "Finland"),
                    "ca" to (if (isFa) "کانادا" else "Canada"),
                    "at" to (if (isFa) "اتریش" else "Austria"),
                    "jp" to (if (isFa) "ژاپن" else "Japan"),
                    "sg" to (if (isFa) "سنگاپور" else "Singapore")
                )
                val activeCc = FirefoxVpnExitTunnel.extractCountryCode(country).lowercase()

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    quickCountries.forEach { (cc, label) ->
                        val isSelected = country.trim().lowercase() == cc || (activeCc == cc && !country.contains("|"))
                        Row(
                            modifier = Modifier
                                .clip(RoundedCornerShape(10.dp))
                                .background(if (isSelected) Color(0xFFFF944D).copy(alpha = 0.22f) else Color(0xFF161922))
                                .border(
                                    width = 1.dp,
                                    color = if (isSelected) Color(0xFFFF944D) else Color(0xFF262C3D),
                                    shape = RoundedCornerShape(10.dp)
                                )
                                .clickable { country = cc }
                                .padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            CountryFlag(countryCode = cc.uppercase(), size = 16.dp)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "$label (${cc.uppercase()})",
                                color = if (isSelected) Color.White else Color(0xFFCBD5E1),
                                fontSize = 11.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                // Full Server / Country Dropdown Picker
                val pickerLabels = remember(serverOptions, isFa) {
                    serverOptions.map { opt ->
                        if (isFa) "${opt.titleFa} [${opt.countryCode}]" else "${opt.titleEn} [${opt.countryCode}]"
                    }
                }
                val selectedOption = serverOptions.firstOrNull { it.id.equals(country.trim(), ignoreCase = true) }
                    ?: serverOptions.firstOrNull { it.countryCode.equals(activeCc, ignoreCase = true) }
                val currentDisplayLabel = when {
                    selectedOption != null -> if (isFa) selectedOption.titleFa else selectedOption.titleEn
                    else -> CountryNames.label(activeCc.uppercase())
                }

                IosGroupCard {
                    IosPickerRow(
                        icon = Icons.Default.Public,
                        iconBg = Color(0xFFFF944D),
                        title = if (isFa) "سرور / کشور خروجی" else "Exit Server / Country",
                        value = currentDisplayLabel,
                        options = pickerLabels,
                        onOptionSelected = { idx ->
                            serverOptions.getOrNull(idx)?.let { picked ->
                                country = picked.id
                            }
                        }
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                IosInputField(
                    label = if (isFa) "کد کشور یا آدرس سرور اختصاصی (Country Code / Custom Host)" else strings.EXIT_NODE_FIREFOX_COUNTRY,
                    value = country,
                    onValueChange = { country = it },
                    placeholder = "de, nl, us, gb, fr, ch, se, ca (or cc|host:port)",
                    testTag = "input_firefox_country",
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(10.dp))

                IosInputField(
                    label = strings.EXIT_NODE_FIREFOX_TOKEN,
                    value = token,
                    onValueChange = { token = it },
                    placeholder = "Guardian-Proxy-Pass / Session token (auto-filled)",
                    testTag = "input_firefox_token",
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(10.dp))

                IosInputField(
                    label = strings.EXIT_NODE_FIREFOX_PORT,
                    value = port,
                    onValueChange = { port = it },
                    placeholder = "10810",
                    keyboardType = KeyboardType.Number,
                    testTag = "input_firefox_port",
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(20.dp))

                // Actions: Cancel & Save
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    OutlinedButton(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f).height(46.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = AppPalette.textSecondary)
                    ) {
                        Text(strings.CANCEL, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    }

                    Button(
                        onClick = {
                            val parsedPort = port.toIntOrNull()?.takeIf { it in 1024..65535 } ?: 10810
                            onSave(account.trim(), token.trim(), country.trim().lowercase().ifBlank { "de" }, parsedPort)
                            onDismiss()
                        },
                        modifier = Modifier.weight(1f).height(46.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF944D))
                    ) {
                        Text(strings.SAVE, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    }
                }
            }
        }
    }
}
