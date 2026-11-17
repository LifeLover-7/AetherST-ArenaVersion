package io.github.immaghzbad.aetherst.shared.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.immaghzbad.aetherst.shared.i18n.LocalAppStrings
import io.github.immaghzbad.aetherst.shared.model.ConnectionStatus
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import io.github.immaghzbad.aetherst.shared.net.WireGuardExitTunnel
import io.github.immaghzbad.aetherst.shared.platform.Bridge
import io.github.immaghzbad.aetherst.shared.ui.theme.AppPalette
import io.github.immaghzbad.aetherst.shared.util.WireGuardConfigParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun CustomWireGuardDialog(
    initialConfig: CustomWireGuardConfig,
    profiles: List<CustomWireGuardConfig> = emptyList(),
    autoSelect: Boolean = false,
    connectionStatus: ConnectionStatus = ConnectionStatus.STOPPED,
    onSave: (CustomWireGuardConfig) -> Unit = {},
    onSaveAll: ((CustomWireGuardConfig, List<CustomWireGuardConfig>, Boolean) -> Unit)? = null,
    onDismiss: () -> Unit,
    onSuccessToast: ((String) -> Unit)? = null
) {
    val strings = LocalAppStrings.current
    val clipboardManager = LocalClipboardManager.current
    val coroutineScope = rememberCoroutineScope()

    var profileList by remember {
        val initialList = if (profiles.isNotEmpty()) {
            profiles
        } else if (initialConfig.isValid()) {
            listOf(initialConfig)
        } else {
            emptyList()
        }
        mutableStateOf(initialList)
    }

    var activeConfig by remember {
        val selected = profileList.firstOrNull { it.endpoint == initialConfig.endpoint }
            ?: profileList.firstOrNull()
            ?: initialConfig
        mutableStateOf(selected)
    }

    var autoSelectState by remember { mutableStateOf(autoSelect) }
    var isProbingPing by remember { mutableStateOf(false) }

    var rawConfigText by remember { mutableStateOf(activeConfig.rawConfig) }
    var showProtonWebView by remember { mutableStateOf(false) }
    var showTunnelAdvisoryDialog by remember { mutableStateOf(false) }
    var showManualInput by remember { mutableStateOf(profileList.isEmpty()) }

    fun addOrUpdateProfile(newCfg: CustomWireGuardConfig) {
        if (!newCfg.isValid()) return
        val existingIndex = profileList.indexOfFirst { it.endpoint == newCfg.endpoint || (it.id.isNotBlank() && it.id == newCfg.id) }
        val updated = if (existingIndex >= 0) {
            profileList.toMutableList().apply { set(existingIndex, newCfg) }
        } else {
            profileList + newCfg
        }
        profileList = updated
        activeConfig = newCfg
        rawConfigText = newCfg.rawConfig
    }

    fun removeProfile(cfg: CustomWireGuardConfig) {
        val updated = profileList.filter { it.endpoint != cfg.endpoint && it.id != cfg.id }
        profileList = updated
        if (activeConfig.endpoint == cfg.endpoint) {
            activeConfig = updated.firstOrNull() ?: CustomWireGuardConfig()
            rawConfigText = activeConfig.rawConfig
        }
    }

    fun triggerPingProbe() {
        if (isProbingPing || profileList.isEmpty()) return
        isProbingPing = true
        coroutineScope.launch {
            val probed = withContext(Dispatchers.Default) {
                WireGuardExitTunnel.probeProfilesFast(profileList, timeoutMs = 1200)
            }
            profileList = probed
            val updatedActive = probed.firstOrNull { it.id == activeConfig.id || it.endpoint == activeConfig.endpoint }
            if (updatedActive != null) activeConfig = updatedActive
            isProbingPing = false
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.85f))
                .clickable(enabled = false) {},
            contentAlignment = Alignment.Center
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth(0.95f)
                    .fillMaxHeight(0.92f)
                    .clip(RoundedCornerShape(24.dp))
                    .background(Color(0xFF0F1117))
                    .border(1.dp, Color(0xFF262C3D), RoundedCornerShape(24.dp)),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F1117)),
                shape = RoundedCornerShape(24.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(20.dp)
                ) {
                    // Header
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(AppPalette.accentVariant),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.VpnKey, null, tint = Color.White, modifier = Modifier.size(20.dp))
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = strings.EXIT_NODE_WG_DIALOG_TITLE,
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 16.sp
                                )
                                Text(
                                    text = strings.EXIT_NODE_CUSTOM_WG_DESC,
                                    color = AppPalette.textSecondary,
                                    fontSize = 11.sp
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Scrollable content
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .verticalScroll(rememberScrollState())
                    ) {
                        // Auto-Select Switch Card
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(14.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = if (autoSelectState) Color(0xFF1E293B) else Color(0xFF141721)
                            ),
                            border = BorderStroke(1.dp, if (autoSelectState) AppPalette.accent else Color(0xFF262C3D))
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 14.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = strings.EXIT_NODE_WG_AUTO_SELECT,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White,
                                        fontSize = 13.sp
                                    )
                                    Text(
                                        text = strings.EXIT_NODE_WG_AUTO_SELECT_DESC,
                                        color = AppPalette.textSecondary,
                                        fontSize = 11.sp
                                    )
                                }
                                Switch(
                                    checked = autoSelectState,
                                    onCheckedChange = { autoSelectState = it },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = Color.White,
                                        checkedTrackColor = AppPalette.accent
                                    )
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Profiles Section Header & Actions
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "${strings.EXIT_NODE_WG_PROFILES} (${profileList.size})",
                                color = Color.White,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                if (profileList.isNotEmpty()) {
                                    TextButton(
                                        onClick = { triggerPingProbe() },
                                        enabled = !isProbingPing,
                                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Icon(Icons.Default.Speed, null, modifier = Modifier.size(14.dp), tint = AppPalette.accent)
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            text = if (isProbingPing) "..." else "تست پینگ",
                                            fontSize = 11.sp,
                                            color = AppPalette.accent,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                    }
                                }
                                TextButton(
                                    onClick = { showManualInput = !showManualInput },
                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Icon(
                                        if (showManualInput) Icons.Default.ExpandLess else Icons.Default.Add,
                                        null,
                                        modifier = Modifier.size(14.dp),
                                        tint = Color.White
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = strings.EXIT_NODE_WG_ADD_PROFILE,
                                        fontSize = 11.sp,
                                        color = Color.White,
                                        fontWeight = FontWeight.Medium
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        // Multi-Profile Card List
                        if (profileList.isNotEmpty()) {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                profileList.forEach { profile ->
                                    val isSelected = activeConfig.endpoint == profile.endpoint
                                    Card(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clip(RoundedCornerShape(12.dp))
                                            .clickable {
                                                activeConfig = profile
                                                rawConfigText = profile.rawConfig
                                            },
                                        shape = RoundedCornerShape(12.dp),
                                        colors = CardDefaults.cardColors(
                                            containerColor = if (isSelected) Color(0xFF1E2638) else Color(0xFF141721)
                                        ),
                                        border = BorderStroke(
                                            1.dp,
                                            if (isSelected) AppPalette.accent else Color(0xFF262C3D)
                                        )
                                    ) {
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(horizontal = 12.dp, vertical = 10.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.SpaceBetween
                                        ) {
                                            Row(
                                                verticalAlignment = Alignment.CenterVertically,
                                                modifier = Modifier.weight(1f)
                                            ) {
                                                Box(
                                                    modifier = Modifier
                                                        .size(18.dp)
                                                        .clip(CircleShape)
                                                        .background(if (isSelected) AppPalette.accent else Color(0xFF334155)),
                                                    contentAlignment = Alignment.Center
                                                ) {
                                                    if (isSelected) {
                                                        Icon(Icons.Default.Check, null, tint = Color.White, modifier = Modifier.size(12.dp))
                                                    }
                                                }
                                                Spacer(modifier = Modifier.width(10.dp))
                                                Column {
                                                    Text(
                                                        text = profile.name.ifBlank { "🌐 ${profile.endpoint}" },
                                                        color = Color.White,
                                                        fontSize = 13.sp,
                                                        fontWeight = FontWeight.Bold
                                                    )
                                                    Text(
                                                        text = profile.endpoint,
                                                        color = AppPalette.textSecondary,
                                                        fontSize = 10.sp,
                                                        fontFamily = FontFamily.Monospace
                                                    )
                                                }
                                            }

                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                // Ping Badge
                                                val ping = profile.lastPingMs
                                                val (pingColor, pingText) = when {
                                                    ping in 1..180 -> Color(0xFF10B981) to "${ping}ms"
                                                    ping in 181..320 -> Color(0xFFF59E0B) to "${ping}ms"
                                                    ping > 320 -> Color(0xFFEF4444) to "${ping}ms"
                                                    else -> Color(0xFF64748B) to "—"
                                                }
                                                Box(
                                                    modifier = Modifier
                                                        .clip(RoundedCornerShape(6.dp))
                                                        .background(pingColor.copy(alpha = 0.15f))
                                                        .border(0.5.dp, pingColor.copy(alpha = 0.4f), RoundedCornerShape(6.dp))
                                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                                ) {
                                                    Text(
                                                        text = pingText,
                                                        color = pingColor,
                                                        fontSize = 10.sp,
                                                        fontWeight = FontWeight.Bold
                                                    )
                                                }

                                                Spacer(modifier = Modifier.width(6.dp))
                                                IconButton(
                                                    onClick = { removeProfile(profile) },
                                                    modifier = Modifier.size(24.dp)
                                                ) {
                                                    Icon(
                                                        Icons.Default.Delete,
                                                        contentDescription = strings.EXIT_NODE_WG_DELETE,
                                                        tint = Color(0xFFEF4444).copy(alpha = 0.7f),
                                                        modifier = Modifier.size(16.dp)
                                                    )
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Spacer(modifier = Modifier.height(12.dp))
                        }

                        // Add / Manual Input Box (Collapsible)
                        if (showManualInput || profileList.isEmpty()) {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(14.dp),
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF141721)),
                                border = BorderStroke(1.dp, Color(0xFF262C3D))
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    // Proton Auto-Import Primary Action Banner
                                    Card(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clip(RoundedCornerShape(12.dp))
                                            .clickable {
                                                val isPrimaryConnected = connectionStatus == ConnectionStatus.RUNNING || connectionStatus == ConnectionStatus.TUN_ACTIVE
                                                if (!isPrimaryConnected) {
                                                    showTunnelAdvisoryDialog = true
                                                } else {
                                                    showProtonWebView = true
                                                }
                                            },
                                        colors = CardDefaults.cardColors(containerColor = Color(0xFF6D4AFF).copy(alpha = 0.18f)),
                                        border = BorderStroke(1.dp, Color(0xFF6D4AFF).copy(alpha = 0.5f))
                                    ) {
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(horizontal = 12.dp, vertical = 10.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.SpaceBetween
                                        ) {
                                            Row(
                                                verticalAlignment = Alignment.CenterVertically,
                                                modifier = Modifier.weight(1f)
                                            ) {
                                                Box(
                                                    modifier = Modifier
                                                        .size(30.dp)
                                                        .clip(RoundedCornerShape(8.dp))
                                                        .background(Color(0xFF6D4AFF)),
                                                    contentAlignment = Alignment.Center
                                                ) {
                                                    Icon(Icons.Default.Shield, null, tint = Color.White, modifier = Modifier.size(16.dp))
                                                }
                                                Spacer(modifier = Modifier.width(10.dp))
                                                Column {
                                                    Text(
                                                        text = strings.PROTON_IMPORT_BUTTON,
                                                        fontWeight = FontWeight.Bold,
                                                        color = Color.White,
                                                        fontSize = 12.sp
                                                    )
                                                    Text(
                                                        text = strings.PROTON_WEBVIEW_SUBTITLE,
                                                        color = AppPalette.textSecondary,
                                                        fontSize = 10.sp,
                                                        maxLines = 1
                                                    )
                                                }
                                            }
                                            Button(
                                                onClick = {
                                                    val isPrimaryConnected = connectionStatus == ConnectionStatus.RUNNING || connectionStatus == ConnectionStatus.TUN_ACTIVE
                                                    if (!isPrimaryConnected) {
                                                        showTunnelAdvisoryDialog = true
                                                    } else {
                                                        showProtonWebView = true
                                                    }
                                                },
                                                shape = RoundedCornerShape(8.dp),
                                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6D4AFF)),
                                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                            ) {
                                                Text("Proton", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                            }
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    // Secondary action buttons: Import .conf file & Paste from clipboard
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        OutlinedButton(
                                            onClick = {
                                                Bridge.pickFile?.invoke { fileContent ->
                                                    if (!fileContent.isNullOrBlank()) {
                                                        val parsed = WireGuardConfigParser.parse(fileContent)
                                                        if (parsed.isValid()) {
                                                            addOrUpdateProfile(parsed)
                                                        }
                                                    }
                                                }
                                            },
                                            modifier = Modifier.weight(1f),
                                            shape = RoundedCornerShape(10.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                                            border = ButtonDefaults.outlinedButtonBorder.copy(brush = SolidColor(Color.White.copy(alpha = 0.2f)))
                                        ) {
                                            Icon(Icons.Default.FileOpen, null, modifier = Modifier.size(14.dp))
                                            Spacer(modifier = Modifier.width(4.dp))
                                            Text(strings.EXIT_NODE_WG_IMPORT_FILE, fontSize = 11.sp, fontWeight = FontWeight.Medium)
                                        }

                                        OutlinedButton(
                                            onClick = {
                                                clipboardManager.getText()?.text?.let { text ->
                                                    if (text.isNotBlank()) {
                                                        val parsed = WireGuardConfigParser.parse(text)
                                                        if (parsed.isValid()) {
                                                            addOrUpdateProfile(parsed)
                                                        } else {
                                                            rawConfigText = text
                                                        }
                                                    }
                                                }
                                            },
                                            modifier = Modifier.weight(1f),
                                            shape = RoundedCornerShape(10.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = AppPalette.accent),
                                            border = ButtonDefaults.outlinedButtonBorder.copy(brush = SolidColor(AppPalette.accent.copy(alpha = 0.5f)))
                                        ) {
                                            Icon(Icons.Default.ContentPaste, null, modifier = Modifier.size(14.dp))
                                            Spacer(modifier = Modifier.width(4.dp))
                                            Text(strings.EXIT_NODE_WG_PASTE_CONF, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(8.dp))

                                    // Raw config text field
                                    OutlinedTextField(
                                        value = rawConfigText,
                                        onValueChange = {
                                            rawConfigText = it
                                            if (it.isNotBlank()) {
                                                val p = WireGuardConfigParser.parse(it)
                                                if (p.isValid()) activeConfig = p
                                            }
                                        },
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(95.dp),
                                        placeholder = {
                                            Text(
                                                text = strings.EXIT_NODE_WG_CONF_PLACEHOLDER,
                                                color = AppPalette.textSecondary.copy(alpha = 0.5f),
                                                fontSize = 11.sp,
                                                fontFamily = FontFamily.Monospace
                                            )
                                        },
                                        textStyle = LocalTextStyle.current.copy(
                                            color = Color.White,
                                            fontSize = 11.sp,
                                            fontFamily = FontFamily.Monospace
                                        ),
                                        shape = RoundedCornerShape(10.dp),
                                        colors = OutlinedTextFieldDefaults.colors(
                                            focusedBorderColor = Color(0xFF38BDF8),
                                            unfocusedBorderColor = Color(0xFF262C3D),
                                            focusedContainerColor = Color(0xFF0F1117),
                                            unfocusedContainerColor = Color(0xFF0F1117),
                                            focusedTextColor = Color.White,
                                            unfocusedTextColor = Color.White
                                        )
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(12.dp))
                        }

                        // Parsed Active Config Summary Card
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(14.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF161B26)),
                            border = BorderStroke(1.dp, Color(0xFF2E384D))
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        text = strings.EXIT_NODE_WG_PARSED_SUMMARY,
                                        color = Color.White,
                                        fontWeight = FontWeight.SemiBold,
                                        fontSize = 13.sp
                                    )
                                    val isValid = activeConfig.isValid()
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = if (isValid) Icons.Default.CheckCircle else Icons.Default.Error,
                                            contentDescription = null,
                                            tint = if (isValid) AppPalette.statusConnected else AppPalette.statusError,
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            text = if (isValid) "Valid" else "Incomplete",
                                            color = if (isValid) AppPalette.statusConnected else AppPalette.statusError,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 11.sp
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.height(10.dp))

                                ConfigSummaryRow(strings.EXIT_NODE_WG_ENDPOINT, activeConfig.endpoint.ifBlank { "—" })
                                ConfigSummaryRow(strings.EXIT_NODE_WG_ADDRESS, listOfNotNull(activeConfig.addressV4.takeIf { it.isNotBlank() }, activeConfig.addressV6.takeIf { it.isNotBlank() }).joinToString(", ").ifBlank { "—" })
                                ConfigSummaryRow(strings.EXIT_NODE_WG_MTU, "${activeConfig.mtu}")
                                ConfigSummaryRow(strings.EXIT_NODE_WG_PUBLIC_KEY, if (activeConfig.publicKey.isNotBlank()) "${activeConfig.publicKey.take(12)}...${activeConfig.publicKey.takeLast(6)}" else "—")
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // Bottom Action Buttons
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
                                val finalCfg = if (rawConfigText.isNotBlank()) {
                                    val p = WireGuardConfigParser.parse(rawConfigText)
                                    if (p.isValid()) p else activeConfig
                                } else {
                                    activeConfig
                                }
                                val updatedProfiles = if (profileList.isNotEmpty()) {
                                    if (profileList.any { it.endpoint == finalCfg.endpoint }) {
                                        profileList.map { if (it.endpoint == finalCfg.endpoint) finalCfg else it }
                                    } else {
                                        profileList + finalCfg
                                    }
                                } else if (finalCfg.isValid()) {
                                    listOf(finalCfg)
                                } else {
                                    emptyList()
                                }

                                if (onSaveAll != null) {
                                    onSaveAll(finalCfg, updatedProfiles, autoSelectState)
                                } else {
                                    onSave(finalCfg)
                                }
                                onDismiss()
                            },
                            modifier = Modifier.weight(1f).height(46.dp),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = AppPalette.accent,
                                contentColor = Color.White
                            )
                        ) {
                            Text(strings.SAVE, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        }
                    }
                }
            }
        }
    }

    // Advisory dialog when primary tunnel is not connected
    if (showTunnelAdvisoryDialog) {
        IosConfirmationDialog(
            title = strings.PROTON_CONNECT_PRIMARY_FIRST_TITLE,
            message = strings.PROTON_CONNECT_PRIMARY_FIRST_DESC,
            confirmText = strings.PROTON_OPEN_ANYWAY,
            confirmColor = Color(0xFF6D4AFF),
            onConfirm = {
                showTunnelAdvisoryDialog = false
                showProtonWebView = true
            },
            onDismiss = {
                showTunnelAdvisoryDialog = false
            }
        )
    }

    // In-app Proton VPN WebView with client-side blob download interceptor
    if (showProtonWebView) {
        ProtonVpnWebView(
            url = "https://account.protonvpn.com/downloads",
            onConfigExtracted = { extractedContent ->
                val parsed = WireGuardConfigParser.parse(extractedContent)
                if (parsed.isValid()) {
                    addOrUpdateProfile(parsed)
                    showProtonWebView = false
                    onSuccessToast?.invoke(strings.PROTON_CONFIG_SUCCESS)
                } else {
                    rawConfigText = extractedContent
                    showProtonWebView = false
                }
            },
            onClose = { showProtonWebView = false }
        )
    }
}

@Composable
private fun ConfigSummaryRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(text = label, color = Color(0xFFCBD5E1), fontSize = 12.sp, fontWeight = FontWeight.Medium)
        Text(
            text = value,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace
        )
    }
}
