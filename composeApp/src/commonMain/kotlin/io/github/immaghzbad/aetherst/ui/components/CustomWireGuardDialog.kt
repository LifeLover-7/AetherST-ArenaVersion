package io.github.immaghzbad.aetherst.shared.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VpnKey
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
import io.github.immaghzbad.aetherst.shared.platform.Bridge
import io.github.immaghzbad.aetherst.shared.ui.theme.AppPalette
import io.github.immaghzbad.aetherst.shared.util.WireGuardConfigParser

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

    var rawConfigText by remember { mutableStateOf(initialConfig.rawConfig) }
    var parsedConfig by remember {
        mutableStateOf(
            if (initialConfig.rawConfig.isNotBlank()) {
                WireGuardConfigParser.parse(initialConfig.rawConfig)
            } else {
                initialConfig
            }
        )
    }

    var showProtonWebView by remember { mutableStateOf(false) }
    var showTunnelAdvisoryDialog by remember { mutableStateOf(false) }

    fun updateFromRaw(text: String) {
        rawConfigText = text
        if (text.isNotBlank()) {
            parsedConfig = WireGuardConfigParser.parse(text)
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
                    .fillMaxWidth(0.94f)
                    .fillMaxHeight(0.90f)
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
                                .size(36.dp)
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

                Spacer(modifier = Modifier.height(14.dp))

                // Scrollable content
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState())
                ) {
                    // Advisory Warning Banner
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF59E0B).copy(alpha = 0.12f)),
                        border = BorderStroke(1.dp, Color(0xFFF59E0B).copy(alpha = 0.4f))
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Icon(
                                imageVector = Icons.Default.Error,
                                contentDescription = null,
                                tint = Color(0xFFF59E0B),
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = strings.EXIT_NODE_WG_UDP_ADVISORY,
                                color = Color(0xFFFDE68A),
                                fontSize = 11.sp,
                                lineHeight = 16.sp
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Proton Auto-Import Primary Action Banner
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .clickable {
                                val isPrimaryConnected = connectionStatus == ConnectionStatus.RUNNING || connectionStatus == ConnectionStatus.TUN_ACTIVE
                                if (!isPrimaryConnected) {
                                    showTunnelAdvisoryDialog = true
                                } else {
                                    showProtonWebView = true
                                }
                            },
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF6D4AFF).copy(alpha = 0.18f)),
                        border = CardDefaults.outlinedCardBorder().copy(brush = SolidColor(Color(0xFF6D4AFF).copy(alpha = 0.5f)))
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.weight(1f)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(32.dp)
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(Color(0xFF6D4AFF)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        Icons.Default.Shield,
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = strings.PROTON_IMPORT_BUTTON,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White,
                                        fontSize = 13.sp
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
                                shape = RoundedCornerShape(10.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6D4AFF)),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
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
                                        updateFromRaw(fileContent)
                                    }
                                }
                            },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                            border = ButtonDefaults.outlinedButtonBorder.copy(brush = SolidColor(Color.White.copy(alpha = 0.2f)))
                        ) {
                            Icon(Icons.Default.FileOpen, null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(strings.EXIT_NODE_WG_IMPORT_FILE, fontSize = 11.sp, fontWeight = FontWeight.Medium)
                        }

                        OutlinedButton(
                            onClick = {
                                clipboardManager.getText()?.text?.let { text ->
                                    if (text.isNotBlank()) updateFromRaw(text)
                                }
                            },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = AppPalette.accent),
                            border = ButtonDefaults.outlinedButtonBorder.copy(brush = SolidColor(AppPalette.accent.copy(alpha = 0.5f)))
                        ) {
                            Icon(Icons.Default.ContentPaste, null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(strings.EXIT_NODE_WG_PASTE_CONF, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Raw .conf Text Area
                    Text(
                        text = strings.EXIT_NODE_WG_PASTE_CONF,
                        color = AppPalette.textSecondary,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    OutlinedTextField(
                        value = rawConfigText,
                        onValueChange = { updateFromRaw(it) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(120.dp),
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
                        shape = RoundedCornerShape(12.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFF38BDF8),
                            unfocusedBorderColor = Color(0xFF262C3D),
                            focusedContainerColor = Color(0xFF141721),
                            unfocusedContainerColor = Color(0xFF141721),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White
                        )
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    // Parsed Summary Card - Solid dark high-contrast
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
                                val isValid = parsedConfig.isValid()
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

                            ConfigSummaryRow(strings.EXIT_NODE_WG_ENDPOINT, parsedConfig.endpoint.ifBlank { "—" })
                            ConfigSummaryRow(strings.EXIT_NODE_WG_ADDRESS, listOfNotNull(parsedConfig.addressV4.takeIf { it.isNotBlank() }, parsedConfig.addressV6.takeIf { it.isNotBlank() }).joinToString(", ").ifBlank { "—" })
                            ConfigSummaryRow(strings.EXIT_NODE_WG_DNS, parsedConfig.dns.ifBlank { "1.1.1.1" })
                            ConfigSummaryRow(strings.EXIT_NODE_WG_MTU, "${parsedConfig.mtu}")
                            ConfigSummaryRow(strings.EXIT_NODE_WG_ALLOWED_IPS, listOfNotNull(parsedConfig.allowedIpsV4.takeIf { it.isNotBlank() }, parsedConfig.allowedIpsV6.takeIf { it.isNotBlank() }).joinToString(", ").ifBlank { "0.0.0.0/0" })
                            ConfigSummaryRow(strings.EXIT_NODE_WG_PUBLIC_KEY, if (parsedConfig.publicKey.isNotBlank()) "${parsedConfig.publicKey.take(12)}...${parsedConfig.publicKey.takeLast(6)}" else "—")
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

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
                            val finalCfg = if (rawConfigText.isNotBlank()) {
                                WireGuardConfigParser.parse(rawConfigText)
                            } else {
                                parsedConfig
                            }
                            if (onSaveAll != null) {
                                val updatedProfiles = if (profiles.isNotEmpty()) {
                                    if (profiles.any { it.endpoint == finalCfg.endpoint }) {
                                        profiles.map { if (it.endpoint == finalCfg.endpoint) finalCfg else it }
                                    } else {
                                        profiles + finalCfg
                                    }
                                } else {
                                    listOf(finalCfg)
                                }
                                onSaveAll(finalCfg, updatedProfiles, autoSelect)
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
                    onSave(parsed)
                    showProtonWebView = false
                    onSuccessToast?.invoke(strings.PROTON_CONFIG_SUCCESS)
                    onDismiss()
                } else {
                    updateFromRaw(extractedContent)
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
