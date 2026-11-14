package io.github.immaghzbad.aetherst.shared.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.immaghzbad.aetherst.platform.isDesktop
import io.github.immaghzbad.aetherst.platform.isWindows
import io.github.immaghzbad.aetherst.shared.i18n.LocalAppStrings
import io.github.immaghzbad.aetherst.shared.i18n.StringsFa
import io.github.immaghzbad.aetherst.shared.model.*
import io.github.immaghzbad.aetherst.shared.ui.theme.AppPalette

@Composable
fun RoutingHubCard(
    config: AetherConfig,
    connectionStatus: ConnectionStatus,
    onClick: () -> Unit,
    enabled: Boolean = true,
    scaleFactor: Float = 1f
) {
    val strings = LocalAppStrings.current
    val isFa = strings is StringsFa

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .clickable(enabled = enabled, onClick = onClick),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = AppPalette.surfaceRaised),
        border = CardDefaults.outlinedCardBorder().copy(brush = SolidColor(Color.White.copy(alpha = 0.08f)))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = (14 * scaleFactor).dp, vertical = (12 * scaleFactor).dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            // Icon & Summary
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size((36 * scaleFactor).dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(AppPalette.accent.copy(alpha = 0.18f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.AltRoute,
                        contentDescription = null,
                        tint = AppPalette.accent,
                        modifier = Modifier.size((20 * scaleFactor).dp)
                    )
                }

                Spacer(modifier = Modifier.width((12 * scaleFactor).dp))

                Column {
                    Text(
                        text = strings.ROUTING_HUB_TITLE,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        fontSize = (13 * scaleFactor).sp,
                        maxLines = 1
                    )
                    Spacer(modifier = Modifier.height(3.dp))
                    // Badges row: Protocol | Exit Node | Connection Mode
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        // Protocol Badge
                        val protoLabel = if (config.protocol == AetherProtocol.ZERO_TRUST) "Z-TRUST" else config.protocol.displayName.split(" ")[0].uppercase()
                        HubBadge(
                            text = protoLabel,
                            bg = AppPalette.accent.copy(alpha = 0.2f),
                            fg = AppPalette.accent,
                            scaleFactor = scaleFactor
                        )

                        // Exit Node Badge
                        val (exitLabel, exitColor) = when (config.exitNodeMode) {
                            ExitNodeMode.DIRECT -> (if (isFa) "مستقیم" else "Direct") to AppPalette.textSecondary
                            ExitNodeMode.PSIPHON_POOL -> {
                                val reg = config.psiphonEgressRegion.trim().uppercase()
                                (if (reg.isNotEmpty()) "سایفون ($reg)" else if (isFa) "سایفون" else "Psiphon") to Color(0xFF30B0C7)
                            }
                            ExitNodeMode.CUSTOM_WG -> (if (isFa) "وایرگارد" else "WireGuard") to AppPalette.statusConnected
                            ExitNodeMode.CUSTOM_SOCKS5 -> (if (isFa) "ساکس ۵" else "SOCKS5") to Color(0xFFFF9F0A)
                        }
                        HubBadge(
                            text = exitLabel,
                            bg = exitColor.copy(alpha = 0.2f),
                            fg = exitColor,
                            scaleFactor = scaleFactor
                        )

                        // Desktop Mode Badge
                        if (isDesktop && isWindows) {
                            val modeLabel = when (config.connectionMode) {
                                ConnectionMode.TUNNEL -> "TUN"
                                ConnectionMode.SYSTEM_PROXY -> "Proxy"
                                ConnectionMode.PROXY_ONLY -> "Manual"
                            }
                            HubBadge(
                                text = modeLabel,
                                bg = Color.White.copy(alpha = 0.08f),
                                fg = Color.White.copy(alpha = 0.7f),
                                scaleFactor = scaleFactor
                            )
                        }
                    }
                }
            }

            // Navigation indicator
            Box(
                modifier = Modifier
                    .size((28 * scaleFactor).dp)
                    .clip(CircleShape)
                    .background(AppPalette.divider.copy(alpha = 0.5f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    tint = AppPalette.textSecondary,
                    modifier = Modifier.size((18 * scaleFactor).dp)
                )
            }
        }
    }
}

@Composable
private fun HubBadge(
    text: String,
    bg: Color,
    fg: Color,
    scaleFactor: Float
) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bg)
            .padding(horizontal = (6 * scaleFactor).dp, vertical = (2 * scaleFactor).dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            color = fg,
            fontWeight = FontWeight.Bold,
            fontSize = (9.5 * scaleFactor).sp,
            maxLines = 1
        )
    }
}

@Composable
fun RoutingModalDialog(
    config: AetherConfig,
    onUpdateConfig: (AetherConfig) -> Unit,
    onUpdateProtocol: (AetherProtocol) -> Unit,
    onOpenPsiphonSheet: () -> Unit,
    onOpenWgDialog: () -> Unit,
    onOpenSocks5Dialog: () -> Unit,
    onDismiss: () -> Unit,
    scaleFactor: Float = 1f
) {
    val strings = LocalAppStrings.current

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.65f))
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = onDismiss
                )
                .padding(horizontal = (16 * scaleFactor).dp, vertical = (24 * scaleFactor).dp),
            contentAlignment = Alignment.Center
        ) {
            Card(
                modifier = Modifier
                    .widthIn(max = (460 * scaleFactor).dp)
                    .fillMaxWidth()
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null,
                        onClick = {} // Consume click inside dialog
                    ),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = AppPalette.surfaceRaised),
                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.12f))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding((18 * scaleFactor).dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy((14 * scaleFactor).dp)
                ) {
                    // Header with Title and Close Button
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size((32 * scaleFactor).dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(AppPalette.accent.copy(alpha = 0.2f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.AltRoute,
                                    contentDescription = null,
                                    tint = AppPalette.accent,
                                    modifier = Modifier.size((18 * scaleFactor).dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = strings.ROUTING_HUB_TITLE,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White,
                                    fontSize = (15 * scaleFactor).sp
                                )
                                Text(
                                    text = strings.ROUTING_HUB_SUBTITLE,
                                    color = AppPalette.textSecondary,
                                    fontSize = (11 * scaleFactor).sp
                                )
                            }
                        }

                        IconButton(
                            onClick = onDismiss,
                            modifier = Modifier.size((32 * scaleFactor).dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Close,
                                contentDescription = "Close",
                                tint = AppPalette.textSecondary,
                                modifier = Modifier.size((18 * scaleFactor).dp)
                            )
                        }
                    }

                    HorizontalDivider(color = Color.White.copy(alpha = 0.08f), thickness = 1.dp)

                    // Section 1: Primary Protocol
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            text = strings.ROUTING_PRIMARY_PROTOCOL,
                            fontWeight = FontWeight.SemiBold,
                            color = Color.White.copy(alpha = 0.85f),
                            fontSize = (12 * scaleFactor).sp
                        )
                        IosProtocolSegmentedControl(
                            selectedProtocol = config.protocol,
                            onProtocolSelected = onUpdateProtocol,
                            allowedProtocols = if (config.isPsiphonActive() || config.isTorActive()) setOf(AetherProtocol.MASQUE, AetherProtocol.WG, AetherProtocol.GOOL) else null,
                            scaleFactor = scaleFactor
                        )
                    }

                    // Section 2: Exit Node
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            text = strings.ROUTING_EXIT_NODE,
                            fontWeight = FontWeight.SemiBold,
                            color = Color.White.copy(alpha = 0.85f),
                            fontSize = (12 * scaleFactor).sp
                        )
                        ExitNodeCard(
                            config = config,
                            onUpdateConfig = onUpdateConfig,
                            onOpenPsiphonSheet = onOpenPsiphonSheet,
                            onOpenWgDialog = onOpenWgDialog,
                            onOpenSocks5Dialog = onOpenSocks5Dialog,
                            scaleFactor = scaleFactor
                        )
                    }

                    // Section 3: Connection Mode (Desktop Windows only)
                    if (isDesktop && isWindows) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(
                                text = strings.ROUTING_CONNECTION_MODE,
                                fontWeight = FontWeight.SemiBold,
                                color = Color.White.copy(alpha = 0.85f),
                                fontSize = (12 * scaleFactor).sp
                            )
                            IosConnectionModeSegmentedControl(
                                selectedMode = config.connectionMode,
                                onModeSelected = { onUpdateConfig(config.copy(connectionMode = it)) },
                                scaleFactor = scaleFactor
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height((4 * scaleFactor).dp))

                    // Done / Confirm Button
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height((46 * scaleFactor).dp),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = AppPalette.accent)
                    ) {
                        Text(
                            text = strings.OK,
                            fontWeight = FontWeight.Bold,
                            fontSize = (14 * scaleFactor).sp,
                            color = Color.White
                        )
                    }
                }
            }
        }
    }
}

