package io.github.immaghzbad.aetherst.shared.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
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
import io.github.immaghzbad.aetherst.shared.ui.theme.AppPalette

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

    var account by remember { mutableStateOf(initialAccount) }
    var token by remember { mutableStateOf(initialToken) }
    var country by remember { mutableStateOf(if (initialCountry.isNotBlank()) initialCountry else "us") }
    var port by remember { mutableStateOf(if (initialPort > 0) initialPort.toString() else "10810") }

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

                Spacer(modifier = Modifier.height(18.dp))

                // FxA / ProxyPass Token
                IosInputField(
                    label = strings.EXIT_NODE_FIREFOX_TOKEN,
                    value = token,
                    onValueChange = { token = it },
                    placeholder = "Bearer token or ProxyPass key",
                    testTag = "input_firefox_token",
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = strings.EXIT_NODE_FIREFOX_TOKEN_DESC,
                    color = Color(0xFF94A3B8),
                    fontSize = 10.sp,
                    modifier = Modifier.padding(horizontal = 4.dp)
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Country Code
                IosInputField(
                    label = strings.EXIT_NODE_FIREFOX_COUNTRY,
                    value = country,
                    onValueChange = { country = it },
                    placeholder = "us, de, gb, fr, nl, ca",
                    testTag = "input_firefox_country",
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Local SOCKS Port
                IosInputField(
                    label = strings.EXIT_NODE_FIREFOX_PORT,
                    value = port,
                    onValueChange = { port = it },
                    placeholder = "10810",
                    keyboardType = KeyboardType.Number,
                    testTag = "input_firefox_port",
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Account Email (Optional)
                IosInputField(
                    label = strings.EXIT_NODE_FIREFOX_ACCOUNT,
                    value = account,
                    onValueChange = { account = it },
                    placeholder = "user@example.com (Optional)",
                    testTag = "input_firefox_account",
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
                            val parsedPort = port.toIntOrNull()?.coerceIn(1, 65535) ?: 10810
                            onSave(account.trim(), token.trim(), country.trim().lowercase().ifBlank { "us" }, parsedPort)
                            onDismiss()
                        },
                        modifier = Modifier.weight(1f).height(46.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFFFF944D),
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

