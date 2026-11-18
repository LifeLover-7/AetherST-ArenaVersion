package io.github.immaghzbad.aetherst.shared.core

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.platform.getSystemUtils
import io.github.immaghzbad.aetherst.platform.PlatformContext
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

object TunHelper {

    const val TUN_NAME = "AetherST"
    const val TUN_IPV4 = "198.18.0.1"
    const val DEFAULT_TUN_MTU = 1280
    const val DNS_FAKE = "198.18.0.2"

    private const val STOP_FLAG = "tun-stop.flag"
    private const val PARAMS_FILE = "tun-params.json"
    private const val HELPER_LOG = "tun-helper.log"
    private const val HEV_OUT = "hev-out.log"
    private const val HEV_ERR = "hev-err.log"
    private const val HEV_YAML = "hev-socks5-tunnel.yml"

    private val isRunning = AtomicBoolean(false)
    private var tailThread: Thread? = null
    @Volatile private var targetSocksPort = 2021

    fun start(
        socksTargetPort: Int,
        configuredMtu: Int = DEFAULT_TUN_MTU,
        bypassExes: Set<String> = emptySet(),
        blockedExes: Set<String> = emptySet(),
        tunnelAllApps: Boolean = true,
        directIps: List<String> = emptyList(),
        udpMode: String = "udp"
    ) {
        if (isRunning.getAndSet(true)) return
        targetSocksPort = socksTargetPort
        val safeMtu = if (configuredMtu in 1200..1360) configuredMtu else DEFAULT_TUN_MTU

        try {
            val context = PlatformContext()
            try {
                getBinaryManager(context).prepareBinary("hev-socks5-tunnel.exe")
            } catch (_: Exception) {}

            val dataDir = getSystemUtils(context).getFilesDir()
            val dataDirFile = File(dataDir)

            File(dataDir, HEV_YAML).writeText(buildHevConfig(socksTargetPort, safeMtu, udpMode))
            writeParams(socksTargetPort, dataDirFile, safeMtu, bypassExes, blockedExes, tunnelAllApps, directIps)
            File(dataDir, STOP_FLAG).delete()
            writeHelperScript(dataDirFile)

            val helperScript = File(dataDirFile, "tun-helper.ps1")
            val appPid = ProcessHandle.current().pid()
            val command = if (Elevation.isElevated()) {
                arrayOf(
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                    "-File", helperScript.absolutePath, "-AppPid", "$appPid"
                )
            } else {
                arrayOf(
                    "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                    "Start-Process -FilePath 'powershell' -WindowStyle Hidden -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','${helperScript.absolutePath}','-AppPid','$appPid'"
                )
            }
            ProcessBuilder(*command).redirectErrorStream(true).start()
            LogRepository.i("[Tun] Direct helper started pointing to $socksTargetPort (mtu=$safeMtu), bypass=${bypassExes.size}, blocked=${blockedExes.size}, directCidrs=${directIps.size}, pid=$appPid")

            startTailing(dataDirFile)
        } catch (e: Exception) {
            isRunning.set(false)
            LogRepository.e("[Tun] Helper start failed: ${e.localizedMessage}")
        }
    }

    fun stop() {
        if (!isRunning.getAndSet(false)) return
        val context = PlatformContext()
        val dataDir = File(getSystemUtils(context).getFilesDir())
        try {
            File(dataDir, STOP_FLAG).writeText("stop")
            LogRepository.i("[Tun] Stop flag written; executing cleanup")
        } catch (_: Exception) {}

        Thread {
            try {
                writeCleanupScript(dataDir)
                val cleanupScript = File(dataDir, "tun-cleanup.ps1")
                if (cleanupScript.exists()) {
                    val command = if (Elevation.isElevated()) {
                        arrayOf(
                            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                            "-File", cleanupScript.absolutePath
                        )
                    } else {
                        arrayOf(
                            "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                            "Start-Process -FilePath 'powershell' -WindowStyle Hidden -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','${cleanupScript.absolutePath}'"
                        )
                    }
                    ProcessBuilder(*command).redirectErrorStream(true).start().waitFor(8, java.util.concurrent.TimeUnit.SECONDS)
                }
                if (System.getProperty("os.name").lowercase().contains("win")) {
                    ProcessBuilder("taskkill", "/F", "/T", "/IM", "hev-socks5-tunnel.exe")
                        .redirectErrorStream(true).start()
                }
            } catch (_: Exception) {}
        }.apply { isDaemon = true; start() }
    }

    fun isActive(): Boolean = isRunning.get()

    private fun buildHevConfig(targetPort: Int, mtu: Int, udpMode: String = "udp"): String {
        val logFile = runCatching {
            val context = PlatformContext()
            val dataDir = getSystemUtils(context).getFilesDir()
            File(dataDir, "hev.log").absolutePath.replace('\\', '/')
        }.getOrDefault("hev.log")
        val safeUdp = if (udpMode.isBlank() || udpMode == "off") "" else "  udp: $udpMode"
        return """
        |tunnel:
        |  name: $TUN_NAME
        |  mtu: $mtu
        |  ipv4: $TUN_IPV4
        |socks5:
        |  address: 127.0.0.1
        |  port: $targetPort
        |$safeUdp
        |mapdns:
        |  address: $DNS_FAKE
        |  port: 53
        |  network: 100.64.0.0
        |  netmask: 255.192.0.0
        |  cache-size: 10000
        |misc:
        |  log-file: '$logFile'
        |  log-level: warn
        |  connect-timeout: 5000
        |  read-write-timeout: 60000
        |""".trimMargin()
    }

    private fun writeParams(
        socksTargetPort: Int,
        dataDir: File,
        mtu: Int,
        bypassExes: Set<String> = emptySet(),
        blockedExes: Set<String> = emptySet(),
        tunnelAllApps: Boolean = true,
        directIps: List<String> = emptyList()
    ) {
        val endpointIps = collectEndpointIps().joinToString(",") { "\"$it\"" }
        val validBypass = bypassExes.filter { it.isNotBlank() && it.endsWith(".exe", ignoreCase = true) }
        val validBlocked = blockedExes.filter { it.isNotBlank() && it.endsWith(".exe", ignoreCase = true) }
        val bypassJson = validBypass.joinToString(",") { "\"${it.replace("\\", "\\\\").replace("\"", "\\\"")}\"" }
        val blockedJson = validBlocked.joinToString(",") { "\"${it.replace("\\", "\\\\").replace("\"", "\\\"")}\"" }
        val directIpsJson = directIps.filter { it.isNotBlank() }.joinToString(",") { "\"${it.replace("\\", "\\\\").replace("\"", "\\\"")}\"" }
        val json = """
        {"tunName":"$TUN_NAME","tunIp":"$TUN_IPV4","dnsFake":"$DNS_FAKE","socksPort":$socksTargetPort,"targetSocksPort":$socksTargetPort,"mtu":$mtu,"endpointIps":[$endpointIps],"bypassExes":[$bypassJson],"blockedExes":[$blockedJson],"tunnelAllApps":$tunnelAllApps,"directIps":[$directIpsJson]}
        """.trimIndent()
        File(dataDir, PARAMS_FILE).writeText(json)
    }

    private fun collectEndpointIps(): List<String> {
        val result = LinkedHashSet<String>()
        val context = PlatformContext()
        val baseDir = File(getSystemUtils(context).getFilesDir())
        val candidates = mutableListOf<File>()
        baseDir.listFiles()?.forEach { candidates.add(it) }
        File(baseDir, "bin").listFiles()?.forEach { candidates.add(it) }
        val pattern = Regex("""(?i)(?:peer|assigned_endpoint)\s*=\s*"?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)""")
        for (file in candidates) {
            if (!file.isFile || !file.extension.equals("toml", ignoreCase = true)) continue
            runCatching {
                val text = file.readText()
                pattern.findAll(text).forEach { result.add(it.groupValues[1]) }
            }
        }
        return result.toList()
    }

    private fun writeHelperScript(dataDir: File) {
        val dataPath = dataDir.absolutePath
        val binPath = File(dataDir, "bin").absolutePath
        val escapedData = dataPath.replace("'", "''")
        val escapedBin = binPath.replace("'", "''")
        val script = """
        |param([int]${'$'}AppPid = 0)
        |${'$'}ErrorActionPreference = 'Continue'
        |${'$'}data = '$escapedData'
        |${'$'}bin = '$escapedBin'
        |if (-not (Test-Path ${'$'}data)) { New-Item -ItemType Directory -Path ${'$'}data -Force | Out-Null }
        |if (-not (Test-Path ${'$'}bin)) { New-Item -ItemType Directory -Path ${'$'}bin -Force | Out-Null }
        |${'$'}logFile = Join-Path${'$'}data '$HELPER_LOG'
        |function L(${'$'}m) { "${'$'}(Get-Date -Format 'HH:mm:ss') ${'$'}m" | Out-File ${'$'}logFile -Append }
        |function Convert-CidrToMask([int]${'$'}prefix) {
        |  if (${'$'}prefix -le 0) { return "0.0.0.0" }
        |  if (${'$'}prefix -ge 32) { return "255.255.255.255" }
        |  ${'$'}maskInt = ([uint32]::MaxValue) -shl (32 - ${'$'}prefix)
        |  return "${'$'}(${'$'}maskInt -shr 24 -band 255).${'$'}(${'$'}maskInt -shr 16 -band 255).${'$'}(${'$'}maskInt -shr 8 -band 255).${'$'}(${'$'}maskInt -band 255)"
        |}
        |function Add-TunRoutes(${'$'}ifIndex) {
        |  try { 
        |    Set-NetIPInterface -InterfaceIndex ${'$'}ifIndex -InterfaceMetric 1 -NlMtu ${'$'}params.mtu -ErrorAction SilentlyContinue | Out-Null
        |    netsh interface ipv4 set subinterface ${'$'}ifIndex mtu=${'$'}params.mtu store=active 2>&1 | Out-Null
        |  } catch {}
        |  ${'$'}r1 = route add 0.0.0.0 mask 128.0.0.0 ${'$'}params.tunIp metric 1 if ${'$'}ifIndex 2>&1
        |  ${'$'}r2 = route add 128.0.0.0 mask 128.0
