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
        |${'$'}logFile = Join-Path ${'$'}data '$HELPER_LOG'
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
        |  ${'$'}r2 = route add 128.0.0.0 mask 128.0.0.0 ${'$'}params.tunIp metric 1 if ${'$'}ifIndex 2>&1
        |  L "route add: ${'$'}r1"
        |  L "route add: ${'$'}r2"
        |  try {
        |    New-NetFirewallRule -DisplayName 'AetherST_Block_IPv6' -Direction Outbound -Action Block -RemoteAddress '::/0' -ErrorAction SilentlyContinue | Out-Null
        |    L "IPv6 leak protection activated"
        |  } catch {}
        |  try {
        |    Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null
        |    Get-NetAdapter | Where-Object { ${'$'}_.InterfaceIndex -ne ${'$'}ifIndex -and ${'$'}_.Status -eq 'Up' } | ForEach-Object {
        |      Set-DnsClientServerAddress -InterfaceIndex ${'$'}_.InterfaceIndex -ServerAddresses '1.1.1.1','1.0.0.1' -ErrorAction SilentlyContinue
        |    }
        |    L "DNS cache cleared & leak protection applied to physical adapters"
        |  } catch {}
        |}
        |function Test-TunRoutes {
        |  ${'$'}t = route print -4 | Select-String "128.0.0.0"
        |  return ((${'$'}t | Measure-Object).Count -ge 2)
        |}
        |L "helper started (app pid ${'$'}AppPid) data=${'$'}data bin=${'$'}bin"
        |${'$'}params = Get-Content (Join-Path ${'$'}data '$PARAMS_FILE') -Raw | ConvertFrom-Json
        |${'$'}exe = Join-Path ${'$'}bin 'hev-socks5-tunnel.exe'
        |${'$'}yml = Join-Path ${'$'}data '$HEV_YAML'
        |${'$'}stopFile = Join-Path ${'$'}data '$STOP_FLAG'
        |if (-not (Test-Path ${'$'}exe)) {
        |  ${'$'}alt = Join-Path ${'$'}data 'hev-socks5-tunnel.exe'
        |  if (Test-Path ${'$'}alt) { ${'$'}exe = ${'$'}alt }
        |}
        |if (-not (Test-Path ${'$'}exe)) { L "ERROR: hev binary missing at ${'$'}exe"; exit 1 }
        |if (-not (Test-Path ${'$'}yml)) { L "ERROR: yml missing at ${'$'}yml"; exit 1 }
        |${'$'}hev = Start-Process -FilePath ${'$'}exe -ArgumentList "`"${'$'}yml`"" -WorkingDirectory ${'$'}bin -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path ${'$'}data '$HEV_OUT') -RedirectStandardError (Join-Path ${'$'}data '$HEV_ERR')
        |L "hev started pid ${'$'}(${'$'}hev.Id) exe=${'$'}exe yml=${'$'}yml"
        |${'$'}ifIndex = ${'$'}null
        |for (${'$'}i = 0; ${'$'}i -lt 40; ${'$'}i++) {
        |  Start-Sleep -Milliseconds 500
        |  ${'$'}line = netsh interface ipv4 show interfaces | Select-String ${'$'}params.tunName
        |  if (${'$'}line) {
        |    ${'$'}toks = ${'$'}line.ToString().Trim() -split '\s+'
        |    if (${'$'}toks.Count -ge 2) { ${'$'}ifIndex = ${'$'}toks[0]; break }
        |  }
        |}
        |if (-not ${'$'}ifIndex) {
        |  L "ERROR: tun adapter not found"
        |  if (Get-Process -Id ${'$'}hev.Id -ErrorAction SilentlyContinue) { Stop-Process -Id ${'$'}hev.Id -Force }
        |  exit 1
        |}
        |L "adapter found index ${'$'}ifIndex"
        |try { Set-NetIPInterface -InterfaceIndex ${'$'}ifIndex -InterfaceMetric 1 -NlMtu ${'$'}params.mtu -ErrorAction SilentlyContinue | Out-Null } catch {}
        |try { Set-DnsClientServerAddress -InterfaceIndex ${'$'}ifIndex -ServerAddresses ${'$'}params.dnsFake -ErrorAction Stop | Out-Null } catch { netsh interface ipv4 set dnsservers name="$(${'$'}params.tunName)" static ${'$'}params.dnsFake primary 2>&1 | Out-Null }
        |Add-TunRoutes ${'$'}ifIndex
        |L "routes present: $(Test-TunRoutes)"
        |function Apply-SplitTunnelingRules(${'$'}tunAlias) {
        |  Get-NetFirewallRule -DisplayName "AetherST_Split_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        |  foreach (${'$'}exe in ${'$'}params.blockedExes) {
        |    if (${'$'}exe -and (Test-Path ${'$'}exe)) {
        |      ${'$'}hash = [Math]::Abs(${'$'}exe.GetHashCode())
        |      New-NetFirewallRule -DisplayName "AetherST_Split_Block_${'$'}hash" -Direction Outbound -Program ${'$'}exe -Action Block -ErrorAction SilentlyContinue | Out-Null
        |      L "Firewall BLOCK rule for: ${'$'}exe"
        |    }
        |  }
        |  if (${'$'}params.tunnelAllApps) {
        |    foreach (${'$'}exe in ${'$'}params.bypassExes) {
        |      if (${'$'}exe -and (Test-Path ${'$'}exe)) {
        |        ${'$'}hash = [Math]::Abs(${'$'}exe.GetHashCode())
        |        New-NetFirewallRule -DisplayName "AetherST_Split_Bypass_${'$'}hash" -Direction Outbound -Program ${'$'}exe -InterfaceAlias ${'$'}tunAlias -Action Block -ErrorAction SilentlyContinue | Out-Null
        |        L "Firewall BYPASS rule for: ${'$'}exe"
        |      }
        |    }
        |  }
        |}
        |Apply-SplitTunnelingRules ${'$'}params.tunName
        |${'$'}gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { ${'$'}_.InterfaceAlias -ne ${'$'}params.tunName -and ${'$'}_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1).NextHop
        |if (-not ${'$'}gw) { ${'$'}gw = (Get-NetIPConfiguration | Where-Object { ${'$'}_.NetAdapter.Status -eq 'Up' -and ${'$'}_.IPv4DefaultGateway -ne ${'$'}null } | Select-Object -First 1).IPv4DefaultGateway.NextHop }
        |L "physical gateway ${'$'}gw"
        |${'$'}cfRanges = @(
        |  @{ ip = '162.159.192.0'; mask = '255.255.255.0' },
        |  @{ ip = '162.159.193.0'; mask = '255.255.255.0' },
        |  @{ ip = '162.159.195.0'; mask = '255.255.255.0' },
        |  @{ ip = '188.114.96.0'; mask = '255.255.255.0' },
        |  @{ ip = '188.114.97.0'; mask = '255.255.255.0' },
        |  @{ ip = '188.114.98.0'; mask = '255.255.255.0' },
        |  @{ ip = '188.114.99.0'; mask = '255.255.255.0' },
        |  @{ ip = '172.64.0.0'; mask = '255.248.0.0' }
        |)
        |foreach (${'$'}r in ${'$'}cfRanges) {
        |  if (${'$'}gw) { route add ${'$'}r.ip mask ${'$'}r.mask ${'$'}gw metric 1 2>&1 | Out-Null }
        |}
        |foreach (${'$'}ip in ${'$'}params.endpointIps) {
        |  if (${'$'}ip -and ${'$'}gw) { route add ${'$'}ip mask 255.255.255.255 ${'$'}gw metric 1 2>&1 | Out-Null }
        |}
        |${'$'}appliedDirect = @()
        |foreach (${'$'}entry in ${'$'}params.directIps) {
        |  if (${'$'}entry -and ${'$'}gw) {
        |    if (${'$'}entry -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)${'$'}') {
        |      ${'$'}netIp = ${'$'}Matches[1]
        |      ${'$'}mask = Convert-CidrToMask ([int]${'$'}Matches[2])
        |      route add ${'$'}netIp mask ${'$'}mask ${'$'}gw metric 1 2>&1 | Out-Null
        |      ${'$'}appliedDirect += @{ ip = ${'$'}netIp; mask = ${'$'}mask }
        |    } elseif (${'$'}entry -match '^\d+\.\d+\.\d+\.\d+${'$'}') {
        |      route add ${'$'}entry mask 255.255.255.255 ${'$'}gw metric 1 2>&1 | Out-Null
        |      ${'$'}appliedDirect += @{ ip = ${'$'}entry; mask = '255.255.255.255' }
        |    }
        |  }
        |}
        |L "Applied direct routes count: ${'$'}(${'$'}appliedDirect.Count)"
        |${'$'}state = @{
        |  ifIndex = "${'$'}ifIndex"
        |  tunIp = "${'$'}(${'$'}params.tunIp)"
        |  gw = "${'$'}gw"
        |  hevPid = ${'$'}hev.Id
        |  endpointIps = @(${'$'}params.endpointIps)
        |  directRoutes = @(${'$'}appliedDirect)
        |}
        |${'$'}state | ConvertTo-Json -Depth 4 | Out-File (Join-Path ${'$'}data 'tun-state.json') -Encoding utf8
        |L "TUN setup complete. PowerShell exiting to save RAM."
        |exit 0
        |""".trimMargin()
        File(dataDir, "tun-helper.ps1").writeText(script)
    }

    private fun writeCleanupScript(dataDir: File) {
        val dataPath = dataDir.absolutePath
        val escapedData = dataPath.replace("'", "''")
        val script = """
        |${'$'}ErrorActionPreference = 'SilentlyContinue'
        |${'$'}data = '$escapedData'
        |${'$'}logFile = Join-Path${'$'}data '$HELPER_LOG'
        |function L(${'$'}m) { "${'$'}(Get-Date -Format 'HH:mm:ss') ${'$'}m" | Out-File ${'$'}logFile -Append }
        |L "helper cleanup started"
        |try { Remove-NetFirewallRule -DisplayName 'AetherST_Block_IPv6' -ErrorAction SilentlyContinue | Out-Null } catch {}
        |try { Get-NetFirewallRule -DisplayName "AetherST_Split_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch {}
        |try { Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null } catch {}
        |try { Get-NetAdapter | Where-Object { ${'$'}_.Status -eq 'Up' } | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex ${'$'}_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue } } catch {}
        |${'$'}stateFile = Join-Path ${'$'}data 'tun-state.json'
        |if (Test-Path ${'$'}stateFile) {
        |  try {
        |    ${'$'}state = Get-Content ${'$'}stateFile -Raw | ConvertFrom-Json
        |    if (${'$'}state.ifIndex -and ${'$'}state.tunIp) {
        |      route delete 0.0.0.0 mask 128.0.0.0 ${'$'}state.tunIp metric 1 if ${'$'}state.ifIndex 2>&1 | Out-Null
        |      route delete 128.0.0.0 mask 128.0.0.0 ${'$'}state.tunIp metric 1 if ${'$'}state.ifIndex 2>&1 | Out-Null
        |    }
        |    if (${'$'}state.endpointIps -and ${'$'}state.gw) {
        |      foreach (${'$'}ip in ${'$'}state.endpointIps) {
        |        if (${'$'}ip) { route delete ${'$'}ip mask 255.255.255.255 ${'$'}state.gw 2>&1 | Out-Null }
        |      }
        |    }
        |    if (${'$'}state.directRoutes -and ${'$'}state.gw) {
        |      foreach (${'$'}dr in ${'$'}state.directRoutes) {
        |        if (${'$'}dr.ip -and ${'$'}dr.mask) { route delete ${'$'}dr.ip mask ${'$'}dr.mask ${'$'}state.gw 2>&1 | Out-Null }
        |      }
        |    }
        |    if (${'$'}state.hevPid) {
        |      Stop-Process -Id ${'$'}state.hevPid -Force -ErrorAction SilentlyContinue
        |    }
        |  } catch {}
        |  Remove-Item ${'$'}stateFile -ErrorAction SilentlyContinue
        |}
        |${'$'}cfRanges = @(
        |  @{ ip = '162.159.192.0'; mask = '255.255.255.0' },
        |  @{ ip = '162.159.193.0'; mask = '255.255.255.0' },
        |  @{ ip = '162.159.195.0'; mask = '255.255.255.0' },
        |  @{ ip = '188.114.96.0'; mask = '255.255.255.0' },
        |  @{ ip = '188.114.97.0'; mask = '255.255.255.0' },
        |  @{ ip = '188.114.98.0'; mask = '255.255.255.0' },
        |  @{ ip = '188.114.99.0'; mask = '255.255.255.0' },
        |  @{ ip = '172.64.0.0'; mask = '255.248.0.0' }
        |)
        |foreach (${'$'}r in ${'$'}cfRanges) {
        |  route delete ${'$'}r.ip mask ${'$'}r.mask 2>&1 | Out-Null
        |}
        |route delete 0.0.0.0 mask 128.0.0.0 $TUN_IPV4 2>&1 | Out-Null
        |route delete 128.0.0.0 mask 128.0.0.0 $TUN_IPV4 2>&1 | Out-Null
        |Get-Process -Name 'hev-socks5-tunnel' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        |Remove-Item (Join-Path ${'$'}data '$STOP_FLAG') -ErrorAction SilentlyContinue
        |L "helper cleanup done"
        |exit 0
        |""".trimMargin()
        File(dataDir, "tun-cleanup.ps1").writeText(script)
    }

    private fun startTailing(dataDir: File) {
        tailThread = Thread {
            val helperFile = File(dataDir, HELPER_LOG)
            var helperOffset = 0L
            var checkCounter = 0
            while (isRunning.get()) {
                try {
                    if (helperFile.exists()) {
                        val len = helperFile.length()
                        if (len > helperOffset) {
                            java.io.RandomAccessFile(helperFile, "r").use { raf ->
                                raf.seek(helperOffset)
                                val bytes = ByteArray((len - helperOffset).toInt())
                                raf.readFully(bytes)
                                helperOffset = len
                                String(bytes).lineSequence().filter { it.isNotBlank() }.forEach {
                                    LogRepository.i("[Tun] $it")
                                }
                            }
                        }
                    }
                    checkCounter++
                    if (checkCounter % 5 == 0) {
                        val isHevAlive = ProcessHandle.allProcesses().anyMatch {
                            it.info().command().map { c -> c.contains("hev-socks5-tunnel", ignoreCase = true) }.orElse(false)
                        }
                        if (!isHevAlive && isRunning.get()) {
                            LogRepository.w("[Tun] hev-socks5-tunnel process exited unexpectedly")
                        }
                    }
                } catch (_: Exception) {}
                Thread.sleep(1000)
            }
        }
        tailThread?.isDaemon = true
        tailThread?.start()
    }
}
