plugins { alias(libs.plugins.kotlin.jvm) }

// Exercise the exact shared network sources used by Android, on host JVM sockets with a real WG peer.
// No Android mockable.jar, Compose/AGP test variant, device privilege, or provider credentials required.
kotlin {
    jvmToolchain(17)
    sourceSets.named("test") {
        kotlin.srcDir("../../composeApp/src/commonMain/kotlin")
        kotlin.include(
            "**/net/ExitConnection.kt", "**/net/FirefoxConnectSession.kt", "**/net/FirefoxVpnExitTunnel.kt",
            "**/net/WireGuardExitConfig.kt", "**/net/WireGuardExitTunnel.kt", "**/net/WireGuardUdpControl.kt",
            "**/model/CustomWireGuardConfig.kt", "**/util/WireGuardConfigParser.kt", "**/net/*Test.kt", "**/data/FixtureLog.kt"
        )
    }
}
dependencies {
    testImplementation(libs.okhttp)
    testImplementation(libs.okio)
    testImplementation(libs.kotlinx.serialization.json)
    testImplementation(libs.kotlinx.coroutines.core)
    testImplementation(kotlin("test-junit"))
    testImplementation(libs.junit)
    testImplementation("com.squareup.okhttp3:okhttp-tls:${libs.versions.okhttp.get()}")
}
tasks.test {
    useJUnit()
    outputs.upToDateWhen { false }
    testLogging { events("passed", "failed", "skipped") }
}
