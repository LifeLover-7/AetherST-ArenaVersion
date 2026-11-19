plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.kotlin.android)
  alias(libs.plugins.kotlin.compose)
  id("org.jetbrains.kotlin.plugin.serialization") version "2.1.0"
}

android {
  namespace = "io.github.immaghzbad.aetherst"
  compileSdk = 36

  defaultConfig {
    applicationId = "io.github.immaghzbad.aetherst"
    minSdk = 26
    targetSdk = 35
    versionCode = 26
    versionName = "2.1.5"

    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

    externalNativeBuild {
      ndkBuild {
        abiFilters("arm64-v8a")
      }
    }
  }

  externalNativeBuild {
    ndkBuild {
      path = file("src/main/cpp/Android.mk")
    }
  }

  ndkVersion = "30.0.15729638"

  signingConfigs {
    create("release") {
      val envKeystore = System.getenv("KEYSTORE_FILE")
      storeFile = when {
        envKeystore != null && file(envKeystore).exists() -> file(envKeystore)
        envKeystore != null && rootProject.file(envKeystore).exists() -> rootProject.file(envKeystore)
        file("src/main/release.jks").exists() -> file("src/main/release.jks")
        else -> rootProject.file("app/src/main/release.jks")
      }
      storePassword = System.getenv("KEYSTORE_PASSWORD") ?: "aether123456"
      keyAlias = System.getenv("KEY_ALIAS") ?: "aetherst"
      keyPassword = System.getenv("KEY_PASSWORD") ?: "aether123456"
      enableV1Signing = true
      enableV2Signing = true
      enableV3Signing = true
      enableV4Signing = false
    }
  }

  buildTypes {
    release {
      isCrunchPngs = true
      isMinifyEnabled = true
      isShrinkResources = true
      proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
      signingConfig = signingConfigs.getByName("release")
    }
    debug { }
  }

  splits {
    abi {
      isEnable = true
      reset()
      include("arm64-v8a")
      isUniversalApk = true
    }
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }

  kotlin {
    compilerOptions {
      jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
  }

  buildFeatures {
    compose = true
    buildConfig = true
  }
  testOptions { unitTests { isIncludeAndroidResources = true } }

  packaging {
    jniLibs {
      useLegacyPackaging = true
    }
  }
}

dependencies {
  implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar", "*.jar"))))
  implementation(project(":composeApp"))
  implementation(platform(libs.androidx.compose.bom))
  implementation(libs.androidx.activity.compose)
  implementation(libs.androidx.compose.material.icons.core)
  implementation(libs.androidx.compose.material.icons.extended)
  implementation(libs.androidx.compose.material3)
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.ui.graphics)
  implementation(libs.androidx.compose.ui.tooling.preview)
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.datastore.preferences)
  implementation(libs.androidx.lifecycle.runtime.compose)
  implementation(libs.androidx.lifecycle.runtime.ktx)
  implementation(libs.androidx.lifecycle.viewmodel.compose)
  implementation(libs.androidx.navigation.compose)
  implementation(libs.androidx.room.ktx)
  implementation(libs.androidx.room.runtime)
  implementation(libs.converter.moshi)
  implementation(libs.kotlinx.coroutines.android)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.kotlinx.serialization.json)
  implementation(libs.logging.interceptor)
  implementation(libs.moshi.kotlin)
  implementation(libs.okhttp)
  implementation(libs.retrofit)
  testImplementation(libs.androidx.compose.ui.test.junit4)
  testImplementation(libs.androidx.core)
  testImplementation(libs.androidx.junit)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
  testImplementation(libs.robolectric)
  androidTestImplementation(libs.androidx.espresso.core)
  androidTestImplementation(libs.androidx.runner)
  debugImplementation(libs.androidx.compose.ui.test.manifest)
  debugImplementation(libs.androidx.compose.ui.tooling)
}
