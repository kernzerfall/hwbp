// SPDX-License-Identifier: EUPL-1.2

import java.net.HttpURLConnection
import java.net.URI
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.protobuf)
}

val rustAbis = listOf("arm64-v8a", "x86_64")
val minApi = 36

android {
    namespace = "k3r.hwbp"
    compileSdk = 37
    ndkVersion = "30.0.16248370"
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "k3r.hwbp"
        minSdk = minApi
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += rustAbis }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        compose = true
    }

    sourceSets {
        // Shared with the Rust crate.
        getByName("main") {
            ((this as ExtensionAware).extensions.getByName("proto") as SourceDirectorySet)
                .srcDir(rootProject.file("proto"))
        }
    }
}

protobuf {
    protoc { artifact = libs.protobuf.protoc.get().toString() }
    generateProtoTasks {
        all().configureEach {
            builtins {
                create("java") { option("lite") }
                create("kotlin") { option("lite") }
            }
        }
    }
}

/**
 * Downloads Google's attestation revocation list. Runs on every build so the
 * embedded snapshot is as fresh as the build. Fails the build if the download
 * fails; for offline builds pass -Phwbp.revocationStatus=/path/to/status.json.
 */
abstract class FetchRevocationStatus : DefaultTask() {
    @get:Input
    abstract val url: Property<String>

    @get:OutputFile
    abstract val output: RegularFileProperty

    init {
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun fetch() {
        val conn = URI(url.get()).toURL().openConnection() as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000
        conn.setRequestProperty("Cache-Control", "no-cache")
        try {
            if (conn.responseCode != 200) throw GradleException("GET ${url.get()}: HTTP ${conn.responseCode}")
            val body = conn.inputStream.use { it.readBytes() }
            if (!String(body).contains("\"entries\"")) throw GradleException("${url.get()}: unexpected response")
            // Only touch the file when the list changed, so cargo doesn't rebuild needlessly.
            val out = output.get().asFile
            if (!out.exists() || !out.readBytes().contentEquals(body)) out.writeBytes(body)
        } finally {
            conn.disconnect()
        }
    }
}

/**
 * Builds the Rust core with cargo-ndk and hands the resulting .so files to AGP
 * as a generated jniLibs source directory (one task per variant).
 */
abstract class CargoNdkBuild @Inject constructor(private val exec: ExecOperations) : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val crateDir: DirectoryProperty

    @get:Internal
    abstract val ndkDir: DirectoryProperty

    @get:Input
    abstract val cargo: Property<String>

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val platform: Property<Int>

    @get:Input
    abstract val release: Property<Boolean>

    /** Builds with `--no-default-features` when false (no chain verification). */
    @get:Input
    abstract val verifyChain: Property<Boolean>

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val revocationStatus: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun build() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        exec.exec {
            workingDir = crateDir.get().asFile
            val ndk = ndkDir.get().asFile.absolutePath
            environment("ANDROID_NDK_HOME", ndk)
            environment("ANDROID_NDK_ROOT", ndk)
            revocationStatus.orNull?.let { environment("HWBP_REVOCATION_STATUS", it.asFile.absolutePath) }
            commandLine(
                buildList {
                    add(cargo.get()); add("ndk")
                    abis.get().forEach { add("-t"); add(it) }
                    add("--platform"); add(platform.get().toString())
                    add("-o"); add(out.absolutePath)
                    add("build")
                    if (release.get()) add("--release")
                    if (!verifyChain.get()) add("--no-default-features")
                },
            )
        }
    }
}

/**
 * Generates third-party notices for the Rust crates linked into the .so with
 * cargo-about (rust/about.toml, rust/about.hbs). Shipped as assets/licenses/rust.html.
 */
abstract class CargoAbout @Inject constructor(private val exec: ExecOperations) : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Internal
    abstract val crateDir: DirectoryProperty

    @get:Input
    abstract val cargo: Property<String>

    @get:Input
    abstract val verifyChain: Property<Boolean>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val out = outputDir.get().asFile.resolve("licenses")
        out.deleteRecursively()
        out.mkdirs()
        exec.exec {
            workingDir = crateDir.get().asFile
            commandLine(
                buildList {
                    add(cargo.get()); add("about"); add("generate")
                    if (!verifyChain.get()) add("--no-default-features")
                    add("-o"); add(out.resolve("rust.html").absolutePath)
                    add("about.hbs")
                },
            )
        }
    }
}

// -Phwbp.verifyChain=false builds without attestation chain verification, for
// devices whose attestation root is not pinned in rust/data/roots.
val verifyChainEnabled = providers.gradleProperty("hwbp.verifyChain").map { it.toBoolean() }.orElse(true)
val localRevocationStatus: File? = providers.gradleProperty("hwbp.revocationStatus").orNull?.let(::file)

val fetchRevocationStatus = tasks.register<FetchRevocationStatus>("fetchRevocationStatus") {
    url.set("https://android.googleapis.com/attestation/status")
    output.set(layout.buildDirectory.file("attestation/status.json"))
}

val cargoAbout = tasks.register<CargoAbout>("cargoAbout") {
    val crate = rootProject.layout.projectDirectory.dir("rust")
    crateDir.set(crate)
    sources.from(crate.files("Cargo.toml", "Cargo.lock", "about.toml", "about.hbs"))
    cargo.set(providers.gradleProperty("hwbp.cargo").orElse("cargo"))
    verifyChain.set(verifyChainEnabled)
    outputDir.set(layout.buildDirectory.dir("generated/rustLicenses"))
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(cargoAbout, CargoAbout::outputDir)
        val crate = rootProject.layout.projectDirectory.dir("rust")
        val task = tasks.register<CargoNdkBuild>("cargoNdk${variant.name.replaceFirstChar(Char::titlecase)}") {
            crateDir.set(crate)
            sources.from(
                crate.files("Cargo.toml", "Cargo.lock", "build.rs"),
                crate.dir("src"),
                crate.dir("data"),
                rootProject.layout.projectDirectory.dir("proto"),
            )
            ndkDir.set(sdkComponents.ndkDirectory)
            cargo.set(providers.gradleProperty("hwbp.cargo").orElse("cargo"))
            abis.set(rustAbis)
            platform.set(minApi)
            release.set(variant.buildType != "debug")
            verifyChain.set(verifyChainEnabled)
            if (verifyChainEnabled.get()) {
                if (localRevocationStatus != null) {
                    revocationStatus.set(localRevocationStatus)
                } else {
                    revocationStatus.set(fetchRevocationStatus.flatMap { it.output })
                }
            }
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(task, CargoNdkBuild::outputDir)
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.credentials)
    implementation(libs.protobuf.kotlin.lite)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
