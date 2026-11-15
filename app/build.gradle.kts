// SPDX-License-Identifier: EUPL-1.2

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.util.Properties
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.protobuf)
    alias(libs.plugins.aboutlibraries)
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
        ndk { abiFilters.addAll(rustAbis) }
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

/**
 * Renders the AboutLibraries export to licenses/android.html. Libraries are grouped by
 * license. For groups listed in app/license-overrides.properties, the project's own license
 * text (needed where it carries the project's copyright line, e.g. BSD) is fetched from the
 * given URL on every build instead of using the generic SPDX text. If the fetch fails, the
 * page says so and the build warns.
 */
abstract class AndroidLicensesHtml : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val definitions: RegularFileProperty

    /** Lines of `<maven group>=<library version> <license URL>`. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val overrides: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    init {
        // Re-fetch override texts on every build.
        outputs.upToDateWhen { false }
    }

    private fun fetch(url: String): String? = try {
        val conn = URI(url).toURL().openConnection() as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000
        try {
            if (conn.responseCode == 200) conn.inputStream.use { String(it.readBytes()) }.takeIf { it.isNotBlank() } else null
        } finally {
            conn.disconnect()
        }
    } catch (e: IOException) {
        null
    }

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    @TaskAction
    @Suppress("UNCHECKED_CAST")
    fun render() {
        val json = groovy.json.JsonSlurper().parse(definitions.get().asFile) as Map<String, Any?>
        val libraries = json["libraries"] as List<Map<String, Any?>>
        val licenses = json["licenses"] as Map<String, Map<String, Any?>>
        val props = Properties().apply { overrides.get().asFile.reader().use(::load) }
        val overrideTexts = props.stringPropertyNames().associateWith { group ->
            val (pinnedVersion, url) = props.getProperty(group).trim().split(Regex("\\s+"), limit = 2)
                .takeIf { it.size == 2 } ?: throw GradleException("license-overrides: '$group' needs '<version> <url>'")
            libraries.filter { (it["uniqueId"] as String).substringBefore(':') == group }
                .mapNotNull { it["artifactVersion"] as? String }.toSet()
                .filter { it != pinnedVersion }
                .forEach { logger.warn("license-overrides: $group is at $it but the license URL is pinned for $pinnedVersion") }
            fetch(url) ?: "failed to fetch $url".also { logger.warn("license-overrides: $it") }
        }

        // section key -> (title, text, libraries)
        data class Section(val title: String, val text: String, val libs: MutableList<Map<String, Any?>> = mutableListOf())
        val sections = linkedMapOf<String, Section>()
        for (lib in libraries.sortedBy { (it["name"] as? String ?: it["uniqueId"] as String).lowercase() }) {
            val group = (lib["uniqueId"] as String).substringBefore(':')
            for (id in lib["licenses"] as List<String>) {
                val lic = licenses[id] ?: throw GradleException("no license text for $id")
                val override = overrideTexts[group]
                val key = if (override != null) "$id/$group" else id
                val title = (lic["name"] as? String ?: id) + if (override != null) " ($group)" else ""
                val text = override ?: (lic["content"] as? String)?.takeIf { it.isNotBlank() }
                    ?: throw GradleException("license $id has no text; check offlineMode/network")
                sections.getOrPut(key) { Section(title, text) }.libs += lib
            }
        }

        val html = buildString {
            append("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n")
            append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
            append("<title>Third-party licenses (Android)</title>\n<style>\n")
            append("  body { font-family: sans-serif; margin: 16px; }\n")
            append("  pre { white-space: pre-wrap; font-size: 12px; background: #f4f4f4; padding: 8px; }\n")
            append("  @media (prefers-color-scheme: dark) { body { background: #111; color: #ddd; } pre { background: #222; } a { color: #8cf; } }\n")
            append("</style>\n</head>\n<body>\n<h1>Third-party licenses (Android)</h1>\n")
            append("<p>Android and Kotlin libraries bundled in the app.</p>\n<ul>\n")
            sections.entries.forEachIndexed { i, (_, sec) ->
                append("  <li><a href=\"#l$i\">${esc(sec.title)}</a> (${sec.libs.size})</li>\n")
            }
            append("</ul>\n")
            sections.entries.forEachIndexed { i, (_, sec) ->
                append("<h2 id=\"l$i\">${esc(sec.title)}</h2>\n<ul>\n")
                for (lib in sec.libs) {
                    val name = lib["name"] as? String ?: lib["uniqueId"] as String
                    val url = (lib["website"] as? String) ?: ((lib["scm"] as? Map<String, Any?>)?.get("url") as? String)
                    val label = esc("$name ${lib["artifactVersion"] ?: ""}".trim())
                    append(if (url != null) "  <li><a href=\"${esc(url)}\">$label</a> <small>${esc(lib["uniqueId"] as String)}</small></li>\n"
                           else "  <li>$label <small>${esc(lib["uniqueId"] as String)}</small></li>\n")
                }
                append("</ul>\n<pre>${esc(sec.text)}</pre>\n")
            }
            append("</body>\n</html>\n")
        }
        val out = outputDir.get().asFile.resolve("licenses")
        out.deleteRecursively()
        out.mkdirs()
        out.resolve("android.html").writeText(html)
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

// Android/Kotlin library metadata + license texts (AboutLibraries), rendered to
// licenses/android.html by androidLicensesHtml below.
aboutLibraries {
    // Pulls SPDX license texts; builds already need network for the revocation list.
    offlineMode = false
    collect {
        filterVariants.add("release")
        includePlatform = false // BOMs ship no code
    }
    export {
        outputFile = layout.buildDirectory.file("generated/aboutLibraries/aboutlibraries.json").get().asFile
        variant = "release"
    }
    license {
        // Fail the build if a dependency under any other license appears.
        strictMode = com.mikepenz.aboutlibraries.plugin.StrictMode.FAIL
        allowedLicenses.addAll("Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "MIT")
    }
}

val androidLicensesHtml = tasks.register<AndroidLicensesHtml>("androidLicensesHtml") {
    dependsOn("exportLibraryDefinitions")
    definitions.set(layout.buildDirectory.file("generated/aboutLibraries/aboutlibraries.json"))
    overrides.set(layout.projectDirectory.file("license-overrides.properties"))
    outputDir.set(layout.buildDirectory.dir("generated/androidLicenses"))
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
        variant.sources.assets?.addGeneratedSourceDirectory(androidLicensesHtml, AndroidLicensesHtml::outputDir)
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
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.credentials)
    implementation(libs.protobuf.kotlin.lite)
}
