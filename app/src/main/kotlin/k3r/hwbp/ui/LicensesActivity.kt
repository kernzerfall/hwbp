// SPDX-License-Identifier: EUPL-1.2

package k3r.hwbp.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.viewinterop.AndroidView
import k3r.hwbp.R

/**
 * Shows the third-party notices bundled at build time: assets/licenses/android.html
 * (AboutLibraries) and assets/licenses/rust.html (cargo-about). JavaScript stays
 * disabled; links open externally, since HWBP itself has no network access.
 */
class LicensesActivity : ComponentActivity() {
    private companion object {
        val PAGES = listOf(
            "Android" to "file:///android_asset/licenses/android.html",
            "Rust" to "file:///android_asset/licenses/rust.html",
        )
    }

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            HwbpTheme {
                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = { Text("Open-source licenses") },
                            navigationIcon = {
                                IconButton(onClick = { finish() }) {
                                    Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = "Back")
                                }
                            },
                        )
                    },
                ) { padding ->
                    var tab by rememberSaveable { mutableIntStateOf(0) }
                    Column(Modifier.fillMaxSize().padding(padding)) {
                        PrimaryTabRow(selectedTabIndex = tab) {
                            PAGES.forEachIndexed { i, (label, _) ->
                                Tab(selected = tab == i, onClick = { tab = i }, text = { Text(label) })
                            }
                        }
                        AndroidView(
                            modifier = Modifier.fillMaxSize(),
                            update = { it.loadUrl(PAGES[tab].second) },
                            factory = { ctx ->
                                WebView(ctx).apply {
                                    settings.javaScriptEnabled = false
                                    settings.allowFileAccess = false
                                    settings.allowContentAccess = false
                                    webViewClient = object : WebViewClient() {
                                        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                                            val url = request.url
                                            if (url.scheme == "https") {
                                                try {
                                                    startActivity(Intent(Intent.ACTION_VIEW, url))
                                                } catch (_: ActivityNotFoundException) {
                                                }
                                            }
                                            // Never navigate inside the viewer; in-page anchors are handled by WebView.
                                            return true
                                        }
                                    }
                                }
                            },
                        )
                    }
                }
            }
        }
    }
}
