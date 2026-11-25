# Android and Burp extensions

Linux x86_64 remains the supported platform.

## Android APK

An Android build is feasible as a separate application. The Linux distribution depends on a Chromium executable, a browser extension with desktop window APIs, and Python processes for the backend. The APK would need an Android activity, an embedded browser engine, and Android ownership of application storage and lifecycle.

| Approach | What it offers | What to validate |
| --- | --- | --- |
| AndroidX WebView | Android-maintained browser embedding. `ProxyController` can direct the application's WebView requests through a proxy on devices with `PROXY_OVERRIDE`. | HTTPS trust restricted to the app, foreground/background transitions, and the device coverage of the proxy feature. |
| GeckoView | A browser engine bundled with the app and support for built-in WebExtensions. | Which browser APIs can be reused, touch navigation, and the cost of shipping and keeping the engine updated. |

See [WebView ProxyController](https://developer.android.com/reference/androidx/webkit/ProxyController), [Android network security configuration](https://developer.android.com/privacy-and-security/security-config), and [GeckoView WebExtensions](https://firefox-source-docs.mozilla.org/mobile/android/geckoview/consumer/web-extensions.html).

Start with browsing and recording the app's own traffic, then implement touch-friendly History and Inspector, offline Decoder and HAR export. Keep browser content isolated from the workspace and its app data. Use local HTTP and HTTPS fixtures to verify request fidelity, certificate errors, background/resume behavior, memory, and exports on an emulator and a physical ARM64 device. A standalone APK also needs a bundled, tested Android proxy runtime. Until that exists, desktop-connected and standalone prototypes have different capabilities. APK signing and updates need their own release process.

## Burp extensions

Burp extensions typically run in a JVM and invoke Burp's Montoya API. Extensions can depend on traffic models, event callbacks, persistence and desktop UI provided by Burp. GreyTab currently uses Chromium's extension APIs and a Python backend. Running existing JARs would require a compatible JVM host and sufficient Montoya behavior for each supported extension. See [Creating Burp extensions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating) and the [Montoya API reference](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/index.html).

GreyTab includes static JAR and BApp inspection and a native view pack interface for offline message formatting. See the [extension guide](EXTENSIONS.md) for the feature matrix, examples and verified workflows.
