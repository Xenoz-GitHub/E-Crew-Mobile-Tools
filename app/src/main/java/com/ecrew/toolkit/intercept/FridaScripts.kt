package com.ecrew.toolkit.intercept

import java.io.File
import java.security.MessageDigest

data class GeneratedScript(
    val name: String,
    val file: File,
    val sha256: String
)

/**
 * Generates inert Frida scripts. The app never executes them and bundles no Frida server.
 * The header is present in every file so a script cannot be mistaken for a stock-device
 * bypass.
 */
object FridaScripts {
    const val CAVEAT =
        "// Running these scripts requires Frida server on a rooted device or a repackaged APK.\n" +
            "// They do nothing on a stock, non-rooted device.\n" +
            "// Authorized testing only. E-Crew does not install Frida, a CA or a repackaged app.\n"

    data class Template(val name: String, val body: String)

    val templates = listOf(
        Template(
            "okhttp_certificate_pinner.js",
            """
            // Hook OkHttp3 CertificatePinner so pinned chains are accepted during analysis.
            Java.perform(function () {
              try {
                var Pinner = Java.use("okhttp3.CertificatePinner");
                Pinner.check.overload("java.lang.String", "java.util.List").implementation =
                  function (host, chain) { return; };
                Pinner.check.overload("java.lang.String", "[java.security.cert.Certificate")
                  .implementation = function (host, chain) { return; };
              } catch (e) { console.log("OkHttp3 CertificatePinner hook unavailable: " + e); }
            });
            """.trimIndent()
        ),
        Template(
            "trustmanagerimpl_check.js",
            """
            // Hook the platform TrustManagerImpl checkServerTrusted path.
            Java.perform(function () {
              try {
                var TM = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                TM.checkServerTrusted.overload(
                  "[Ljava.security.cert.X509Certificate;",
                  "java.lang.String",
                  "java.lang.String",
                  "boolean",
                  "boolean",
                  "[byte]",
                  "[byte]"
                ).implementation = function () { return []; };
              } catch (e) { console.log("TrustManagerImpl hook unavailable: " + e); }
            });
            """.trimIndent()
        ),
        Template(
            "conscrypt_trustmanager.js",
            """
            // Broader Conscrypt TrustManagerImpl hooks, including the older overload.
            Java.perform(function () {
              var TM = Java.use("com.android.org.conscrypt.TrustManagerImpl");
              var overloads = TM.checkServerTrusted.overloads;
              for (var i = 0; i < overloads.length; i++) {
                overloads[i].implementation = function () { return []; };
              }
            });
            """.trimIndent()
        ),
        Template(
            "boringssl_verify.js",
            """
            // Hook BoringSSL's native chain verifier. Addresses differ by Android release.
            Java.perform(function () {
              try {
                var SSL = Java.use("com.android.org.conscrypt.NativeCrypto");
                SSL.SSL_verify_cert_chain.implementation = function () { return 1; };
              } catch (e) { console.log("NativeCrypto hook unavailable: " + e); }
            });
            Interceptor.attach(Module.findExportByName(null, "SSL_verify_cert_chain"), {
              onLeave: function (retval) { retval.replace(1); }
            });
            """.trimIndent()
        ),
        Template(
            "rootbeer_isrooted.js",
            """
            // Hook RootBeer so analysis tooling does not report a rooted test device.
            Java.perform(function () {
              try {
                var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
                RootBeer.isRooted.implementation = function () { return false; };
              } catch (e) { console.log("RootBeer hook unavailable: " + e); }
            });
            """.trimIndent()
        ),
        Template(
            "safetynet_basic_integrity.js",
            """
            // Hook Safety Net basic integrity responses. This does not forge a hardware attestation.
            Java.perform(function () {
              try {
                var Response = Java.use("com.google.android.gms.safetynet.SafetyNetApi");
                console.log("SafetyNet API present; hook the app's callback implementation.");
              } catch (e) { console.log("SafetyNet classes unavailable: " + e); }
            });
            """.trimIndent()
        ),
        Template(
            "file_exists_root_paths.js",
            """
            // Return false for common root-manager paths while the app performs file probes.
            Java.perform(function () {
              var File = Java.use("java.io.File");
              var blocked = ["/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
                "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
                "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
                "/su/bin/su", "/magisk/.core/bin/su"];
              File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                for (var i = 0; i < blocked.length; i++) {
                  if (path === blocked[i]) return false;
                }
                return this.exists();
              };
            });
            """.trimIndent()
        )
    )

    fun generate(directory: File): List<GeneratedScript> {
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw ProxyException("cannot create the Frida script directory")
        }
        return templates.map { template ->
            val file = File(directory, template.name)
            val text = CAVEAT + "\n" + template.body + "\n"
            file.writeText(text, Charsets.US_ASCII)
            GeneratedScript(template.name, file, sha256(text.toByteArray(Charsets.US_ASCII)))
        }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/** Display-only guides. No command is executed by the app. */
object PinningGuides {
    val repackaging = """
        User-executed repackaging path for an app you own or may test:
        1. apktool d target.apk -o target-src
        2. Create res/xml/network_security_config.xml that trusts the operator CA for the
           target domain. Do not ship this build to users.
        3. Reference android:networkSecurityConfig="@xml/network_security_config" in the
           application element of AndroidManifest.xml.
        4. apktool b target-src -o target-unsigned.apk
        5. zipalign -f 4 target-unsigned.apk target-aligned.apk
        6. apksigner sign --ks operator.jks --out target-signed.apk target-aligned.apk
        Repackaging breaks the original signature and updates. Service terms may prohibit it.
    """.trimIndent()

    val magisk = """
        Rooted-device pointer: the MagiskTrustUserCerts module can move a user CA into the
        system store for testing. E-Crew does not bundle, download or install Magisk or that
        module. Removing the module and the CA is the operator's responsibility.
    """.trimIndent()

    val manualCa = """
        Manual CA path (no bundled CA):
        1. Obtain the intercepting proxy CA from the operator's Burp/mitmproxy instance.
        2. Install it as a user CA in Settings > Security > Encryption and credentials.
        3. On Android 7+ most apps do not trust user CAs unless their network security config
           allows it. A stock app may still pin certificates.
        4. Remove the CA after testing. E-Crew never installs a CA automatically.
    """.trimIndent()

    val manualProxy = listOf(
        "Connect the phone and the interception host to the same trusted LAN.",
        "Start the local proxy, or keep using the PCAP module for passive evidence.",
        "Open Settings > Wi-Fi > the connected network > Modify network > Advanced options.",
        "Set Proxy to Manual and enter the interception host and port.",
        "Confirm a test request appears in Burp/mitmproxy before testing the target app.",
        "Remove the proxy setting when finished; otherwise all apps keep using it."
    )

    val caveat = "SSL pinning bypass is impossible on a completely stock, non-rooted device " +
        "without Frida (root or repackaged app) or APK repackaging. The in-app proxy does " +
        "not terminate TLS and cannot decrypt HTTPS by itself."
}
