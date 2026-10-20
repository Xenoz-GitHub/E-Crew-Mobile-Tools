package com.ecrew.toolkit.apk

enum class Severity(val rank: Int) {
    CRITICAL(4),
    HIGH(3),
    MEDIUM(2),
    LOW(1),
    INFO(0);

    fun lower(): Severity = when (this) {
        CRITICAL -> HIGH
        HIGH -> MEDIUM
        MEDIUM -> LOW
        LOW -> INFO
        INFO -> INFO
    }
}

enum class FindingSource(val order: Int, val label: String) {
    MANIFEST(0, "Manifest"),
    SECRET(1, "Secret"),
    NATIVE(2, "Native"),
    FLUTTER(3, "Flutter"),
    FILE_PROVIDER(4, "FileProvider"),
    SIGNING(5, "Signing")
}

data class Finding(
    val id: String,
    val severity: Severity,
    val title: String,
    val evidence: String,
    val source: FindingSource,
    val componentRef: String? = null
)

/**
 * Converts facts and scanner results into one de-duplicated, severity-ranked list.
 * Secret values are never accepted here; scanners supply only redacted previews and hashes.
 */
object FindingEngine {
    private val dangerousPermissions = setOf(
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.BODY_SENSORS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES"
    )

    fun fromManifest(facts: ApkManifestFacts): List<Finding> {
        val findings = ArrayList<Finding>()
        if (facts.application.debuggable == true) {
            findings.add(
                Finding(
                    id = "app_debuggable",
                    severity = Severity.HIGH,
                    title = "Application is debuggable",
                    evidence = "android:debuggable=true lets a debugger attach to the process",
                    source = FindingSource.MANIFEST
                )
            )
        }
        if (facts.application.allowBackup != false) {
            val value = facts.application.allowBackup?.toString()
                ?: "not set (platform default true)"
            findings.add(
                Finding(
                    id = "app_backup_allowed",
                    severity = Severity.MEDIUM,
                    title = "Application backup is allowed",
                    evidence = "android:allowBackup=$value",
                    source = FindingSource.MANIFEST
                )
            )
        }
        val cleartext = facts.application.usesCleartextTraffic
        when {
            cleartext == true -> findings.add(
                Finding(
                    id = "app_cleartext",
                    severity = Severity.HIGH,
                    title = "Cleartext traffic permitted",
                    evidence = "android:usesCleartextTraffic=true",
                    source = FindingSource.MANIFEST
                )
            )

            cleartext == null && facts.effectiveTargetSdk <= 27 -> findings.add(
                Finding(
                    id = "app_cleartext_default",
                    severity = Severity.MEDIUM,
                    title = "Cleartext traffic permitted by platform default",
                    evidence = "usesCleartextTraffic is not set and targetSdk is " +
                        facts.effectiveTargetSdk,
                    source = FindingSource.MANIFEST
                )
            )
        }
        if (facts.application.testOnly == true) {
            findings.add(
                Finding(
                    id = "app_test_only",
                    severity = Severity.INFO,
                    title = "Application is marked testOnly",
                    evidence = "android:testOnly=true",
                    source = FindingSource.MANIFEST
                )
            )
        }
        val target = facts.effectiveTargetSdk
        if (target < 28) {
            findings.add(
                Finding(
                    id = "sdk_target_outdated",
                    severity = Severity.MEDIUM,
                    title = "Target SDK is below 28",
                    evidence = "targetSdk=$target; newer platform behavior changes are not opted in",
                    source = FindingSource.MANIFEST
                )
            )
        }
        if (facts.minSdk != null && facts.targetSdk != null && facts.minSdk > facts.targetSdk) {
            findings.add(
                Finding(
                    id = "sdk_range_invalid",
                    severity = Severity.HIGH,
                    title = "Invalid SDK range",
                    evidence = "minSdk=${facts.minSdk} is greater than targetSdk=${facts.targetSdk}",
                    source = FindingSource.MANIFEST
                )
            )
        }
        for (permission in facts.permissions) {
            if (dangerousPermissions.contains(permission)) {
                val severity = when (permission) {
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_SMS" -> Severity.MEDIUM

                    else -> Severity.LOW
                }
                findings.add(
                    Finding(
                        id = "dangerous_permission:" + permission.substringAfterLast('.'),
                        severity = severity,
                        title = "Dangerous permission: " + permission.substringAfterLast('.'),
                        evidence = permission,
                        source = FindingSource.MANIFEST
                    )
                )
            }
        }
        permissionCombos(facts.permissions).forEach { combo ->
            findings.add(
                Finding(
                    id = "permission_combo:" + combo.id,
                    severity = combo.severity,
                    title = combo.title,
                    evidence = combo.permissions.joinToString(", "),
                    source = FindingSource.MANIFEST
                )
            )
        }
        if (facts.application.enabled) {
            for (component in facts.components) {
                if (!component.enabled) continue
                if (component.exported) {
                    findings.add(exportedComponentFinding(facts, component))
                }
                accessibilityFinding(component)?.let { findings.add(it) }
                deviceAdminFinding(component)?.let { findings.add(it) }
                notificationListenerFinding(component)?.let { findings.add(it) }
                vpnServiceFinding(component)?.let { findings.add(it) }
            }
        }
        return merge(findings)
    }

    fun fromSecrets(result: SecretScanResult): List<Finding> {
        val findings = ArrayList<Finding>()
        for (match in result.matches) {
            if (match.kind == "URL") continue
            findings.add(
                Finding(
                    id = "secret:${match.ruleId}:${match.sha256.take(16)}",
                    severity = match.severity,
                    title = "Possible ${match.kind}",
                    evidence = "${match.redacted} at ${match.location}" +
                        (match.context?.let { " ($it)" } ?: "") +
                        " [sha256 ${match.sha256.take(16)}]",
                    source = FindingSource.SECRET,
                    componentRef = match.context ?: match.location
                )
            )
        }
        return merge(findings)
    }

    fun fromNative(result: NativeScanResult): List<Finding> {
        val findings = result.threats.map { threat ->
            Finding(
                id = "native:${threat.ruleId}:${threat.libraryPath}",
                severity = threat.severity,
                title = threat.title,
                evidence = "${threat.preview} in ${threat.libraryPath}",
                source = FindingSource.NATIVE,
                componentRef = threat.libraryPath
            )
        }
        return merge(findings)
    }

    fun fromFlutter(facts: FlutterFacts): List<Finding> {
        val findings = ArrayList<Finding>()
        if (facts.present) {
            findings.add(
                Finding(
                    id = "flutter_detected",
                    severity = Severity.INFO,
                    title = "Flutter application",
                    evidence = "libflutter.so detected" +
                        (facts.enginePath?.let { " at $it" } ?: ""),
                    source = FindingSource.FLUTTER
                )
            )
        }
        for (bridge in facts.bridges) {
            findings.add(
                Finding(
                    id = "flutter_bridge:${bridge.id}",
                    severity = bridge.severity,
                    title = bridge.title,
                    evidence = bridge.evidence,
                    source = FindingSource.FLUTTER
                )
            )
        }
        return merge(findings)
    }

    fun fromFileProviders(scan: FileProviderScan): List<Finding> =
        scan.configs.map { config ->
            val worst = config.rules.maxByOrNull { it.severity.rank } ?: config.rules.first()
            Finding(
                id = "file_provider_paths",
                severity = config.severity,
                title = "Permissive FileProvider path configuration",
                evidence = "${config.resourceName}: ${worst.type} " +
                    "name=${worst.name} path=${worst.path.ifBlank { "<root>" }}",
                source = FindingSource.FILE_PROVIDER,
                componentRef = config.resourceName
            )
        }.let { merge(it) }

    fun fromSigning(
        info: ApkSigningInfo,
        now: Long = System.currentTimeMillis()
    ): List<Finding> {
        val findings = ArrayList<Finding>()
        if (!info.v1 && !info.v2 && !info.v3) {
            findings.add(
                Finding(
                    id = "signing_no_schemes",
                    severity = Severity.INFO,
                    title = "No APK signature scheme detected",
                    evidence = "${info.source}; APK may be unsigned or unreadable",
                    source = FindingSource.SIGNING
                )
            )
        } else if (info.v1 && !info.v2 && !info.v3) {
            findings.add(
                Finding(
                    id = "signing_v1_only",
                    severity = Severity.MEDIUM,
                    title = "Only v1 JAR signing detected",
                    evidence = "${info.source}; v2/v3 signing blocks are absent",
                    source = FindingSource.SIGNING
                )
            )
        }
        if ((info.v1 || info.v2 || info.v3) && info.certificates.isEmpty()) {
            findings.add(
                Finding(
                    id = "signing_no_certificates",
                    severity = Severity.MEDIUM,
                    title = "Signature present but certificates unreadable",
                    evidence = "${info.source}; scheme presence was detected without certificate data",
                    source = FindingSource.SIGNING
                )
            )
        }
        for (certificate in info.certificates) {
            val certificateRef = certificate.sha256.take(16)
            if (certificate.subject.contains("CN=Android Debug")) {
                findings.add(
                    Finding(
                        id = "signing_debug_certificate:$certificateRef",
                        severity = Severity.HIGH,
                        title = "Debug signing certificate",
                        evidence = "${certificate.subject} [sha256 $certificateRef]",
                        source = FindingSource.SIGNING,
                        componentRef = certificateRef
                    )
                )
            }
            if (certificate.notAfter < now) {
                findings.add(
                    Finding(
                        id = "signing_expired_certificate:$certificateRef",
                        severity = Severity.MEDIUM,
                        title = "Signing certificate is expired",
                        evidence = "${certificate.subject}; expired ${certificate.notAfter}",
                        source = FindingSource.SIGNING,
                        componentRef = certificateRef
                    )
                )
            }
            val algorithm = certificate.signatureAlgorithm.uppercase()
            if (algorithm.startsWith("MD5")) {
                findings.add(
                    Finding(
                        id = "signing_weak_algorithm:$certificateRef",
                        severity = Severity.HIGH,
                        title = "Weak certificate signature algorithm",
                        evidence = "${certificate.signatureAlgorithm} [sha256 $certificateRef]",
                        source = FindingSource.SIGNING,
                        componentRef = certificateRef
                    )
                )
            } else if (algorithm.startsWith("SHA1")) {
                findings.add(
                    Finding(
                        id = "signing_weak_algorithm:$certificateRef",
                        severity = Severity.MEDIUM,
                        title = "Legacy certificate signature algorithm",
                        evidence = "${certificate.signatureAlgorithm} [sha256 $certificateRef]",
                        source = FindingSource.SIGNING,
                        componentRef = certificateRef
                    )
                )
            }
        }
        for (warning in info.warnings.distinct()) {
            findings.add(
                Finding(
                    id = "signing_warning",
                    severity = Severity.INFO,
                    title = "Signing metadata warning",
                    evidence = warning,
                    source = FindingSource.SIGNING,
                    componentRef = warning
                )
            )
        }
        return merge(findings)
    }

    fun merge(findings: List<Finding>): List<Finding> {
        val byKey = LinkedHashMap<String, Finding>()
        for (finding in findings) {
            val key = finding.id + "|" + (finding.componentRef ?: "")
            val existing = byKey[key]
            if (existing == null || finding.severity.rank > existing.severity.rank) {
                byKey[key] = finding
            }
        }
        return byKey.values.sortedWith(
            compareByDescending<Finding> { it.severity.rank }
                .thenBy { it.source.order }
                .thenBy { it.id }
                .thenBy { it.componentRef ?: "" }
        )
    }

    private fun exportedComponentFinding(
        facts: ApkManifestFacts,
        component: ComponentFacts
    ): Finding {
        val base = when (component.kind) {
            ComponentKind.PROVIDER ->
                if (component.grantUriPermissions) Severity.CRITICAL else Severity.HIGH
            ComponentKind.SERVICE -> Severity.HIGH
            ComponentKind.RECEIVER -> Severity.HIGH
            ComponentKind.ACTIVITY -> Severity.MEDIUM
        }
        val effectivePermission = component.permission ?: facts.application.permission
        var severity = base
        if (effectivePermission != null) {
            severity = severity.lower()
        }
        val exportLabel = when (component.exportKind) {
            ExportKind.EXPLICIT_EXPORTED -> "explicit"
            ExportKind.IMPLICIT_EXPORTED -> "implicit (android:exported absent)"
            ExportKind.EXPLICIT_NOT_EXPORTED -> "not exported"
            ExportKind.DEFAULT_NOT_EXPORTED -> "default not exported"
        }
        val filters = component.intentFilters.flatMap { it.actions }.distinct()
        val evidence = buildString {
            append(component.name)
            append("; export=").append(exportLabel)
            append("; permission=").append(effectivePermission ?: "none")
            if (filters.isNotEmpty()) {
                append("; actions=").append(filters.joinToString(",").take(160))
            }
            if (component.grantUriPermissions) append("; grantUriPermissions=true")
        }
        return Finding(
            id = "exported_" + component.kind.tag,
            severity = severity,
            title = "Exported " + component.kind.tag,
            evidence = evidence,
            source = FindingSource.MANIFEST,
            componentRef = component.name
        )
    }

    private fun accessibilityFinding(component: ComponentFacts): Finding? {
        if (component.kind != ComponentKind.SERVICE) return null
        val action = component.intentFilters.any {
            it.actions.contains("android.accessibilityservice.AccessibilityService")
        }
        val bind = component.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
        if (!action && !bind) return null
        return Finding(
            id = "accessibility_service",
            severity = Severity.HIGH,
            title = "Accessibility service",
            evidence = component.name + " can observe and control the UI",
            source = FindingSource.MANIFEST,
            componentRef = component.name
        )
    }

    private fun deviceAdminFinding(component: ComponentFacts): Finding? {
        if (component.kind != ComponentKind.RECEIVER) return null
        val action = component.intentFilters.any {
            it.actions.contains("android.app.action.DEVICE_ADMIN_ENABLED")
        }
        if (!action) return null
        return Finding(
            id = "device_admin_receiver",
            severity = Severity.HIGH,
            title = "Device administration receiver",
            evidence = component.name,
            source = FindingSource.MANIFEST,
            componentRef = component.name
        )
    }

    private fun notificationListenerFinding(component: ComponentFacts): Finding? {
        if (component.kind != ComponentKind.SERVICE) return null
        if (component.permission != "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE") {
            return null
        }
        return Finding(
            id = "notification_listener",
            severity = Severity.HIGH,
            title = "Notification listener service",
            evidence = component.name + " can read notifications",
            source = FindingSource.MANIFEST,
            componentRef = component.name
        )
    }

    private fun vpnServiceFinding(component: ComponentFacts): Finding? {
        if (component.kind != ComponentKind.SERVICE) return null
        if (component.permission != "android.permission.BIND_VPN_SERVICE") return null
        return Finding(
            id = "vpn_service",
            severity = Severity.MEDIUM,
            title = "VPN service",
            evidence = component.name + " can establish a VPN interface",
            source = FindingSource.MANIFEST,
            componentRef = component.name
        )
    }

    private fun permissionCombos(permissions: List<String>): List<PermissionCombo> {
        val result = ArrayList<PermissionCombo>()
        if (permissions.any { it.contains("SMS") } && permissions.contains(
                "android.permission.READ_CONTACTS"
            )
        ) {
            result.add(
                PermissionCombo(
                    "sms_contacts",
                    Severity.HIGH,
                    "SMS and contacts access together",
                    listOf("SMS", "READ_CONTACTS")
                )
            )
        }
        if (permissions.contains("android.permission.CAMERA") &&
            permissions.contains("android.permission.RECORD_AUDIO")
        ) {
            result.add(
                PermissionCombo(
                    "camera_microphone",
                    Severity.MEDIUM,
                    "Camera and microphone access together",
                    listOf("CAMERA", "RECORD_AUDIO")
                )
            )
        }
        if (permissions.contains("android.permission.ACCESS_FINE_LOCATION") &&
            permissions.contains("android.permission.ACCESS_BACKGROUND_LOCATION")
        ) {
            result.add(
                PermissionCombo(
                    "background_location",
                    Severity.HIGH,
                    "Background location access",
                    listOf("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION")
                )
            )
        }
        if (permissions.contains("android.permission.SYSTEM_ALERT_WINDOW") &&
            permissions.contains("android.permission.REQUEST_INSTALL_PACKAGES")
        ) {
            result.add(
                PermissionCombo(
                    "overlay_installer",
                    Severity.HIGH,
                    "Overlay and package installer access together",
                    listOf("SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES")
                )
            )
        }
        return result
    }

    private data class PermissionCombo(
        val id: String,
        val severity: Severity,
        val title: String,
        val permissions: List<String>
    )
}
