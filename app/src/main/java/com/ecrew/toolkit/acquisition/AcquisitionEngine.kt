package com.ecrew.toolkit.acquisition

import android.content.Context
import com.ecrew.toolkit.ioc.IocArtifact
import com.ecrew.toolkit.ioc.IocEngine
import com.ecrew.toolkit.ioc.IocScanResult
import com.ecrew.toolkit.ioc.Stix2Parser
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Sequential acquisition runner. Public modules are always in the registry; the privileged
 * module reports PARTIAL when the one-time DUMP grant is absent. Nothing in this engine
 * mutates device state. Output is a directory plus an AndroidQF-style ZIP.
 */
class AcquisitionEngine(private val context: Context) {
    private val running = AtomicBoolean(false)

    fun modules(includeApks: Boolean): List<QfModule> {
        val modules = mutableListOf<QfModule>(
            PackagesModule(context),
            SettingsModule(context),
            GetpropModule(context),
            NetworkStateModule(context),
            ContentResolverModule(context),
            FilesModule(context),
            PrivilegedModule(context)
        )
        if (includeApks) modules.add(ApkCopyModule(context))
        return modules
    }

    fun run(
        includeApks: Boolean,
        selectedIds: Set<String>? = null,
        progress: (String) -> Unit = {},
        extraBundleText: String? = null
    ): AcquisitionSession {
        if (!running.compareAndSet(false, true)) {
            throw AcquisitionException("an acquisition session is already running")
        }
        val startedAt = System.currentTimeMillis()
        val sessionId = UUID.randomUUID().toString()
        try {
            val root = File(context.filesDir, "acquisition")
            if (!root.isDirectory && !root.mkdirs()) {
                throw AcquisitionException("cannot create the acquisition root")
            }
            val directory = File(root, sessionId)
            val cache = File(context.cacheDir, "acquisition")
            if (!cache.isDirectory && !cache.mkdirs()) {
                throw AcquisitionException("cannot create the acquisition cache")
            }
            val writer = AndroidQfWriter(directory, cache)
            val results = ArrayList<AcquisitionModuleResult>()
            val requested = modules(includeApks).filter {
                selectedIds == null || it.id in selectedIds
            }
            for (module in requested) {
                progress("collecting ${module.label}...")
                val moduleStart = System.currentTimeMillis()
                val sink = ArtifactSink(writer)
                val output = try {
                    module.collect(sink)
                } catch (error: Exception) {
                    ModuleOutput(
                        ModuleStatus.FAILED,
                        sink.names(),
                        error.message ?: error.javaClass.simpleName
                    )
                }
                results.add(
                    AcquisitionModuleResult(
                        id = module.id,
                        label = module.label,
                        status = output.status,
                        startedAt = moduleStart,
                        finishedAt = System.currentTimeMillis(),
                        artifacts = output.artifacts,
                        error = output.error
                    )
                )
            }
            progress("finalizing archive...")
            val finishedAt = System.currentTimeMillis()
            val session = writer.finish(sessionId, startedAt, finishedAt, results)
            val ioc = scanIocs(session, extraBundleText)
            appendAudit(session, ioc)
            progress("acquisition complete: ${session.artifacts.size} artifacts")
            return session.copy(ioc = ioc)
        } finally {
            running.set(false)
        }
    }

    private fun scanIocs(session: AcquisitionSession, extraBundleText: String?): IocScanResult? {
        val artifacts = ArrayList<IocArtifact>()
        for (artifact in session.artifacts) {
            if (artifact.path.endsWith(".apk")) continue
            if (artifact.size > MAX_IOC_ARTIFACT) continue
            val file = File(session.directory, artifact.path)
            if (!file.isFile) continue
            try {
                artifacts.add(IocArtifact(artifact.path, file.readText(Charsets.UTF_8)))
            } catch (_: Exception) {
                // Binary or unreadable artifacts are skipped; the acquisition still succeeds.
            }
        }
        return try {
            val bundled = context.assets.open("ioc/ecrew-mini-bundle.json").use {
                it.readBytes().toString(Charsets.UTF_8)
            }
            val bundle = Stix2Parser.parse(bundled)
            val extra = if (extraBundleText.isNullOrBlank()) {
                null
            } else {
                Stix2Parser.parse(extraBundleText)
            }
            val combined = if (extra == null) bundle else bundle.copy(
                indicators = bundle.indicators + extra.indicators,
                skippedPatterns = bundle.skippedPatterns + extra.skippedPatterns
            )
            IocEngine.match(combined, artifacts)
        } catch (_: Exception) {
            null
        }
    }

    private fun appendAudit(session: AcquisitionSession, ioc: IocScanResult?) {
        try {
            val directory = File(context.filesDir, "audit/acquisition")
            if (!directory.isDirectory && !directory.mkdirs()) return
            val target = File(directory, session.id + ".jsonl")
            FileOutputStream(target, true).bufferedWriter().use { writer ->
                writer.write(
                    "{\"type\":\"acquisition_start\",\"session\":\"${session.id}\"," +
                        "\"at\":${session.startedAt}}\n"
                )
                for (module in session.modules) {
                    writer.write(
                        "{\"type\":\"module\",\"session\":\"${session.id}\"," +
                            "\"id\":\"${module.id}\",\"status\":\"${module.status.name}\"," +
                            "\"artifacts\":${module.artifacts.size}," +
                            "\"error\":${QfJson.quote(module.error)}}\n"
                    )
                }
                writer.write(
                    "{\"type\":\"acquisition_end\",\"session\":\"${session.id}\"," +
                        "\"at\":${session.finishedAt},\"artifacts\":${session.artifacts.size}," +
                        "\"ioc_matches\":${ioc?.matches?.size ?: 0}}\n"
                )
            }
        } catch (_: Exception) {
            // The acquisition result remains usable if the audit directory is unavailable.
        }
    }

    private companion object {
        const val MAX_IOC_ARTIFACT = 8L * 1024 * 1024
    }
}
