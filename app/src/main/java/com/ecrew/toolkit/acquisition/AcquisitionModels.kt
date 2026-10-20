package com.ecrew.toolkit.acquisition

import com.ecrew.toolkit.ioc.IocScanResult
import java.io.File

enum class ModuleStatus { COMPLETED, PARTIAL, FAILED, SKIPPED }

data class AcquisitionModuleResult(
    val id: String,
    val label: String,
    val status: ModuleStatus,
    val startedAt: Long,
    val finishedAt: Long,
    val artifacts: List<String>,
    val error: String?
)

data class AcquisitionArtifact(
    val path: String,
    val size: Long,
    val sha256: String
)

data class AcquisitionSession(
    val id: String,
    val startedAt: Long,
    val finishedAt: Long,
    val directory: File,
    val archive: File,
    val modules: List<AcquisitionModuleResult>,
    val artifacts: List<AcquisitionArtifact>,
    val ioc: IocScanResult?
) {
    val completedCount: Int get() = modules.count { it.status == ModuleStatus.COMPLETED }
    val partialCount: Int get() = modules.count { it.status == ModuleStatus.PARTIAL }
    val failedCount: Int get() = modules.count { it.status == ModuleStatus.FAILED }
}

class AcquisitionException(message: String, cause: Throwable? = null) : Exception(message, cause)
