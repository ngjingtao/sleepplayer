package dev.remiband.sleep

import android.content.Context
import android.os.SystemClock
import androidx.health.connect.client.HealthConnectClient
import androidx.health.connect.client.permission.HealthPermission
import androidx.health.connect.client.records.HeartRateRecord
import androidx.health.connect.client.request.ReadRecordsRequest
import androidx.health.connect.client.time.TimeRangeFilter
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * Heart rate from the phone's health store, instead of from the band.
 *
 * Why this is the preferred source when it works: no BLE connection, no
 * protocol work, no fighting Mi Fitness over the radio. Whatever writes to
 * Health Connect -- Mi Fitness, Google Fit, another band's app -- becomes the
 * source automatically.
 *
 * Why it is not always usable:
 *
 *  * records arrive in **batches**, so the newest sample can be minutes old;
 *  * the user has to grant read permission inside the Health Connect app;
 *  * Mi Fitness must actually be writing heart rate there, which is unverified
 *    on this device.
 *
 * That last point is the reason [describe] exists: it reports what is really in
 * the store, with the originating package name, so the question "is there
 * anything here at all?" is answerable in one tap instead of by inference.
 *
 * Timestamps are converted from wall clock to `elapsedRealtime` before the
 * detector sees them. The detector reasons in a monotonic timeline; feeding it
 * wall-clock milliseconds would make every window comparison meaningless.
 */
class HealthConnectSource(private val context: Context) {

    data class Sample(
        val elapsedMs: Long,
        val wallMs: Long,
        val bpm: Int,
        val origin: String,
    )

    companion object {
        /**
         * Packages that may host Health Connect's data provider.
         *
         * The AndroidX client defaults to the Play Store app's package. Android
         * 14 ships Health Connect as a system module under a different name, so
         * that default resolves to nothing and the permission UI never opens --
         * the request returns an empty set in milliseconds, with no prompt.
         */
        val CANDIDATE_PACKAGES = listOf(
            "com.android.healthfitness",
            "com.google.android.apps.healthdata",
            "com.android.healthconnect.controller",
        )

        /** The first candidate the platform agrees is an available provider. */
        fun detectProviderPackage(context: Context): String? =
            CANDIDATE_PACKAGES.firstOrNull { pkg ->
                runCatching {
                    HealthConnectClient.getSdkStatus(context, pkg) ==
                        HealthConnectClient.SDK_AVAILABLE
                }.getOrDefault(false)
            }

        /** Every candidate with its status, for the log when detection fails. */
        fun describeCandidates(context: Context): String = CANDIDATE_PACKAGES.joinToString(", ") {
            val st = runCatching { HealthConnectClient.getSdkStatus(context, it) }.getOrNull()
            val name = when (st) {
                HealthConnectClient.SDK_AVAILABLE -> "available"
                HealthConnectClient.SDK_UNAVAILABLE -> "unavailable"
                HealthConnectClient.SDK_UNAVAILABLE_PROVIDER_UPDATE_REQUIRED -> "needs-update"
                else -> "status=$st"
            }
            "$it=$name"
        }
    }

    val readPermission: String = HealthPermission.getReadPermission(HeartRateRecord::class)

    private var client: HealthConnectClient? = null
    private var cursorWallMs = 0L

    /** HealthConnectClient.SDK_AVAILABLE / SDK_UNAVAILABLE / ..._UPDATE_REQUIRED. */
    fun status(): Int = HealthConnectClient.getSdkStatus(context)

    fun available(): Boolean = status() == HealthConnectClient.SDK_AVAILABLE

    private fun client(): HealthConnectClient =
        client ?: HealthConnectClient.getOrCreate(context).also { client = it }

    suspend fun hasPermission(): Boolean {
        if (!available()) return false
        return try {
            client().permissionController.getGrantedPermissions().contains(readPermission)
        } catch (t: Throwable) {
            false
        }
    }

    /**
     * Samples from the last [lookbackMinutes], oldest first.
     *
     * When [advanceCursor] is true, only samples newer than the previous call
     * are returned -- that is the polling path, so the same record is not fed
     * to the detector twice. The inspection path passes false so it can report
     * what is there regardless of earlier reads.
     */
    suspend fun readRecent(
        lookbackMinutes: Long = 10,
        advanceCursor: Boolean = true,
    ): List<Sample> {
        if (!available()) return emptyList()

        val nowWall = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()
        val from = Instant.now().minus(lookbackMinutes, ChronoUnit.MINUTES)

        val response = client().readRecords(
            ReadRecordsRequest(
                recordType = HeartRateRecord::class,
                timeRangeFilter = TimeRangeFilter.between(from, Instant.now()),
            )
        )

        val found = ArrayList<Sample>()
        for (record in response.records) {
            val origin = record.metadata.dataOrigin.packageName
            for (sample in record.samples) {
                val wall = sample.time.toEpochMilli()
                if (advanceCursor && wall <= cursorWallMs) continue
                val bpm = sample.beatsPerMinute.toInt()
                if (bpm !in 25..250) continue
                found.add(
                    Sample(
                        elapsedMs = nowElapsed - (nowWall - wall),
                        wallMs = wall,
                        bpm = bpm,
                        origin = origin,
                    )
                )
            }
        }
        found.sortBy { it.wallMs }
        if (advanceCursor) {
            found.lastOrNull()?.let { cursorWallMs = maxOf(cursorWallMs, it.wallMs) }
        }
        return found
    }

    fun resetCursor() {
        cursorWallMs = 0L
    }

    /** One-paragraph answer to "is there any heart rate in here?". */
    suspend fun describe(): String {
        val st = status()
        if (st != HealthConnectClient.SDK_AVAILABLE) {
            return when (st) {
                HealthConnectClient.SDK_UNAVAILABLE ->
                    "Health Connect is not available on this device"
                else ->
                    "Health Connect needs an update (status $st)"
            }
        }
        val granted = hasPermission()
        if (!granted) {
            return "Health Connect is present, but read permission is not granted " +
                "($readPermission). Grant it in the Health Connect app."
        }
        val day = readRecent(lookbackMinutes = 24 * 60, advanceCursor = false)
        if (day.isEmpty()) {
            return "Permission granted, but there are NO heart-rate records in the " +
                "last 24h. Whatever is supposed to write them is not doing it."
        }
        val newest = day.last()
        val ageMinutes = (System.currentTimeMillis() - newest.wallMs) / 60_000
        val origins = day.map { it.origin }.distinct().joinToString(", ")
        return "${day.size} samples in the last 24h; newest ${newest.bpm} bpm " +
            "${ageMinutes} min ago; written by: $origins"
    }
}
