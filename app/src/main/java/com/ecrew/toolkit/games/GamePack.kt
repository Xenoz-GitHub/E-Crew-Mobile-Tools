package com.ecrew.toolkit.games

/**
 * A third-party game that the Games Hub installs through
 * [android.content.pm.PackageInstaller] on first play. The APK can either be bundled in
 * the main APK's assets or chosen once by the user (see the Hub's import flow).
 *
 * The APK itself is deliberately left untouched: both games contain native runtimes
 * (Unity and Adobe AIR) that cannot be safely merged into the toolkit's process.
 */
data class GamePack(
    val id: String,
    val title: String,
    val assetName: String,
    val packageName: String,
    val launchActivity: String,
    val nativeAbis: List<String> = listOf("armeabi-v7a")
)

object GamePacks {
    val MobileLegacy = GamePack(
        id = "mobile-legacy",
        title = "Mobile Legacy",
        assetName = "mobile-legacy.apk",
        packageName = "com.kc.lfg",
        launchActivity = "com.trophit.MyUnityPlayerActivity"
    )

    val SwordsNinja = GamePack(
        id = "swords-ninja",
        title = "Swords Ninja",
        assetName = "swords-ninja.apk",
        packageName = "air.net.A5dplay.bleachvsnaruto",
        launchActivity = "air.net.A5dplay.bleachvsnaruto.AppEntry"
    )
}
