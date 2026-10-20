package com.ecrew.toolkit.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * Dark scheme mixing a semi-green (teal/mint) primary with blue secondary/tertiary accents
 * on a deep blue-green background. Semantic status colors used by screens (AccentGood /
 * AccentWarn / AccentBad / AccentInfo) stay independent of this palette.
 */
private val DarkColorScheme = darkColorScheme(
    // Semi-green primary: mint-teal, the "chat bubble / action" color.
    primary = Color(0xFF5FCFA8),
    onPrimary = Color(0xFF003828),
    primaryContainer = Color(0xFF12503F),
    onPrimaryContainer = Color(0xFFA8F2DA),

    // Blue secondary: selection pills, secondary buttons, supporting text accents.
    secondary = Color(0xFF6BB4F2),
    onSecondary = Color(0xFF003355),
    secondaryContainer = Color(0xFF173D5C),
    onSecondaryContainer = Color(0xFFCDE6FF),

    // Cyan bridge between the green and the blue.
    tertiary = Color(0xFF5BC8D6),
    onTertiary = Color(0xFF00363D),
    tertiaryContainer = Color(0xFF0E4A52),
    onTertiaryContainer = Color(0xFFB7ECF2),

    // Deep blue-green surfaces so the green/blue accents sit on a matching base.
    background = Color(0xFF0C1517),
    onBackground = Color(0xFFDCE5E2),
    surface = Color(0xFF0C1517),
    onSurface = Color(0xFFDCE5E2),
    surfaceVariant = Color(0xFF2B3A38),
    onSurfaceVariant = Color(0xFFB0C4BE),
    outline = Color(0xFF7C918C),

    // Errors keep the conventional red so failures stay unambiguous.
    error = Color(0xFFF2B8B5),
    onError = Color(0xFF601410),
    errorContainer = Color(0xFF8C1D18),
    onErrorContainer = Color(0xFFF9DEDC)
)

@Composable
fun ForensicToolkitTheme(
    content: @Composable () -> Unit
) {
    // Forced dark theme as per requirements; no light scheme exists.
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
