# E-Crew Agent - R8 rules.
#
# The agent has no reflection-based entry points beyond what the Android Gradle plugin
# already keeps. The accessibility service and the foreground service are declared in the
# manifest and therefore kept automatically.
#
# Tink (pulled in transitively by androidx.security:security-crypto for
# EncryptedSharedPreferences) references compile-time-only annotation classes that are not
# shipped inside the APK. They are never loaded at runtime; R8 only needs to stop treating
# their absence as an error.

-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn javax.annotation.concurrent.**
