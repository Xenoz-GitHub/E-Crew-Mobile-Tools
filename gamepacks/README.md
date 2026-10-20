# Local game packs

This directory is optional. It lets a locally built APK ship game packs inside
`assets/` without putting third-party APK binaries in Git.

Expected names:

- `mobile-legacy.apk` — first Games Hub pack
- `swords-ninja.apk` — second Games Hub pack

The `.apk` files here are ignored by Git and are not part of the public source
tree. They are streamed into Android's `PackageInstaller` on first play; the
Games Hub then launches the installed package.

Android requires the device user to confirm package installation. A normal
sideloaded application cannot silently install another APK. The Hub therefore
opens the system installer once per pack, then launches the game after success.

Only add APK files here when you have the right to install and redistribute
them. Public release builds should omit this directory unless redistribution
permission has been obtained from the game owners.
