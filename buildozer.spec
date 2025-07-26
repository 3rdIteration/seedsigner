[app]
# (str) Title of your application
title = SeedSigner

# (str) Package name
package.name = seedsigner

# (str) Package domain (needed for android/ios packaging)
package.domain = org.seedsigner

# (str) Source code where the main.py live
source.dir = .

# (str) Application entry point
entrypoint = src/main.py

# (list) Application requirements
requirements = python3,kivy,opencv-python,Pillow

# (str) Supported orientation (portrait, landscape or all)
orientation = portrait

# (str) Android API to use
android.api = 33

# (str) Minimum API your APK will support
android.minapi = 21

# (str) Android NDK version to use
android.ndk = 25b

[buildozer]
log_level = 2
warn_on_root = 1
