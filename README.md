# 📋 ClipClop - Secure Clipboard Sync 🐎🔒

<p align="center">
  <img src="https://media1.tenor.com/m/a-dKVjzm5QwAAAAC/foto.gif" alt="Running Horse">
</p>

Welcome to **ClipClop**, the magical (and now secure!) clipboard synchronization tool that makes your Mac and Android devices share clipboards like they're best friends at a sleepover!

## 🤔 What is ClipClop?

Ever copied something on your Mac and wished you could paste it on your Android phone? Or vice versa? ClipClop is here to make that dream come true! It's like having a clipboard that gallops between your devices faster than you can say "copy-paste"! 

ClipClop synchronizes your clipboard content (text AND images!) between your macOS computer and Android devices over your local Wi-Fi network. No cloud services, no data harvesting, just pure local magic! ✨

## 🌟 Features

- 🔄 **Real-time sync**: Copy on Mac, paste on Android (and vice versa!)
- 🖼️ **Image support**: Yes, it handles images too! Screenshots, photos, memes - you name it!
- 🔒 **End-to-End Encryption**: Uses military-grade AES-256 GCM encryption. Your data is safe even on public Wi-Fi.
- 📱 **QR Code Pairing**: Instantly connect your phone by scanning a QR code.
- 🍎 **Native macOS menu bar app**: Lives quietly in your menu bar (no Dock icon, no Alt-Tab presence).
- ⚡ **Efficient**: Uses native macOS events for zero-lag sync and minimal battery usage.
- 🎯 **Zero configuration**: Just run it, scan the QR code, and you're done!

## 🚀 Quick Start

1.  **Run ClipClop** on your Mac (either the `.app` or install the `.pkg`).
2.  Click the menu bar icon (🐴) and select **"Connect Mobile"**.
3.  **Scan the QR code** with the ClipClop Android app.
4.  **Start copying and pasting** like a clipboard wizard! 🧙‍♂️

## 🛠️ Building Your Own Package

Want to create your own `.pkg` installer? Here's how to join the ClipClop packaging party:

### Prerequisites

- macOS
- Python 3.10+ 
- Xcode Command Line Tools (`xcode-select --install`)

### Step 1: Set Up Your Environment

```bash
# Clone or download this repository
cd ClipClop

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Create the App Bundle

```bash
# Build the .app bundle with PyInstaller
pyinstaller --name "ClipClop" \
    --windowed \
    --icon="icon.icns" \
    --osx-bundle-identifier "com.yourname.clipclop" \
    --add-data="icon.icns:." \
    --hidden-import="pyperclip" \
    --hidden-import="netifaces" \
    --hidden-import="rumps" \
    --hidden-import="cryptography" \
    --hidden-import="qrcode" \
    --hidden-import="PIL" \
    menubar_app.py

# Make it a menu bar only application (removes Dock icon)
/usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" "dist/ClipClop.app/Contents/Info.plist"
```

### Step 3: Create the Package Installer

```bash
pkgbuild \
  --component dist/ClipClop.app \
  --install-location /Applications \
  --identifier com.inventure.clipclop \
  ClipClop.pkg
```

### Step 4: Install the App

```bash
sudo installer -pkg ClipClop.pkg -target /
ls -d /Applications/ClipClop.app   # Verify it landed in /Applications
```

### Step 5: Clean Up Build Artifacts

```bash
rm -rf dist build ClipClop.pkg ClipClop.spec
```

This leaves your repo tidy and ready for the next build.

## 🔧 Configuration

ClipClop stores its settings in `~/.config/clipboard_sync_app/settings.json`, including your **secret encryption key**. Do not share this file!

The menu bar app lets you:
- 📊 View connection status
- 📱 Pair new devices via QR Code
- ⏱️ Adjust sync intervals (though "Automatic" is best)
- ❌ Quit the application

## 🐛 Troubleshooting

**Can't connect?**
- Ensure both devices are on the same Wi-Fi.
- Check your Mac's Firewall settings (allow incoming connections for ClipClop).
- Re-scan the QR code if you reset the app settings.

**App won't open?**
- Check Console.app for logs.
- Ensure you have permissions to record the screen/access clipboard (System Settings -> Privacy & Security).

## 📜 License

This project is open source and available under the MIT License.

---

**Happy ClipClopping!** 🐎📋✨
