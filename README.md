# 📋 ClipClop - Your Clipboard's Best Friend! 🐎

<p align="center">
  <img src="https://media1.tenor.com/m/a-dKVjzm5QwAAAAC/foto.gif" alt="Running Horse">
</p>

Welcome to **ClipClop**, the magical clipboard synchronization tool that makes your Mac and Android devices share clipboards like they're best friends at a sleepover!

## 🤔 What is ClipClop?

Ever copied something on your Mac and wished you could paste it on your Android phone? Or vice versa? ClipClop is here to make that dream come true! It's like having a clipboard that gallops between your devices faster than you can say "copy-paste"! 

ClipClop synchronizes your clipboard content (text AND images!) between your macOS computer and Android devices over your local Wi-Fi network. No cloud services, no data harvesting, just pure local magic! ✨

## 🌟 Features

- 🔄 **Real-time sync**: Copy on Mac, paste on Android (and vice versa!)
- 🖼️ **Image support**: Yes, it handles images too! Screenshots, photos, memes - you name it!
- 🍎 **Native macOS menu bar app**: Lives quietly in your menu bar (no Dock icon, no Alt-Tab presence) like a well-behaved digital pet.
- ⚡ **Adjustable sync intervals**: From lightning-fast (1 second) to chill mode (60 seconds)
- 🔘 **Manual trigger**: Sometimes you just want to force-sync, and we get that
- 🔒 **Local network only**: Your data stays on YOUR network
- 🎯 **Zero configuration**: Just run it and connect!

## 🚀 Quick Start

1.  **Run ClipClop** on your Mac (either the `.app` or install the `.pkg`)
2.  **Note the IP address** shown in the menu bar
3.  **Install the Android companion app**
4.  **Connect** using the IP address and port 65432
5.  **Start copying and pasting** like a clipboard wizard! 🧙‍♂️

## 🛠️ Building Your Own Package

Want to create your own `.pkg` installer? Here's how to join the ClipClop packaging party:

### Prerequisites

- macOS
- Python 3.10+ with the required dependencies
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

### Step 2: Create the App Bundle & Configure for Menu Bar Only

```bash
# Build the .app bundle with PyInstaller
pyinstaller --name "ClipClop" \
    --windowed \
    --icon="icon.icns" \
    --osx-bundle-identifier "com.yourname.clipclop" \
    --add-data="icon.icns:." \
    --add-data="clipboard.py:." \
    --hidden-import="pyperclip" \
    --hidden-import="netifaces" \
    --hidden-import="rumps" \
    menubar_app.py

# After PyInstaller creates the .app bundle, modify its Info.plist
# to make it a menu bar only application (LSUIElement).
# This removes the Dock icon and Alt-Tab entry.
/usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" "dist/ClipClop.app/Contents/Info.plist"
```

This creates `dist/ClipClop.app`. Test it to make sure it works and appears only in the menu bar.
**Note:** Replace `com.yourname.clipclop` with your actual bundle identifier.

### Step 3: Create the Package Installer

Now that `dist/ClipClop.app` is configured correctly, you can package it.

#### Method 1: Simple Package (Recommended)
```bash
# Create a simple .pkg that installs to /Applications
productbuild --component "dist/ClipClop.app" /Applications "ClipClop.pkg"
```
Move the .pkg file to the downloads folder and install the app.

#### Method 2: Advanced Package
If you need more control (e.g., scripts, specific versioning not handled by PyInstaller):
```bash
# Create a component package first
pkgbuild --root "dist/ClipClop.app" \
    --identifier "com.yourname.clipclop" \
    --version "1.0" \
    --install-location "/Applications/ClipClop.app" \
    "ClipClop-component.pkg"

# Create distribution XML (optional, for customization)
productbuild --synthesize \
    --package "ClipClop-component.pkg" \
    "distribution.xml"

# Build the final installer
productbuild --distribution "distribution.xml" \
    --package-path . \
    "ClipClop.pkg"
```
**Note:** Ensure the `--identifier` in `pkgbuild` matches the one used with PyInstaller or your desired app identifier.

### Step 4: Test Your Package

1.  **Test the installer**: Double-click your `.pkg` file.
2.  **Check installation**: Look for ClipClop in `/Applications`.
3.  **Run the app**: Make sure it appears *only* in your menu bar and not in the Dock or Alt-Tab switcher.
4.  **Celebrate**: You've just created a macOS package for a menu bar agent! 🎉

## 🔧 Configuration

ClipClop stores its settings in `~/.config/clipboard_sync_app/settings.json`. The menu bar app lets you:

- 📊 View current server IP and port
- ⏱️ Adjust sync interval (0-60 seconds)
- 🔄 Manually trigger clipboard sync
- ❌ Quit the application

## 🐛 Troubleshooting

**App won't start?**
- Check Console.app for error messages.
- Make sure all dependencies are installed.
- Try running the script directly from Terminal before packaging to see error output.

**App still shows in Dock after packaging?**
-   Ensure the `PlistBuddy` command in "Step 2" ran successfully and modified `dist/ClipClop.app/Contents/Info.plist` *before* you ran `productbuild`.
-   Verify `LSUIElement` is set to `true` (or `<true/>`) in the `Info.plist` inside the *installed* `/Applications/ClipClop.app`.
-   Sometimes macOS caches Dock icons. Try logging out and back in, or `killall Dock`.

**Can't connect from Android?**
- Ensure both devices are on the same Wi-Fi network.
- Check if your Mac's firewall is blocking incoming connections on port 65432 for ClipClop.
- Try the different IP addresses shown in the menu.

**Package installer fails?**
- Make sure you have admin privileges.
- Try the simple `productbuild` method first.
- Check that the `.app` bundle (after `PlistBuddy` modification) works correctly before packaging.

## 🤝 Contributing

Found a bug? Have a feature idea? Want to make ClipClop even more awesome? Contributions are welcome! Just remember:

- Keep it fun! 🎉
- Test your changes.
- Update this README if needed.

## 📜 License

This project is open source and available under the MIT License.

## 🙏 Acknowledgments

- Thanks to the `rumps` library for making native macOS menu bar apps easy.
- Shoutout to `pyperclip` for clipboard magic.

---

**Happy ClipClopping!** 🐎📋✨
