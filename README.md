# 📋 ClipClop - Your Clipboard's Best Friend! 🐎

Welcome to **ClipClop**, the magical clipboard synchronization tool that makes your Mac and Android devices share clipboards like they're best friends at a sleepover!

## 🤔 What is ClipClop?

Ever copied something on your Mac and wished you could paste it on your Android phone? Or vice versa? ClipClop is here to make that dream come true! It's like having a clipboard that gallops between your devices faster than you can say "copy-paste"! 

ClipClop synchronizes your clipboard content (text AND images!) between your macOS computer and Android devices over your local Wi-Fi network. No cloud services, no data harvesting, just pure local magic! ✨

## 🌟 Features

- 🔄 **Real-time sync**: Copy on Mac, paste on Android (and vice versa!)
- 🖼️ **Image support**: Yes, it handles images too! Screenshots, photos, memes - you name it!
- 🍎 **Native macOS menu bar app**: Lives quietly in your menu bar like a well-behaved digital pet
- ⚡ **Adjustable sync intervals**: From lightning-fast (1 second) to chill mode (60 seconds)
- 🔘 **Manual trigger**: Sometimes you just want to force-sync, and we get that
- 🔒 **Local network only**: Your data stays on YOUR network
- 🎯 **Zero configuration**: Just run it and connect!

## 🚀 Quick Start

1. **Run ClipClop** on your Mac (either the `.app` or install the `.pkg`)
2. **Note the IP address** shown in the menu bar
3. **Install the Android companion app**
4. **Connect** using the IP address and port 65432
5. **Start copying and pasting** like a clipboard wizard! 🧙‍♂️

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
pip install pyperclip opencv-python pyrealsense2 netifaces rumps pyinstaller
```

### Step 2: Create the App Bundle

```bash
# Build the .app bundle with PyInstaller
pyinstaller --name "ClipClop" \
    --windowed \
    --icon="icon.png" \
    --add-data="icon.png:." \
    --add-data="clipboard.py:." \
    --hidden-import="pyperclip" \
    --hidden-import="netifaces" \
    --hidden-import="rumps" \
    menubar_app.py
```

This creates `dist/ClipClop.app` - test it to make sure it works!

### Step 3: Create the Package Installer

#### Method 1: Simple Package (Recommended)
```bash
# Create a simple .pkg that installs to /Applications
productbuild --component "dist/ClipClop.app" /Applications "ClipClop.pkg"
```

#### Method 2: Advanced Package
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

### Step 4: Test Your Package

1. **Test the installer**: Double-click your `.pkg` file
2. **Check installation**: Look for ClipClop in `/Applications`
3. **Run the app**: Make sure it appears in your menu bar
4. **Celebrate**: You've just created a macOS package! 🎉

## 🔧 Configuration

ClipClop stores its settings in `~/.config/clipboard_sync_app/settings.json`. The menu bar app lets you:

- 📊 View current server IP and port
- ⏱️ Adjust sync interval (0-60 seconds)
- 🔄 Manually trigger clipboard sync
- ❌ Quit the application

## 🐛 Troubleshooting

**App won't start?**
- Check Console.app for error messages
- Make sure all dependencies are installed
- Try running from Terminal to see error output

**Can't connect from Android?**
- Ensure both devices are on the same Wi-Fi network
- Check if firewall is blocking port 65432
- Try the different IP addresses shown in the menu

**Package installer fails?**
- Make sure you have admin privileges
- Try the simple `productbuild` method first
- Check that the `.app` bundle works before packaging

## 🤝 Contributing

Found a bug? Have a feature idea? Want to make ClipClop even more awesome? Contributions are welcome! Just remember:

- Keep it fun! 🎉
- Test your changes
- Update this README if needed

## 📜 License

This project is open source and available under the MIT License.

## 🙏 Acknowledgments

- Thanks to the `rumps` library for making native macOS menu bar apps easy
- Shoutout to `pyperclip` for clipboard magic

---

**Happy ClipClopping!** 🐎📋✨