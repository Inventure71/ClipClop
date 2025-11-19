ARCHITECTURE.md
=============

# System Architecture

ClipClop is designed as a modular, secure, and efficient clipboard synchronization tool. It follows a clean architecture pattern to separate concerns between the User Interface, Business Logic, and Infrastructure (Network/Clipboard).

## 📦 Project Structure

```
clipclop/
├── __init__.py
├── main.py              # CLI Entry point
├── config.py            # Configuration & Secret Key Management
├── sync_service.py      # Core Controller (The "Brain")
├── clipboard/           # Clipboard Abstraction Layer
│   ├── base.py          # Interface
│   └── macos.py         # Native PyObjC Implementation
├── network/             # Networking Layer
│   ├── server.py        # Socket Server & Client Handling
│   ├── protocol.py      # Message Serialization
│   └── crypto.py        # AES-256 GCM Encryption
└── ui/                  # User Interface
    ├── menubar.py       # Rumps (Menu Bar) App
    └── qr_window.py     # QR Code Generation & Display
```

## 🔄 Data Flow

1.  **Clipboard Monitoring**:
    *   The `SyncService` runs a lightweight monitor loop.
    *   It polls `MacOSClipboard.get_change_count()` (using native `NSPasteboard`), which is virtually free for the CPU.
    *   When the change count increments, it reads the new content.

2.  **Processing**:
    *   Content is identified as **Text** or **Image**.
    *   Images are read directly from memory as PNG/TIFF data.
    *   A hash (MD5) is calculated to detect duplicate events (echo prevention).

3.  **Encryption**:
    *   The content is serialized to JSON.
    *   `CryptoManager` encrypts the JSON using **AES-256 GCM**.
    *   A unique 12-byte `nonce` is generated for every message.

4.  **Transmission**:
    *   The encrypted packet (Nonce + Ciphertext + Tag) is sent over TCP sockets to all connected clients (Android devices).

5.  **Receiving (Reverse Flow)**:
    *   Server receives an encrypted packet.
    *   `CryptoManager` decrypts and authenticates it.
    *   If valid, `SyncService` updates the local Mac clipboard.
    *   The hash is stored to prevent re-broadcasting the same update back to the sender.

## 🔐 Security

*   **Encryption**: AES-GCM (Galois/Counter Mode) with 256-bit keys.
*   **Key Exchange**: The secret key is generated securely on the Mac and transferred to the phone via **QR Code** (Out-of-Band pairing).
*   **Traffic**: All TCP traffic is opaque and cannot be read or tampered with by network snoopers.

## ⚡ Efficiency

*   **Native Bindings**: Uses `pyobjc-framework-Cocoa` to talk directly to macOS APIs.
*   **Zero-Copy (mostly)**: Avoids shelling out to `osascript` or `pbcopy` unless absolutely necessary.
*   **Smart Sleep**: The monitor loop adapts its sleep cycle based on activity and available API capabilities.

