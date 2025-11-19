import sys
from .base import ClipboardProvider
from .macos import MacOSClipboard

def get_clipboard_provider() -> ClipboardProvider:
    if sys.platform == 'darwin':
        return MacOSClipboard()
    else:
        # TODO: Implement Windows/Linux support
        raise NotImplementedError(f"Platform {sys.platform} not supported yet.")

