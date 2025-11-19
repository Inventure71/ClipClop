import threading
import rumps
import socket
import qrcode
from PIL import Image
import io
import os
import tempfile

class QRWindow(object):
    def __init__(self, data_str, title="Pair Device"):
        self.data_str = data_str
        self.title_str = title
        self.temp_file = None

    def show(self):
        # Generate QR Code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(self.data_str)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to temp file
        fd, path = tempfile.mkstemp(suffix=".png")
        os.close(fd)
        img.save(path)
        self.temp_file = path

        # Create a simple rumps notification or better yet, alert with icon
        # Rumps alerts are limited. We can use a custom window or just the alert with the icon.
        # Since rumps.alert icon support is tricky with sizing, let's try a simple approach first:
        # Open the image in the default viewer (Preview). It's the cleanest "Zero UI code" way.
        # Or use a simple Tkinter/Cocoa window if we want it integrated. 
        # Given the user wants "only the nav bar", opening a temporary "Pairing" window is standard.
        
        # For now, let's use the system's default image viewer for simplicity and reliability.
        # It's a "Pairing Card".
        subprocess.call(['open', path])

        # Alternatively, we could use `rumps.Window` but it's for text input.
        # We could use a notification but it's too small.

import subprocess

