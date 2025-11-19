import subprocess
import base64
import sys
import pyperclip
from .base import ClipboardProvider

# Import PyObjC modules if available
try:
    from AppKit import NSPasteboard, NSPasteboardTypePNG, NSPasteboardTypeTIFF, NSPasteboardTypeString
    from Foundation import NSData, NSImage
    HAS_PYOBJC = True
except ImportError:
    HAS_PYOBJC = False

class MacOSClipboard(ClipboardProvider):
    def __init__(self):
        self.verbose_debug = False
        self.communicate_timeout = 3
        self.has_pyobjc = HAS_PYOBJC
        
        if self.has_pyobjc:
            self.pb = NSPasteboard.generalPasteboard()
            print("[INFO] PyObjC (AppKit) found. Using efficient NSPasteboard.")
        else:
            print("[WARNING] PyObjC not found. Using slower osascript fallback.")

    def get_text(self) -> str:
        if self.has_pyobjc:
            try:
                content = self.pb.stringForType_(NSPasteboardTypeString)
                return str(content) if content else ""
            except Exception as e:
                print(f"[CLIPBOARD] Error getting text via PyObjC: {e}")
                # Fallback
        try:
            return pyperclip.paste() or ""
        except Exception as e:
            print(f"[CLIPBOARD] Error getting text: {e}")
            return ""

    def set_text(self, text: str) -> bool:
        if self.has_pyobjc:
            try:
                self.pb.clearContents()
                self.pb.setString_forType_(text, NSPasteboardTypeString)
                return True
            except Exception as e:
                print(f"[CLIPBOARD] Error setting text via PyObjC: {e}")
                # Fallback
        try:
            pyperclip.copy(text)
            return True
        except Exception as e:
            print(f"[CLIPBOARD] Error setting text: {e}")
            return False

    def get_image(self) -> tuple[str | None, str | None]:
        """
        Get image from macOS clipboard.
        Uses PyObjC if available, otherwise falls back to osascript.
        Returns (base64_data, format_str) or (None, None).
        """
        if self.has_pyobjc:
            return self._get_image_pyobjc()
        else:
            return self._get_image_osascript()

    def set_image(self, base64_data: str, format_hint: str = "png") -> bool:
        """Set image to clipboard."""
        if self.has_pyobjc:
            return self._set_image_pyobjc(base64_data)
        else:
            return self._set_image_osascript(base64_data)

    def get_change_count(self) -> int:
        """Returns a change count or similar identifier to detect changes efficiently."""
        if self.has_pyobjc:
            try:
                return self.pb.changeCount()
            except Exception:
                return -1
        return -1

    # --- PyObjC Implementations ---

    def _get_image_pyobjc(self) -> tuple[str | None, str | None]:
        try:
            # Check for common image types
            available_types = self.pb.types()
            
            # Prefer PNG
            if NSPasteboardTypePNG in available_types:
                data = self.pb.dataForType_(NSPasteboardTypePNG)
                if data:
                    b64_str = base64.b64encode(data.bytes()).decode('utf-8')
                    return b64_str, 'png'
            
            # Fallback to TIFF (common on macOS)
            if NSPasteboardTypeTIFF in available_types:
                data = self.pb.dataForType_(NSPasteboardTypeTIFF)
                if data:
                    # We could convert TIFF to PNG here if needed, but sending raw might be okay
                    # dependent on receiver. For now, let's send what we get or convert if simple.
                    # Android might not like TIFF. Let's try to convert to PNG using NSImage if possible.
                    img = NSImage.alloc().initWithData_(data)
                    if img:
                        # Convert to PNG
                        from AppKit import NSBitmapImageRep
                        tiff_rep = NSBitmapImageRep.imageRepWithData_(data)
                        if tiff_rep:
                            png_data = tiff_rep.representationUsingType_properties_(4, None) # 4 is NSPNGFileType
                            if png_data:
                                b64_str = base64.b64encode(png_data.bytes()).decode('utf-8')
                                return b64_str, 'png'
                    
                    # If conversion fails, send TIFF
                    b64_str = base64.b64encode(data.bytes()).decode('utf-8')
                    return b64_str, 'tiff'

            return None, None

        except Exception as e:
            print(f"[CLIPBOARD] Error getting image via PyObjC: {e}")
            return None, None

    def _set_image_pyobjc(self, base64_data: str) -> bool:
        try:
            image_bytes = base64.b64decode(base64_data)
            ns_data = NSData.dataWithBytes_length_(image_bytes, len(image_bytes))
            
            self.pb.clearContents()
            # We'll write as PNG data. 
            self.pb.setData_forType_(ns_data, NSPasteboardTypePNG)
            return True
        except Exception as e:
            print(f"[CLIPBOARD] Error setting image via PyObjC: {e}")
            return False

    # --- Fallback Implementations ---

    def _get_image_osascript(self) -> tuple[str | None, str | None]:
        # ... existing osascript implementation ...
        print_prefix = "[MACOS_CLIPBOARD_IMG_GET]"
        available_types_str = ""
        
        try:
            osa_info_proc = subprocess.Popen(['osascript', '-e', 'clipboard info'],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            osa_info_stdout, _ = osa_info_proc.communicate(timeout=1)
            if osa_info_stdout:
                available_types_str = osa_info_stdout.decode(errors='ignore').strip()
        except Exception:
            return None, None

        image_type_indicators = ['PNGf', 'JPEG', 'TIFF', 'GIF', 'BMP ', 'jp2 ']
        if not any(indicator in available_types_str for indicator in image_type_indicators):
            return None, None

        osascript_type_map = [
            {'applescript_type': 'PNG picture', 'class_hint': 'PNGf', 'common_name': 'png', 'magic': [b'\x89PNG\r\n\x1a\n']},
            {'applescript_type': 'JPEG picture','class_hint': 'JPEG', 'common_name': 'jpeg', 'magic': [b'\xff\xd8\xff']},
        ]

        for item in osascript_type_map:
            class_hint = item['class_hint']
            common_name = item['common_name']
            magic_bytes_list = item['magic']
            
            if class_hint not in available_types_str:
                continue

            applescript_command = f"get the clipboard as «class {class_hint}»"

            try:
                proc = subprocess.Popen(
                    ['osascript', '-e', applescript_command],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdout, _ = proc.communicate(timeout=self.communicate_timeout + 1)

                stdout_str = stdout.decode(errors='ignore').strip()

                if proc.returncode == 0 and stdout_str:
                    if stdout_str.startswith("«data ") and stdout_str.endswith("»"):
                        hex_data_part = stdout_str[len("«data "):-1]
                        if hex_data_part.upper().startswith(class_hint.upper()):
                             hex_data_part = hex_data_part[len(class_hint):]
                        
                        if hex_data_part:
                            try:
                                image_bytes = bytes.fromhex(hex_data_part)
                                if any(image_bytes.startswith(magic) for magic in magic_bytes_list):
                                    return base64.b64encode(image_bytes).decode('utf-8'), common_name
                            except ValueError:
                                pass
            except Exception:
                pass

        return None, None

    def _set_image_osascript(self, base64_data: str) -> bool:
        try:
            image_bytes = base64.b64decode(base64_data)
            proc = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.communicate(input=image_bytes, timeout=self.communicate_timeout)
            return proc.returncode == 0
        except Exception:
            return False
