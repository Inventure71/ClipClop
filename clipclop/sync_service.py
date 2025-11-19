import threading
import hashlib
import time
from .config import ConfigManager
from .clipboard import get_clipboard_provider
from .network.server import ClipboardServer
from .network.crypto import CryptoManager

class SyncService:
    def __init__(self):
        self.config = ConfigManager()
        self.clipboard = get_clipboard_provider()
        
        crypto = None
        if self.config.encryption_key:
            crypto = CryptoManager(self.config.encryption_key)
            
        self.server = ClipboardServer(
            port=65432, 
            on_message_received=self.on_client_message,
            crypto_manager=crypto
        )
        
        self.stop_event = threading.Event()
        self.monitor_thread = None
        
        # State tracking to prevent loops
        self.last_sent_hash = None
        self.last_received_hash = None
        
        # Local cache of clipboard state
        self.current_text_state = ""
        self.current_image_state = None

    def start(self):
        self.stop_event.clear()
        self.server.start()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("[SERVICE] Sync service started.")

    def stop(self):
        self.stop_event.set()
        self.server.stop()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("[SERVICE] Sync service stopped.")

    def get_network_info(self):
        return self.server.get_ips(), self.server.port

    def on_client_message(self, message: dict, client_addr: str):
        """Callback when server receives a message from a client."""
        try:
            content = message.get('content', '')
            msg_type = message.get('type')
            
            # Calculate hash to prevent echo
            payload_bytes = content.encode('utf-8') if content else b''
            received_hash = hashlib.md5(payload_bytes).hexdigest()
            
            self.last_received_hash = received_hash
            self.last_sent_hash = received_hash # Don't echo back what we just got
            
            if msg_type == 'text':
                print(f"[SERVICE] Received text from {client_addr}")
                if self.clipboard.set_text(content):
                    self.current_text_state = content
                    self.current_image_state = None
            
            elif msg_type == 'image':
                fmt = message.get('format', 'png')
                print(f"[SERVICE] Received image ({fmt}) from {client_addr}")
                if self.clipboard.set_image(content, fmt):
                    self.current_image_state = content
                    self.current_text_state = ""
                    
        except Exception as e:
            print(f"[SERVICE] Error handling client message: {e}")

    def manual_sync(self):
        print("[SERVICE] Manual sync triggered.")
        self._check_and_broadcast(force=True)

    def _monitor_loop(self):
        print("[SERVICE] Monitor loop started.")
        last_change_count = -1
        
        while not self.stop_event.is_set():
            if self.config.automatic_monitoring:
                should_check = False
                
                # Efficient check if possible
                if hasattr(self.clipboard, 'get_change_count'):
                    count = self.clipboard.get_change_count()
                    if count != -1:
                        if count != last_change_count:
                            # print(f"[DEBUG] Change count: {last_change_count} -> {count}")
                            should_check = True
                            last_change_count = count
                    else:
                        should_check = True # Fallback to polling
                else:
                    should_check = True # Always poll if no efficient check

                if should_check:
                    self._check_and_broadcast(force=False)
                
                # Intelligent sleeping
                # If we have an efficient change count, we can sleep longer or just wait
                # But since we are in a loop, we still need to be responsive to stop_event
                # For PyObjC, we don't need to poll often if changeCount is reliable.
                # However, `get_change_count` is fast, so polling it is cheap.
                
                sleep_time = self.config.check_interval
                if hasattr(self.clipboard, 'get_change_count') and self.clipboard.get_change_count() != -1:
                     # If using native change count, we can check frequently (e.g. 0.5s) without cost
                     # regardless of the "interval" setting which might be for legacy polling.
                     # Or we respect the interval if the user wants it slow.
                     # Let's respect the interval but clamp it to be reasonable.
                     sleep_time = max(0.5, sleep_time)
                
                self.stop_event.wait(sleep_time)
            else:
                self.stop_event.wait(1.0)

    def _check_and_broadcast(self, force=False):
        # Get current clipboard content
        img_data, img_fmt = self.clipboard.get_image()
        text_data = None
        
        if img_data is None:
            text_data = self.clipboard.get_text()

        # Determine what we have
        content_type = None
        content_data = None
        content_fmt = None
        
        if img_data:
            content_type = "image"
            content_data = img_data
            content_fmt = img_fmt
        elif text_data:
            content_type = "text"
            content_data = text_data
        else:
            # Empty clipboard
            pass

        # Hash it
        current_hash = None
        if content_data:
            current_hash = hashlib.md5(content_data.encode('utf-8')).hexdigest()
        else:
            current_hash = hashlib.md5(b"").hexdigest()

        # Logic to decide if we send
        should_send = force
        if not should_send:
             # Only send if content is different from last sent
             if current_hash != self.last_sent_hash:
                 # AND it is not what we just received from a client (to avoid echo loops)
                 if current_hash != self.last_received_hash:
                     should_send = True
        
        if should_send:
            msg = {}
            if content_type:
                msg = {"type": content_type, "content": content_data}
                if content_fmt:
                    msg["format"] = content_fmt
            else:
                # Send clear/empty?
                msg = {"type": "text", "content": ""}

            count = self.server.broadcast(msg)
            if count > 0:
                print(f"[SERVICE] Broadcasted {content_type or 'empty'} to {count} clients.")
            
            self.last_sent_hash = current_hash
            if not force:
                self.last_received_hash = None # Reset received tracking
            
            # Update local state
            if content_type == "text":
                self.current_text_state = content_data
                self.current_image_state = None
            elif content_type == "image":
                self.current_image_state = content_data
                self.current_text_state = ""

        # Sync local state variables if we didn't send (to keep track)
        if not should_send:
             if content_type == "text":
                self.current_text_state = content_data
             elif content_type == "image":
                self.current_image_state = content_data

