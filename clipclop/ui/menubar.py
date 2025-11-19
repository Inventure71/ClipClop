import os
import sys
import rumps
import threading
from ..sync_service import SyncService
from ..config import ConfigManager
from .qr_window import QRWindow

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
        return os.path.join(os.path.dirname(base_path), 'Resources', relative_path)
    except Exception:
        return os.path.join(os.path.abspath("."), relative_path)

APP_NAME = "ClipClop"
ICON_PATH = resource_path("icon.icns") 

INTERVAL_OPTIONS = [
    ("Disabled (Manual Only)", 0),
    ("0.5 Seconds", 0.5),
    ("1 Second", 1),
    ("2 Seconds", 2),
    ("5 Seconds", 5),
    ("10 Seconds", 10),
    ("15 Seconds", 15),
    ("30 Seconds", 30),
    ("60 Seconds", 60),
]

def get_slider_value_from_seconds(seconds_val):
    if seconds_val <= 0:
        return 0
    closest_index = 0
    min_diff = float('inf')
    for i, (_, s) in enumerate(INTERVAL_OPTIONS):
        if s == 0 and seconds_val > 0 : continue
        diff = abs(s - seconds_val)
        if diff < min_diff:
            min_diff = diff
            closest_index = i
        elif diff == min_diff and s > INTERVAL_OPTIONS[closest_index][1]:
            closest_index = i
    return closest_index

class ClipboardSyncApp(rumps.App):
    def __init__(self, service: SyncService):
        super().__init__(APP_NAME, icon=ICON_PATH, quit_button=None)
        self.service = service
        self.config = ConfigManager()
        
        interval_items = []
        for i, (label, _) in enumerate(INTERVAL_OPTIONS):
            item = rumps.MenuItem(label, callback=self.set_interval)
            item.idx = i
            interval_items.append(item)
            
        self.menu = [
            rumps.MenuItem("Status: Ready", callback=None),
            None,
            rumps.MenuItem("Connect Mobile", callback=self.show_qr),
            None,
            rumps.MenuItem("Settings", callback=None), # Placeholder
            ("Check Interval", interval_items),
            rumps.MenuItem("Manual Sync", callback=self.manual_check),
            None,
            rumps.MenuItem("Quit", callback=rumps.quit_application)
        ]
        
        self.update_interval_display()
        self.update_status_display()
        
        # Start timers to update UI
        rumps.Timer(self.update_status_display, 5).start()
        
        # Ensure service is started
        if not self.service.monitor_thread:
            self.service.start()

    def update_status_display(self, _=None):
        ips, port = self.service.get_network_info()
        client_count = self.service.server.get_client_count() if hasattr(self.service.server, 'get_client_count') else 0
        
        if client_count > 0:
            self.menu["Status: Ready"].title = f"Status: Connected ({client_count})"
        elif ips:
             self.menu["Status: Ready"].title = "Status: Ready to Pair"
        else:
             self.menu["Status: Ready"].title = "Status: No Network"

    def update_interval_display(self, _=None):
        current = self.config.check_interval
        idx = get_slider_value_from_seconds(current)
        for i, (label, _) in enumerate(INTERVAL_OPTIONS):
            self.menu["Check Interval"][label].state = (i == idx)

    def set_interval(self, sender):
        idx = sender.idx
        _, seconds = INTERVAL_OPTIONS[idx]
        self.config.update_interval(seconds)
        self.update_interval_display()

    def manual_check(self, _):
        threading.Thread(target=self.service.manual_sync, daemon=True).start()
        rumps.notification(APP_NAME, "", "Manual check & send initiated.")

    def show_qr(self, _):
        ips, port = self.service.get_network_info()
        if not ips:
            rumps.alert("No Network", "Connect to Wi-Fi to pair devices.")
            return
            
        # Format: clipclop://IP:PORT?key=KEY
        primary_ip = ips[0]
        key = self.config.encryption_key or ""
        
        import urllib.parse
        safe_key = urllib.parse.quote(key)
        
        pair_data = f"clipclop://{primary_ip}:{port}?key={safe_key}"
        
        qr = QRWindow(pair_data, title="Scan to Connect")
        qr.show()
