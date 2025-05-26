import rumps
import threading
import clipboard

APP_NAME = "Clipboard Sync"
ICON_PATH = "icon.png"

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
    def __init__(self):
        super().__init__(APP_NAME, icon=ICON_PATH, quit_button=None)
        interval_items = []
        for i, (label, _) in enumerate(INTERVAL_OPTIONS):
            item = rumps.MenuItem(label, callback=self.set_interval)
            item.idx = i  # Store the index as a custom attribute
            interval_items.append(item)
        self.menu = [
            rumps.MenuItem("IP/Port: ...", callback=None),
            rumps.MenuItem("Interval: ...", callback=None),
            None,  # separator
            ("Set Check Interval", interval_items),
            None,
            rumps.MenuItem("Manual Check & Send", callback=self.manual_check),
            None,
            rumps.MenuItem("Quit", callback=rumps.quit_application)
        ]
        self.interval_index = get_slider_value_from_seconds(clipboard.current_check_interval_seconds)
        self.update_interval_display()
        self.update_ip_display()
        self.backend_started = False
        rumps.Timer(self.update_ip_display, 5).start()
        rumps.Timer(self.update_interval_display, 2).start()
        self.start_backend()

    def update_ip_display(self, _=None):
        ips, port = clipboard.get_server_network_info()
        if ips and port:
            ip_str = ", ".join(ips)
            self.menu["IP/Port: ..."].title = f"IP: {ip_str} Port: {port}"
        elif port:
            self.menu["IP/Port: ..."].title = f"IP: (Resolving...) Port: {port}"
        else:
            self.menu["IP/Port: ..."].title = "IP/Port: Awaiting server..."

    def update_interval_display(self, _=None):
        idx = get_slider_value_from_seconds(clipboard.current_check_interval_seconds)
        label, _ = INTERVAL_OPTIONS[idx]
        self.menu["Interval: ..."].title = f"Interval: {label}"
        # Update checkmarks
        for i, (label, _) in enumerate(INTERVAL_OPTIONS):
            self.menu["Set Check Interval"][label].state = (i == idx)

    def set_interval(self, sender):
        idx = sender.idx
        _, seconds = INTERVAL_OPTIONS[idx]
        clipboard.update_check_interval(seconds)
        self.update_interval_display()

    def manual_check(self, _):
        threading.Thread(target=clipboard.manual_trigger_send_clipboard_content, daemon=True).start()
        rumps.notification(APP_NAME, "", "Manual check & send initiated.")

    def start_backend(self):
        if not self.backend_started:
            clipboard.stop_event.clear()
            self.monitor_thread = threading.Thread(target=clipboard.clipboard_monitor_thread_func, daemon=True)
            self.server_thread = threading.Thread(target=clipboard.start_server_thread_func, daemon=True)
            self.monitor_thread.start()
            self.server_thread.start()
            self.backend_started = True

if __name__ == '__main__':
    ClipboardSyncApp().run() 