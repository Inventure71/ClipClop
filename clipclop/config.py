import os
import json
import threading
import secrets
import base64

class ConfigManager:
    _instance = None
    _lock = threading.Lock()

    DEFAULT_CHECK_INTERVAL = 1.0
    CONFIG_DIR = os.path.expanduser("~/.config/clipboard_sync_app")
    CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ConfigManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        self.check_interval = self.DEFAULT_CHECK_INTERVAL
        self.automatic_monitoring = True
        self.encryption_key = None # Base64 encoded key
        
        self._load_config()
        
        # Ensure we have a key
        if not self.encryption_key:
            self.encryption_key = self._generate_key()
            self.save_config()
            
        self._initialized = True

    def _generate_key(self):
        """Generate a 32-byte secure key and return it as base64 string."""
        key_bytes = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(key_bytes).decode('utf-8')

    def _ensure_config_dir(self):
        if not os.path.exists(self.CONFIG_DIR):
            try:
                os.makedirs(self.CONFIG_DIR)
                return True
            except OSError as e:
                print(f"[ERROR] Could not create config directory {self.CONFIG_DIR}: {e}")
                return False
        return True

    def _load_config(self):
        if not self._ensure_config_dir():
            return

        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.check_interval = float(config.get('check_interval_seconds', self.DEFAULT_CHECK_INTERVAL))
                    self.automatic_monitoring = self.check_interval > 0
                    self.encryption_key = config.get('encryption_key')
            except (json.JSONDecodeError, ValueError, TypeError) as e:
                print(f"[ERROR] Error loading config: {e}. Using defaults.")
        else:
            self.save_config()

    def save_config(self):
        if not self._ensure_config_dir():
            return

        config_to_save = {
            'check_interval_seconds': self.check_interval,
            'encryption_key': self.encryption_key
        }
        try:
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(config_to_save, f, indent=4)
        except IOError as e:
            print(f"[ERROR] Could not write config file {self.CONFIG_FILE}: {e}")

    def update_interval(self, seconds: float):
        if seconds < 0:
            seconds = 0
        
        self.check_interval = seconds
        self.automatic_monitoring = seconds > 0
        print(f"[CONFIG] Updated check interval to: {self.check_interval}s. Monitoring: {self.automatic_monitoring}")
        self.save_config()
