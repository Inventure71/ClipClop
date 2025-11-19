def start_ui(service):
    try:
        from .menubar import ClipboardSyncApp
        app = ClipboardSyncApp(service)
        app.run()
    except ImportError as e:
        print(f"[ERROR] Could not start UI: {e}")
        print("Ensure 'rumps' is installed.")
