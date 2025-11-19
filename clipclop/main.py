import argparse
import sys
import time
from .sync_service import SyncService
from .ui import start_ui

def main():
    parser = argparse.ArgumentParser(description="ClipClop Clipboard Sync")
    parser.add_argument("--headless", action="store_true", help="Run without GUI")
    args = parser.parse_args()

    service = SyncService()

    if args.headless:
        print("Starting in headless mode...")
        service.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")
            service.stop()
    else:
        # The UI will ensure the service is started, or we can start it here.
        # It's safer to let the UI manage the lifecycle if it's running, 
        # but we pass the service instance.
        start_ui(service)

if __name__ == "__main__":
    main()

