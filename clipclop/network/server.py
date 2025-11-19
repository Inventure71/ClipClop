import socket
import threading
import time
from typing import Callable, List, Tuple, Optional
from .protocol import receive_message, send_message
from .crypto import CryptoManager

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

class ClipboardServer:
    def __init__(self, port: int, on_message_received: Callable[[dict, str], None], crypto_manager: Optional[CryptoManager] = None):
        self.host = '0.0.0.0'
        self.port = port
        self.on_message_received = on_message_received
        self.crypto_manager = crypto_manager
        
        self.clients: List[socket.socket] = []
        self.clients_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.server_thread = None
        self.socket = None

    def start(self):
        self.stop_event.clear()
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()

    def stop(self):
        self.stop_event.set()
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        if self.server_thread:
            self.server_thread.join(timeout=2)

    def broadcast(self, message: dict):
        with self.clients_lock:
            current_clients = list(self.clients)
        
        if not current_clients:
            return 0

        sent_count = 0
        for client in current_clients:
            if send_message(client, message, self.crypto_manager):
                sent_count += 1
            else:
                self._remove_client(client)
        return sent_count

    def get_ips(self) -> List[str]:
        """Get available IP addresses for this machine."""
        ips = []
        if HAS_NETIFACES:
            try:
                for interface in netifaces.interfaces():
                    ifaddresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in ifaddresses:
                        for link in ifaddresses[netifaces.AF_INET]:
                            ip = link.get('addr')
                            if ip and not ip.startswith('127.') and not ip.startswith("169.254."):
                                ips.append(ip)
            except Exception as e:
                print(f"[NETWORK] Error getting IPs: {e}")
        
        # Fallback
        if not ips:
            try:
                hostname = socket.gethostname()
                primary_ip = socket.gethostbyname(hostname)
                if primary_ip and not primary_ip.startswith('127.'): 
                     ips.append(primary_ip)
            except Exception:
                pass
        
        return list(set(ips))

    def get_client_count(self) -> int:
        with self.clients_lock:
            return len(self.clients)

    def _server_loop(self):
        print(f"[SERVER] Starting on port {self.port}")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen()
            self.socket.settimeout(1.0)
        except OSError as e:
            print(f"[SERVER] CRITICAL: Could not bind to port {self.port}: {e}")
            self.stop_event.set()
            return

        while not self.stop_event.is_set():
            try:
                conn, addr = self.socket.accept()
                self._handle_new_connection(conn, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"[SERVER] Accept error: {e}")
        
        print("[SERVER] Stopped.")

    def _handle_new_connection(self, conn, addr):
        print(f"[SERVER] Client connected: {addr}")
        conn.setblocking(True)
        with self.clients_lock:
            self.clients.append(conn)
        
        # Send current configuration (if needed) or just start loop
        # For now, just start the loop
        t = threading.Thread(target=self._client_loop, args=(conn, addr), daemon=True)
        t.start()

    def _client_loop(self, conn, addr):
        try:
            while not self.stop_event.is_set():
                message = receive_message(conn, self.crypto_manager)
                if message is None:
                    break
                self.on_message_received(message, str(addr))
        except Exception as e:
            print(f"[SERVER] Error with client {addr}: {e}")
        finally:
            print(f"[SERVER] Client disconnected: {addr}")
            self._remove_client(conn)
            try:
                conn.close()
            except Exception:
                pass

    def _remove_client(self, conn):
        with self.clients_lock:
            if conn in self.clients:
                self.clients.remove(conn)

