import socket
import threading
import json
import time
import pyperclip # For text
import subprocess # For pbcopy/pbpaste (images on macOS)
import base64
import hashlib
import struct # For packing/unpacking message length
import os # For config file path
import sys # For platform check (though primarily macOS focused)

# Attempt to import netifaces, otherwise fall back
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    print("[INFO] 'netifaces' library not found. IP address suggestion will be basic.")
    print("       For more accurate IP suggestions, install it with: pip3 install netifaces")


HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 65432
COMMUNICATE_TIMEOUT = 3 # Timeout for pbpaste/pbcopy in seconds

# --- Configuration ---
CONFIG_DIR = os.path.expanduser("~/.config/clipboard_sync_app")
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")
DEFAULT_CHECK_INTERVAL_SECONDS = 1.0  # Default to 1 second
current_check_interval_seconds = DEFAULT_CHECK_INTERVAL_SECONDS
automatic_monitoring_active = True # Controlled by interval > 0

# --- Network Information Storage ---
SERVER_IPS = []
SERVER_PORT = None

def ensure_config_dir_exists():
    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR)
        except OSError as e:
            print(f"[ERROR] Could not create config directory {CONFIG_DIR}: {e}")
            return False
    return True

def load_config():
    global current_check_interval_seconds, automatic_monitoring_active
    if not ensure_config_dir_exists():
        print("[CONFIG] Using default check interval due to config dir issue.")
        current_check_interval_seconds = DEFAULT_CHECK_INTERVAL_SECONDS
        automatic_monitoring_active = current_check_interval_seconds > 0
        return

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                current_check_interval_seconds = float(config.get('check_interval_seconds', DEFAULT_CHECK_INTERVAL_SECONDS))
                if current_check_interval_seconds <= 0:
                    current_check_interval_seconds = 0 # Treat negative or zero as disabled for interval timing
                    automatic_monitoring_active = False
                else:
                    automatic_monitoring_active = True
                print(f"[CONFIG] Loaded check interval: {current_check_interval_seconds}s. Monitoring active: {automatic_monitoring_active}")
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            print(f"[ERROR] Error loading config: {e}. Using defaults.")
            current_check_interval_seconds = DEFAULT_CHECK_INTERVAL_SECONDS
            automatic_monitoring_active = True
    else:
        print("[CONFIG] No config file found. Using defaults and creating one.")
        current_check_interval_seconds = DEFAULT_CHECK_INTERVAL_SECONDS
        automatic_monitoring_active = True
        save_config() # Create a default config file

def save_config():
    if not ensure_config_dir_exists():
        print("[CONFIG] Could not save config due to config dir issue.")
        return

    config_to_save = {'check_interval_seconds': current_check_interval_seconds}
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_to_save, f, indent=4)
        # print(f"[CONFIG] Saved check interval: {current_check_interval_seconds}s")
    except IOError as e:
        print(f"[ERROR] Could not write config file {CONFIG_FILE}: {e}")

def update_check_interval(new_interval_seconds: float):
    global current_check_interval_seconds, automatic_monitoring_active
    if new_interval_seconds < 0: new_interval_seconds = 0 # Floor at 0

    current_check_interval_seconds = new_interval_seconds
    if current_check_interval_seconds == 0:
        automatic_monitoring_active = False
        print(f"[CONFIG] Automatic clipboard monitoring DISABLED (interval set to 0).")
    else:
        automatic_monitoring_active = True
        print(f"[CONFIG] Updated check interval to: {current_check_interval_seconds}s. Monitoring active.")
    save_config()


# --- macOS Clipboard Utilities ---
def get_macos_clipboard_image():
    """Tries to get an image from macOS clipboard using osascript,
       returns (base64_data, format_str) or (None, None)"""
    print_prefix = "[GET_IMG_DEBUG_OSASCRIPT]"
    verbose_debug = False # Set to True for extremely detailed logs, False for quieter operation

    available_types_str = ""
    try:
        osa_info_proc = subprocess.Popen(['osascript', '-e', 'clipboard info'],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        osa_info_stdout, osa_info_stderr = osa_info_proc.communicate(timeout=1)
        if osa_info_stdout:
            available_types_str = osa_info_stdout.decode(errors='ignore').strip()
            if verbose_debug: print(f"{print_prefix} osascript clipboard info: {available_types_str}")
        if osa_info_stderr and osa_info_stderr.strip() and verbose_debug: # Only show stderr if verbose
            print(f"{print_prefix} osascript clipboard info STDERR: {osa_info_stderr.decode(errors='ignore').strip()}")
    except Exception as e_info:
        if verbose_debug: print(f"{print_prefix} Exception getting clipboard info via osascript: {e_info}")
        return None, None # If we can't get info, probably can't get image

    # Check if any common image types are even listed before attempting to get them
    # This reduces noise when clipboard is just text.
    image_type_indicators = ['PNGf', 'JPEG', 'TIFF', 'GIF', 'BMP ', 'jp2 '] # Note space in 'BMP '
    if not any(indicator in available_types_str for indicator in image_type_indicators):
        if verbose_debug: print(f"{print_prefix} No common image type indicators found in clipboard info. Skipping image fetch.")
        return None, None

    # If we proceed, it means an image type was likely found.
    if verbose_debug and available_types_str : print(f"{print_prefix} [VERBOSE] Potential image detected. Info: {available_types_str}")


    osascript_type_map = [
        {'applescript_type': 'PNG picture', 'class_hint': 'PNGf', 'common_name': 'png', 'magic': [b'\x89PNG\r\n\x1a\n']},
        {'applescript_type': 'JPEG picture','class_hint': 'JPEG', 'common_name': 'jpeg', 'magic': [b'\xff\xd8\xff']},
    ]

    for item in osascript_type_map:
        as_type = item['applescript_type']
        class_hint = item['class_hint'] # e.g. PNGf
        common_name = item['common_name']
        magic_bytes_list = item['magic']
        
        # Only try to get this specific image type if its indicator was in clipboard info
        if class_hint not in available_types_str and as_type not in available_types_str : # crude check
            if verbose_debug: print(f"{print_prefix} Skipping '{as_type}' as '{class_hint}' not in clipboard info.")
            continue

        if verbose_debug: print(f"{print_prefix} Attempting to get '{as_type}' (class hint '{class_hint}') via osascript...")
        
        applescript_command = f"get the clipboard as «class {class_hint}»"

        try:
            proc = subprocess.Popen(
                ['osascript', '-e', applescript_command],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(timeout=COMMUNICATE_TIMEOUT + 1)

            stdout_str = stdout.decode(errors='ignore').strip()
            stderr_str = stderr.decode(errors='ignore').strip()

            if verbose_debug or proc.returncode != 0 : # Print details if verbose or if there was an error
                print(f"{print_prefix} osascript for '{as_type}' | RC: {proc.returncode}")
                if stdout_str: print(f"{print_prefix}   ↳ STDOUT (first 100 chars): {stdout_str[:100]}")
                if stderr_str: print(f"{print_prefix}   ↳ STDERR: {stderr_str}")

            if proc.returncode == 0 and stdout_str:
                if stdout_str.startswith("«data ") and stdout_str.endswith("»"):
                    hex_data_part = stdout_str[len("«data "):-1]
                    actual_hex_data = ""
                    # Check if the hex_data_part starts with the class_hint (case-insensitive for robustness)
                    if hex_data_part.upper().startswith(class_hint.upper()) and len(hex_data_part) > len(class_hint):
                        actual_hex_data = hex_data_part[len(class_hint):]
                    elif hex_data_part.isalnum(): # Fallback if no class_hint prefix
                         actual_hex_data = hex_data_part
                    
                    if actual_hex_data:
                        try:
                            image_bytes = bytes.fromhex(actual_hex_data)
                            if verbose_debug: print(f"{print_prefix}     Successfully decoded {len(image_bytes)} bytes from hex for {common_name}.")
                            is_correct_type = any(image_bytes.startswith(magic) for magic in magic_bytes_list)
                            if is_correct_type:
                                if verbose_debug: print(f"{print_prefix}     ✓ [VERBOSE] Image validated as '{common_name}'. Returning.")
                                return base64.b64encode(image_bytes).decode('utf-8'), common_name
                            else:
                                if verbose_debug: print(f"{print_prefix}     ✗ Magic bytes DO NOT match for '{common_name}' after hex decode. Data: {image_bytes[:20]}")
                        except ValueError:
                            if verbose_debug: print(f"{print_prefix}     Error: Could not convert hex string to bytes: '{actual_hex_data[:50]}...'")
                    elif verbose_debug:
                        print(f"{print_prefix}     Could not extract actual hex data from: {hex_data_part}")
                elif verbose_debug:
                    print(f"{print_prefix}   STDOUT is not in expected «data ...» format.")
            elif proc.returncode == 1 and "Can't make some data into the expected type. (-1700)" in stderr_str:
                # This is an expected failure if the clipboard doesn't contain this specific image type
                if verbose_debug: print(f"{print_prefix}   '{as_type}' not found on clipboard or not convertible (expected error -1700).")
            # else: Other errors or no stdout

        except subprocess.TimeoutExpired:
            print(f"{print_prefix} osascript command timed out for '{as_type}'.")
        except FileNotFoundError:
            print(f"{print_prefix} CRITICAL ERROR: 'osascript' command not found.")
            return None, None
        except Exception as e:
            print(f"{print_prefix} Unexpected error with osascript for '{as_type}': {e}")

    if verbose_debug: print(f"{print_prefix} No suitable image was successfully retrieved and validated using osascript.")
    return None, None


def set_macos_clipboard_image(base64_data, img_format_hint="png"):
    print_prefix = "[SET_IMG_DEBUG]"
    verbose_debug = False # Set to True for detailed logs
    try:
        image_bytes = base64.b64decode(base64_data)
        if verbose_debug: print(f"{print_prefix} Attempting to set image to clipboard. Byte length: {len(image_bytes)}. Format hint: {img_format_hint}")
        proc = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = proc.communicate(input=image_bytes, timeout=COMMUNICATE_TIMEOUT)
        
        stderr_decoded = stderr.decode(errors='ignore').strip()
        if proc.returncode == 0:
            if verbose_debug: print(f"{print_prefix} pbcopy command for image executed successfully (RC 0).")
            if stderr_decoded and verbose_debug: print(f"{print_prefix} pbcopy STDERR (RC 0): {stderr_decoded}")
            return True
        else:
            print(f"{print_prefix} ERROR: pbcopy command for image failed with RC {proc.returncode}.")
            if stderr_decoded: print(f"{print_prefix} pbcopy STDERR (RC != 0): {stderr_decoded}")
            return False
            
    except base64.BinasciiError as e:
        print(f"{print_prefix} ERROR: Invalid base64 data received for image: {e}")
        return False
    except FileNotFoundError:
        print(f"{print_prefix} CRITICAL ERROR: 'pbcopy' command not found. Cannot set images to clipboard.")
        return False
    except subprocess.TimeoutExpired:
        print(f"{print_prefix} ERROR: pbcopy command timed out while setting image.")
        return False
    except Exception as e:
        print(f"{print_prefix} ERROR: Unexpected error setting macOS image clipboard: {e}")
        return False
# --- End macOS Clipboard Utilities ---

# --- Globals for state management ---
last_clipboard_content_hash_sent_or_echoed = None
last_received_content_hash = None
monitor_current_text_state = ""
monitor_current_image_b64_state = None
clients = []
clients_lock = threading.Lock()
stop_event = threading.Event() # Used to signal threads to stop

# --- Network and Client Handling functions ---
def send_message(sock, message_dict):
    try:
        json_data = json.dumps(message_dict).encode('utf-8')
        message_len = len(json_data)
        sock.sendall(struct.pack('>I', message_len))
        sock.sendall(json_data)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"Error sending to client {sock.getpeername()}: {e}. Removing client.")
        remove_client(sock)
    except Exception as e:
        print(f"Unexpected error sending message: {e}")

def receive_message(sock):
    try:
        raw_msglen = sock.recv(4)
        if not raw_msglen: return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        if not (0 < msglen < 20 * 1024 * 1024): 
            print(f"Warning: Invalid message length ({msglen} bytes). Closing connection.")
            return None
        data = b''
        while len(data) < msglen:
            packet = sock.recv(msglen - len(data))
            if not packet: return None
            data += packet
        return json.loads(data.decode('utf-8'))
    except (ConnectionResetError, BrokenPipeError, OSError, struct.error) as e:
        # print(f"Error receiving from client: {e}. Likely disconnected.") # Can be noisy
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON message: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error receiving message: {e}")
        return None

def handle_client(conn, addr):
    global last_received_content_hash, last_clipboard_content_hash_sent_or_echoed
    print(f"Client connected: {addr}")
    with clients_lock: clients.append(conn)
    try:
        while not stop_event.is_set():
            message = receive_message(conn)
            if message is None: break # Connection closed or error
            
            content_payload = message.get('content', '')
            msg_type = message.get('type')
            
            # Create hash based on actual payload, not just string representation for images
            if msg_type == 'image':
                # Assuming content_payload for image is base64 string
                payload_for_hash = content_payload.encode('utf-8')
            else: # text
                payload_for_hash = content_payload.encode('utf-8')

            received_hash_val = hashlib.md5(payload_for_hash).hexdigest()
            
            # Update local clipboard
            if msg_type == 'text':
                pyperclip.copy(content_payload)
                print(f"Server clipboard (text) updated by client {addr}.")
                # Update monitor's view of clipboard state to prevent immediate resend
                global monitor_current_text_state, monitor_current_image_b64_state
                monitor_current_text_state = content_payload
                monitor_current_image_b64_state = None 
            elif msg_type == 'image':
                img_format_hint = message.get('format', 'png')
                if set_macos_clipboard_image(content_payload, img_format_hint):
                    print(f"Server clipboard (image) updated by client {addr}.")
                    monitor_current_image_b64_state = content_payload
                    monitor_current_text_state = ""
                else:
                    print(f"Failed to set server clipboard image from client {addr} data.")
            
            # This assignment makes the echo suppression work.
            # The monitor will see this hash and not resend what was just received.
            last_received_content_hash = received_hash_val
            # Also, mark it as 'sent_or_echoed' because we don't want the monitor to
            # immediately pick it up as a new local change if the client sent something
            # that was ALREADY on the local clipboard.
            last_clipboard_content_hash_sent_or_echoed = received_hash_val

    except Exception as e:
        if not stop_event.is_set(): # Don't print errors if we are shutting down
            print(f"Error with client {addr}: {e}")
    finally:
        print(f"Client {addr} disconnected.")
        remove_client(conn)
        if conn:
            try: conn.close()
            except Exception: pass

def remove_client(sock):
    with clients_lock:
        if sock in clients:
            clients.remove(sock)

# --- Core Clipboard Processing Logic ---
def _get_current_clipboard_state():
    """Gets current clipboard content (image or text).
    Returns: (type_str, content_data, format_str_if_image_or_none)
    e.g., ("image", "base64string", "png") or ("text", "sometext", None) or (None, None, None) if empty/error
    """
    actual_clipboard_img_b64, actual_clipboard_img_fmt = None, None
    actual_clipboard_text = ""
    try:
        actual_clipboard_img_b64, actual_clipboard_img_fmt = get_macos_clipboard_image()
    except Exception as e:
        print(f"[CORE_LOGIC] Error in get_macos_clipboard_image(): {e}")

    try:
        if actual_clipboard_img_b64 is None: # Only try text if no image was definitively found
            pasted_text = pyperclip.paste()
            if pasted_text is not None: actual_clipboard_text = pasted_text
    except pyperclip.PyperclipException: # Expected if clipboard is not text or inaccessible
        actual_clipboard_text = ""
    except Exception as e:
        print(f"[CORE_LOGIC] Error in pyperclip.paste(): {e}")
        actual_clipboard_text = "" # Fallback

    if actual_clipboard_img_b64 is not None:
        return "image", actual_clipboard_img_b64, actual_clipboard_img_fmt
    elif actual_clipboard_text: # Only consider text if it's non-empty
        return "text", actual_clipboard_text, None
    else: # Clipboard is effectively empty or unreadable
        return None, None, None


def process_and_broadcast_clipboard_state(force_send=False):
    """
    Checks current clipboard, and if changed (or force_send is True),
    broadcasts to clients. Updates global state variables.
    Returns True if content was sent, False otherwise.
    """
    global last_clipboard_content_hash_sent_or_echoed, last_received_content_hash
    global monitor_current_text_state, monitor_current_image_b64_state

    content_type, content_data, content_format = _get_current_clipboard_state()

    current_hash = None
    if content_data is not None:
        current_hash = hashlib.md5(content_data.encode('utf-8')).hexdigest()
    
    # Determine if we need to send:
    # 1. Force send is True.
    # 2. Content changed from what we last sent/echoed.
    # 3. Content is not what we just received from another client (echo suppression).
    
    should_send = False
    if force_send:
        should_send = True
        # print("[PROCESS] Force send triggered.")
    elif current_hash != last_clipboard_content_hash_sent_or_echoed:
        if current_hash == last_received_content_hash:
            # print(f"[PROCESS] Clipboard content (hash {current_hash[:8] if current_hash else 'N/A'}, type {content_type}) matches last received. Echo, not re-sending.")
            last_clipboard_content_hash_sent_or_echoed = current_hash # Mark as echoed
            last_received_content_hash = None # Reset echo suppression for next distinct change
        else:
            should_send = True
            # print(f"[PROCESS] New local clipboard content detected (hash {current_hash[:8] if current_hash else 'N/A'}, type {content_type}).")
    # else: content is same as last sent/echoed, or no content. No send needed.

    if should_send:
        # Prepare message
        if content_data is None and (monitor_current_text_state or monitor_current_image_b64_state):
            # Clipboard became empty, send empty text to signify clear
            # print("[PROCESS] Clipboard cleared. Sending empty text.")
            message_dict = {"type": "text", "content": ""}
            current_hash_for_log = hashlib.md5("".encode('utf-8')).hexdigest()
        elif content_data is not None:
            message_dict = {"type": content_type, "content": content_data}
            if content_type == "image":
                message_dict["format"] = content_format
            current_hash_for_log = current_hash
        else: # No content and clipboard was already "empty" in our state, do nothing
            # print("[PROCESS] Clipboard empty and was already considered empty. No send.")
            # Update state even if not sending, to reflect current reality
            monitor_current_text_state = "" if content_type != "text" else content_data
            monitor_current_image_b64_state = None if content_type != "image" else content_data
            return False


        with clients_lock:
            current_clients_list = list(clients) # Iterate over a copy

        if not current_clients_list:
            if content_data or (not content_data and (monitor_current_text_state or monitor_current_image_b64_state)):
                 print(f"[PROCESS] Clipboard changed (type {content_type if content_data else 'cleared'}), but no clients connected.")
        else:
            for client_conn in current_clients_list:
                send_message(client_conn, message_dict)
            
            if content_data:
                print(f"[PROCESS] Sent new clipboard content (type {content_type}, hash {current_hash_for_log[:8] if current_hash_for_log else 'N/A'}) to {len(current_clients_list)} client(s).")
            elif (not content_data and (monitor_current_text_state or monitor_current_image_b64_state)):
                 print(f"[PROCESS] Sent cleared clipboard state to {len(current_clients_list)} client(s).")


        last_clipboard_content_hash_sent_or_echoed = current_hash # Update with the hash of what was actually sent/processed
        if not force_send: # If it was a force send, don's mess with received hash as it's an explicit user action
            last_received_content_hash = None # Clear after a successful send/echo cycle for local changes

        # Update monitor's internal state to reflect the new clipboard reality that was just processed
        if content_type == "image":
            monitor_current_image_b64_state = content_data
            monitor_current_text_state = ""
        elif content_type == "text":
            monitor_current_text_state = content_data
            monitor_current_image_b64_state = None
        else: # Clipboard is empty
            monitor_current_text_state = ""
            monitor_current_image_b64_state = None
        return True
    
    # Even if not sent, update monitor's view of current state if it differs from clipboard
    # This ensures monitor_current_text/image_state are accurate reflections of the actual clipboard
    # if no change was detected worthy of sending.
    is_actual_image = (content_type == "image" and content_data is not None)
    actual_text = content_data if content_type == "text" else ""
    actual_image = content_data if is_actual_image else None

    if monitor_current_text_state != actual_text or monitor_current_image_b64_state != actual_image:
        monitor_current_text_state = actual_text
        monitor_current_image_b64_state = actual_image
        # print("[PROCESS DEBUG] Synced monitor state with actual clipboard (no send)")

    return False

# --- Clipboard Monitor Thread ---
def clipboard_monitor_thread_func():
    """Monitors clipboard for changes and broadcasts them."""
    global automatic_monitoring_active, current_check_interval_seconds
    
    print("Clipboard monitor thread started.")
    load_config() # Load initial interval

    while not stop_event.is_set():
        if automatic_monitoring_active and current_check_interval_seconds > 0:
            # print(f"[MONITOR] Checking clipboard (interval: {current_check_interval_seconds}s)")
            process_and_broadcast_clipboard_state(force_send=False)
            stop_event.wait(current_check_interval_seconds) # Use event's wait for interruptibility
        else:
            # print("[MONITOR] Automatic monitoring is paused or interval is 0. Sleeping...")
            stop_event.wait(5) # Sleep longer if not active, but still check stop_event
    print("Clipboard monitor thread stopped.")

def manual_trigger_send_clipboard_content():
    """Manually triggers a clipboard check and sends if content is new or different."""
    print("[MANUAL TRIGGER] Initiated manual clipboard check and send.")
    if process_and_broadcast_clipboard_state(force_send=True): # force_send=True for manual
        print("[MANUAL TRIGGER] Content processed/sent.")
    else:
        print("[MANUAL TRIGGER] No new content to send or clipboard empty.")

# --- Network Info and Main Execution ---
def get_network_ips():
    global SERVER_IPS # Store for external access
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
        except Exception as e: print(f"[ERROR] Could not get IPs using netifaces: {e}")
    if not ips:
        try:
            hostname = socket.gethostname()
            primary_ip = socket.gethostbyname(hostname)
            if primary_ip and not primary_ip.startswith('127.'): 
                if primary_ip not in ips: ips.append(primary_ip)
            _, _, ipaddrlist = socket.gethostbyname_ex(hostname)
            for ip_addr in ipaddrlist:
                if ip_addr and not ip_addr.startswith('127.') and ip_addr not in ips: ips.append(ip_addr)
        except socket.gaierror: print("[WARNING] Could not resolve hostname using standard methods.")
    
    SERVER_IPS = list(set(ips)) # Update the global
    return SERVER_IPS

def get_server_network_info():
    """Returns the determined server IPs and port."""
    return SERVER_IPS, SERVER_PORT

def start_server_thread_func():
    """Handles incoming client connections."""
    global SERVER_PORT # Store for external access
    print("Server thread started. Waiting for client connections...")
    # Initial load of config, primarily for the monitor thread, but good to have consistent state
    load_config()
    SERVER_PORT = PORT # Store the port
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
    except OSError as e:
        print(f"!!! CRITICAL ERROR: Could not bind to {HOST}:{PORT} - {e}")
        stop_event.set() # Signal other threads to stop
        return
    
    server_socket.listen()
    server_socket.settimeout(1.0) # Timeout for accept() to allow checking stop_event

    print(f"\nClipboard Sync Server is RUNNING.")
    print(f"Listening on port: {PORT}")
    print(f"Binding to host : {HOST}")
    print("-" * 60)
    possible_ips = get_network_ips()
    if possible_ips:
        print("To connect from your Android device, use ONE of these IP addresses")
        print("(Device MUST be on the SAME Wi-Fi network):")
        for ip in possible_ips: print(f"  ➡️   {ip}")
        print(f"\nAnd use port: {PORT}")
    else:
        print("Could not auto-determine Mac's IP. Find manually (System Settings -> Wi-Fi -> Details -> TCP/IP).")
        print(f"Then use that IP and port {PORT} in the Android app.")
    print("-" * 60)
    print("Waiting for a client to connect...\n")

    threads = []
    try:
        while not stop_event.is_set():
            try:
                conn, addr = server_socket.accept()
                conn.setblocking(True) # Ensure client sockets are blocking after accept
                client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
                threads.append(client_thread)
            except socket.timeout:
                continue # Allow loop to check stop_event
            except KeyboardInterrupt: # Should be handled by main app's shutdown
                print("\nServer thread received KeyboardInterrupt, initiating shutdown...")
                stop_event.set()
                break
            except Exception as e:
                if not stop_event.is_set():
                    print(f"Error accepting new connection: {e}")
                time.sleep(0.5) # Brief pause before retrying accept on error
    finally:
        print("Server thread shutting down...")
        if server_socket:
            server_socket.close()
        for t in threads:
            if t.is_alive():
                t.join(timeout=1) # Give client threads a moment to finish
        print("Server thread stopped.")

def main_cli_start():
    # This function is for standalone CLI execution if needed for testing.
    # The menubar app will call start_server_thread_func and clipboard_monitor_thread_func directly.
    
    # Ensure stop_event is clear at start
    stop_event.clear()

    # Load configuration first
    load_config()

    monitor_thread = threading.Thread(target=clipboard_monitor_thread_func, daemon=True)
    server_thread = threading.Thread(target=start_server_thread_func, daemon=True)

    monitor_thread.start()
    server_thread.start()

    try:
        while monitor_thread.is_alive() and server_thread.is_alive():
            time.sleep(0.5) # Keep main thread alive
    except KeyboardInterrupt:
        print("\n[CLI MAIN] KeyboardInterrupt detected. Shutting down...")
    finally:
        print("[CLI MAIN] Initiating shutdown sequence...")
        stop_event.set() # Signal threads to stop
        
        if monitor_thread.is_alive():
            print("[CLI MAIN] Waiting for monitor thread to stop...")
            monitor_thread.join(timeout=5) # Wait for monitor thread
        if server_thread.is_alive():
            print("[CLI MAIN] Waiting for server thread to stop...")
            server_thread.join(timeout=5) # Wait for server thread
        
        print("[CLI MAIN] All threads stopped. Exiting.")

if __name__ == '__main__':
    # When run directly, start in CLI mode.
    # The GUI app will import and use functions like:
    # update_check_interval, manual_trigger_send_clipboard_content,
    # start_server_thread_func, clipboard_monitor_thread_func, stop_event
    main_cli_start()