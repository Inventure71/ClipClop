import json
import struct
import socket
from typing import Optional
from .crypto import CryptoManager

def send_message(sock, message_dict: dict, crypto: Optional[CryptoManager] = None):
    try:
        json_data = json.dumps(message_dict).encode('utf-8')
        
        if crypto:
            data_to_send = crypto.encrypt(json_data)
        else:
            data_to_send = json_data
            
        message_len = len(data_to_send)
        sock.sendall(struct.pack('>I', message_len))
        sock.sendall(data_to_send)
        return True
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        # print(f"[PROTOCOL] Error sending to {sock.getpeername()}: {e}")
        return False
    except Exception as e:
        print(f"[PROTOCOL] Unexpected error sending message: {e}")
        return False

def _recv_bytes(sock, count, allow_timeout_at_start=False):
    """
    Helper to ensure exactly count bytes are read. 
    Raises socket.timeout ONLY if allow_timeout_at_start is True and we timeout BEFORE reading any bytes.
    Otherwise, loops until bytes are read or socket error/close.
    """
    data = b''
    while len(data) < count:
        try:
            packet = sock.recv(count - len(data))
            if not packet:
                # Connection closed by peer (EOF)
                return None
            data += packet
        except socket.timeout:
            if allow_timeout_at_start and len(data) == 0:
                 # We haven't started reading yet, so it's safe to raise timeout
                 raise
            # If we are in the middle of reading, we MUST continue waiting.
            # We cannot abort a partial read without losing sync.
            continue 
        except (ConnectionResetError, BrokenPipeError):
             # Connection was forcibly closed
             return None
        except BlockingIOError:
             # Handle non-blocking sockets if ever used
             continue
    return data

def receive_message(sock, crypto: Optional[CryptoManager] = None):
    try:
        # Read message length (4 bytes)
        # We allow timeout here because it's the start of a message. 
        # If we timeout waiting for the header, it just means no message is coming yet.
        try:
            raw_msglen = _recv_bytes(sock, 4, allow_timeout_at_start=True)
        except socket.timeout:
            # Timeout waiting for message start - this is normal for idle connection
            raise
            
        if not raw_msglen:
            return None
            
        msglen = struct.unpack('>I', raw_msglen)[0]
        
        # Increase limit for encrypted images if needed, but 20MB is plenty
        if not (0 < msglen < 20 * 1024 * 1024): 
            print(f"[PROTOCOL] Warning: Invalid message length ({msglen} bytes).")
            return None
            
        # For body, we definitely want to wait until we get it all. 
        # We DO NOT allow timeout to abort here because we have committed to reading a message.
        data = _recv_bytes(sock, msglen, allow_timeout_at_start=False)
        if not data:
            return None
            
        if crypto:
            decrypted_data = crypto.decrypt(data)
            if decrypted_data is None:
                print("[PROTOCOL] Decryption failed.")
                return None
            return json.loads(decrypted_data.decode('utf-8'))
        else:
            return json.loads(data.decode('utf-8'))
    
    # CRITICAL: Handle socket.timeout BEFORE OSError because socket.timeout is a subclass of OSError in Python 3
    except socket.timeout:
        # Re-raise timeout so _client_loop can handle it
        raise
    except (ConnectionResetError, BrokenPipeError, struct.error):
        return None
    except json.JSONDecodeError as e:
        print(f"[PROTOCOL] Error decoding JSON: {e}")
        return None
    except OSError as e:
        # Other OS-level socket errors (but not timeout, which was already handled above)
        print(f"[PROTOCOL] OS error: {e}")
        return None
