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

def receive_message(sock, crypto: Optional[CryptoManager] = None):
    try:
        raw_msglen = sock.recv(4)
        if not raw_msglen: return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        
        # Increase limit for encrypted images if needed, but 20MB is plenty
        if not (0 < msglen < 20 * 1024 * 1024): 
            print(f"[PROTOCOL] Warning: Invalid message length ({msglen} bytes).")
            return None
            
        data = b''
        while len(data) < msglen:
            packet = sock.recv(msglen - len(data))
            if not packet: return None
            data += packet
            
        if crypto:
            decrypted_data = crypto.decrypt(data)
            if decrypted_data is None:
                print("[PROTOCOL] Decryption failed.")
                return None
            return json.loads(decrypted_data.decode('utf-8'))
        else:
            return json.loads(data.decode('utf-8'))
            
    except (ConnectionResetError, BrokenPipeError, OSError, struct.error):
        return None
    except json.JSONDecodeError as e:
        print(f"[PROTOCOL] Error decoding JSON: {e}")
        return None
    except Exception as e:
        print(f"[PROTOCOL] Unexpected error receiving: {e}")
        return None
