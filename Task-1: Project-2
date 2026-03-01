import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64
from datetime import datetime

'''Server Side'''

# pre-shared key (match server)
KEY = b'12345678901234567890123456789012'

def log_message(message, msg_type="SENT"):
    # log messages with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open('client_chat.log', 'a') as log_file:
        log_file.write(f"[{timestamp}] {msg_type}: {message}\n")

def encrypt_msg(msg):
    # encrypting message with random IV and return IV + encrypted data
    # generating random IV for this message
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    padded_msg = pad(msg.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_msg)
    
    # returning IV + encrypted data (IV doesn't need to be secret)
    return base64.b64encode(iv + encrypted).decode('utf-8')

def main():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 5000))
        print("Connected to server. Type 'quit' to exit.\n")
        log_message("Client connected to server", "CONNECTION")
        
        while True:
            message = input("You: ")
            if message.lower() == 'quit':
                print("Disconnecting...")
                log_message("Client disconnected", "DISCONNECTION")
                break
            if not message:
                continue
            
            # encrypting and sending message
            encrypted_msg = encrypt_msg(message)
            client_socket.sendall(encrypted_msg.encode())
            print(f"[Encrypted]: {encrypted_msg[:50]}...\n")
            log_message(f"Sent: {message}", "SENT")
            
    except ConnectionRefusedError:
        print("Error: Could not connect to server. Make sure server is running.")
        log_message("Failed to connect to server", "ERROR")
    except Exception as e:
        print(f"Error: {e}")
        log_message(f"Error: {e}", "ERROR")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()


'''Client Side'''

# pre-shared key (match server)
KEY = b'12345678901234567890123456789012'

def log_message(message, msg_type="SENT"):
    # log messages with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open('client_chat.log', 'a') as log_file:
        log_file.write(f"[{timestamp}] {msg_type}: {message}\n")

def encrypt_msg(msg):
    # encrypting message with random IV and return IV + encrypted data
    # generating random IV for this message
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    padded_msg = pad(msg.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_msg)
    
    # returning IV + encrypted data (IV doesn't need to be secret)
    return base64.b64encode(iv + encrypted).decode('utf-8')

def main():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 5000))
        print("Connected to server. Type 'quit' to exit.\n")
        log_message("Client connected to server", "CONNECTION")
        
        while True:
            message = input("You: ")
            if message.lower() == 'quit':
                print("Disconnecting...")
                log_message("Client disconnected", "DISCONNECTION")
                break
            if not message:
                continue
            
            # encrypting and sending message
            encrypted_msg = encrypt_msg(message)
            client_socket.sendall(encrypted_msg.encode())
            print(f"[Encrypted]: {encrypted_msg[:50]}...\n")
            log_message(f"Sent: {message}", "SENT")
            
    except ConnectionRefusedError:
        print("Error: Could not connect to server. Make sure server is running.")
        log_message("Failed to connect to server", "ERROR")
    except Exception as e:
        print(f"Error: {e}")
        log_message(f"Error: {e}", "ERROR")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
