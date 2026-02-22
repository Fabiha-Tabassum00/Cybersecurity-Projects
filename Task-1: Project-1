import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
import time
import logging

# Blank your screen
subprocess.call('clear', shell=True)

logging.basicConfig(
    filename='scan_results.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

print("======== Project - 1: Port Scanner =========")

max_threads = 100

def generate_port_chunks(port_range):
    port_ranges = port_range.split('-')
    start_port = int(port_ranges[0])
    end_port = int(port_ranges[1])

    # chunk size calculation
    total_ports = end_port - start_port + 1
    chunk_size = max(1, total_ports // max_threads)
    
    port_chunks = []
    for i in range(max_threads):
        chunk_start = start_port + (chunk_size * i)
        chunk_end = chunk_start + chunk_size - 1
        # making sure to not to exceed the end port
        if chunk_start > end_port:
            break
        if chunk_end > end_port:
            chunk_end = end_port
        port_chunks.append([chunk_start, chunk_end])
    return port_chunks

def scan(ip_add, port_chunk):
    print(f"Scanning {ip_add} from {port_chunk[0]} to {port_chunk[1]}...")

    for port in range(int(port_chunk[0]), int(port_chunk[1]) + 1):
        try:
            scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            scan_socket.settimeout(2)
            result = scan_socket.connect_ex((ip_add, port))
            
            if result == 0:  # successful connection
                message = f"Port {port} is open."
                print(f"[+] {message}")
                logging.info(message)
            else:
                # different error codes indicate different states
                if result == 111:  # connection refused
                    message = f"Port {port} is closed."
                    print(f"[-] {message}")
                    logging.info(message)
                elif result == 110:  # timeout
                    message = f"Port {port} timeout."
                    print(f"[!] {message}")
                    logging.info(message)
                else:                  # connection error
                    message = f"Port {port} Error (code: {result})"
                    print(f"[?] {message}")
                    logging.info(message)
            
            scan_socket.close()
            
        except socket.error as e:
            message = f"Port {port} Socket error: {e}"
            print(f"[X] {message}")
            logging.error(message)

def main():
    # Get user input
    print("~~~~~ Port Scanner ~~~~~")
    ip_address = input("Enter IP address to scan: ").strip()   # single host
    
    while True:
        port_range = input("Enter port range (e.g., 1-1000): ").strip()  # single port e.g, 80-80, range of ports e.g, 1-1000
        try:
            start, end = map(int, port_range.split('-'))
            if start < 1 or end > 65535 or start > end:  # valid port range
                print("Invalid port range. Ports must be between 1-65535.")
                continue
            break
        except ValueError:
            print("Invalid format. Please use format like '1-1000'")
    
    print(f"\nTarget: {ip_address}")
    print(f"Port range: {port_range}")
    print(f"Using {max_threads} threads\n")
    
    port_chunks = generate_port_chunks(port_range)
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(scan, [ip_address] * len(port_chunks), port_chunks)
    
    end_time = time.time()
    print(f"\nScan completed in {end_time - start_time:.2f} seconds.")

if __name__ == '__main__':
    main()
