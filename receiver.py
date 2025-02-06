import time
from scapy.all import sniff, IPv6
from scapy.layers.inet6 import IPv6ExtHdrDestOpt, PadN, IPv6ExtHdrHopByHop
import threading
import argparse
from tkinter import INSERT
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import os
# Global variables
stop_event = threading.Event()
buffer_ = []  # Buffer to store PadN data (in hex format)
msg = []  # List to store decrypted messages
alternate_packet_flag = False  # Flag to handle alternate packets
interface = None  # Network interface
target_ipv6 = ""
logs=[]
scroll=None

def inject_logs(scroll,log):
    scroll.configure(state ='normal')
    scroll.clipboard_clear()
    for log in logs:
        scroll.insert(INSERT,log+'\n')
    scroll.configure(state ='disabled')


def decrypt_aes(ciphertext_hex, key):
    """Decrypt ciphertext using AES-256-CBC."""
    # Convert ciphertext from hex to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    # Extract IV (first 16 bytes) and actual ciphertext
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    
    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()

def verify_data(received_data_hex, expected_packets, short_hash):
    """Verify the integrity of the received data."""
    # Compute the full hash of the received data
    received_data_bytes = bytes.fromhex(received_data_hex)
    full_hash = hashlib.sha256(received_data_bytes).digest()
    computed_short_hash = full_hash[:8]  # Use only the first 8 bytes
    
    # Compare with the expected short hash
    if computed_short_hash != short_hash:
        print("Short hash verification failed: Data corrupted.")
        logs.append("Short hash verification failed: Data corrupted.")
        # inject_logs(scroll,logs)
        return False
    
    # Compare the number of packets
    if len(buffer_) != expected_packets:
        print(f"Packet count mismatch: Expected {expected_packets}, Received {len(buffer_)}.")
        logs.append(f"Packet count mismatch: Expected {expected_packets}, Received {len(buffer_)}.")
        # inject_logs(scroll,logs)
        return False
    
    print("Short hash verification succeeded: Data is intact.")
    print("Packet count verified.")
    logs.append("Short hash verification succeeded: Data is intact.")
    logs.append("Packet count verified.")
    # inject_logs(scroll,logs)
    return True

def packet_callback(packet):
    """Callback function for processing each received packet."""
    global alternate_packet_flag, buffer_, scroll, logs
    
    if stop_event.is_set():
        return  # Stop processing if the stop event is set

    # Handle Destination Options Header
    if IPv6ExtHdrDestOpt in packet:
        dst_opt_hdr = packet[IPv6ExtHdrDestOpt]
        for opt in dst_opt_hdr.options:
            if isinstance(opt, PadN):  # Check if option is PadN
                padn_data = opt.optdata
                
                # Identify metadata packet by length (12 bytes)
                if len(padn_data) == 12:
                    # Parse metadata packet
                    total_packets_binary = padn_data[:4]  # First 32 bits (4 bytes)
                    expected_packets = int.from_bytes(total_packets_binary, byteorder='big')
                    
                    # Extract the short hash (remaining 8 bytes)
                    short_hash = padn_data[4:]
                    
                    print(f"Metadata Packet Received: Total Packets = {expected_packets}")
                    logs.append(f"Metadata Packet Received: Total Packets = {expected_packets}")
                    # inject_logs(scroll,logs)
                    # Verify and decrypt the accumulated data
                    if buffer_:
                        combined_hex = "".join(buffer_)  # Combine all hex strings
                        
                        # Verify data integrity
                        if verify_data(combined_hex, expected_packets, short_hash):
                            try:
                                decrypted_message = decrypt_aes(combined_hex, key)
                                print(f"Decrypted Message: {decrypted_message}")
                                logs.append(f"Decrypted Message: {decrypted_message}")
                                inject_logs(scroll,logs)
                                msg.append(decrypted_message)
                            except Exception as e:
                                print(f"Decryption failed: {e}")
                        
                        # Reset buffer after decryption
                        buffer_.clear()
                    
                    continue
                
                # Skip alternate packets if the interface is 'lo'
                if interface == "lo":
                    if not alternate_packet_flag:
                        alternate_packet_flag = not alternate_packet_flag
                        continue
                
                # Collect PadN data
                buffer_.append(padn_data.hex())  # Store data in hex format
                print(f"Collected PadN Data (Hex): {padn_data.hex()}")
                
                # Toggle the alternate packet flag
                if interface == "lo":
                    alternate_packet_flag = not alternate_packet_flag

def sniff_thread():
    global interface, stop_event
    # Set up the BPF filter
    _filter = f"ip6 src host {target_ipv6}" if target_ipv6 else "ip6"

    print("Sniffing started in Background. Press Ctrl+C to stop.")
    try:
        # Sniff only IPv6 packets
        sniff(
            iface=interface,  # Use the specified interface
            filter=_filter,  # Capture all IPv6 packets
            prn=packet_callback,
            store=False,
            timeout=1200,
            stop_filter=lambda x: stop_event.is_set()
        )
    except KeyboardInterrupt:
        print("\nSniffing stopped.")
        stop_event.set()
        return

def delete_firewall_rule():
    print("Deleting Firewall Rule: "+name)
    delete_process = os.popen('netsh advfirewall firewall delete rule name="'+name)
    read_delete_process = delete_process.read()
    delete_process.close()
    print(read_delete_process)

def reciever_main(password,target_ip,scrll,interFace,myip):
    global key, interface,target_ipv6, scroll, logs,name # AES decryption key and network interface

    target_ipv6 = target_ip
    interface = interFace if interFace else "Wi-Fi"
    scroll = scrll
    
    #firewall rule
    name = f'Allow incoming connections from {target_ip} to {myip}.'
    print("Checking if rule exists in firewall:")
    check_output = os.popen('netsh advfirewall firewall show rule name="'+name+'"')
    read_check_output = check_output.read().split()
    if(read_check_output[-1]=="criteria."):
        print("No rule exists.")
        print('Adding Firewall Rule to allow incoming connections from "'+target_ip+'" to "'+myip+'".')
        process = os.popen('netsh advfirewall firewall add rule name="'+name+'" dir=in action=allow enable=yes protocol=any remoteip='+target_ip+' localip='+myip+' profile=any')
        readProcess = process.read()
        process.close()
        print(readProcess)
    else:
        print("Rule Exists, continuing.")

    # Derive a 32-byte key from the password using SHA-256
    key = hashlib.sha256(password.encode()).digest()

    # Prompt the user for the network interface
    #interface = input("Enter the network interface (e.g., lo,eth0, wlan0, Wi-Fi)[default:Wi-Fi]: ")

    sniff_thread_instance = threading.Thread(target=sniff_thread)
    sniff_thread_instance.start()

    

