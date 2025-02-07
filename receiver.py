from time import strftime,localtime
from scapy.all import sniff, IPv6
from scapy.layers.inet6 import IPv6ExtHdrDestOpt, PadN, IPv6ExtHdrHopByHop
import threading
import argparse
from tkinter import INSERT,END
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import os

# global variables
stop_event = threading.Event()
buffer_ = []  
msg = []  
alternate_packet_flag = False 
interface = None  
target_ipv6 = ""
logs=[]
scroll=None

def inject_logs(scroll,log):
    scroll.configure(state ='normal')
    scroll.clipboard_clear()
    for log in logs:
        scroll.insert(INSERT,log+'\n')
    scroll.configure(state ='disabled')
    scroll.yview(END)
    scroll.yview_scroll(-4,"units")
    logs.clear()
    # scroll.clipboard_clear()


def decrypt_aes(ciphertext_hex, key):
    """Decrypt ciphertext using AES-256-CBC."""
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()

def verify_data(received_data_hex, expected_packets, short_hash):
    """Verify the integrity of the received data."""
    received_data_bytes = bytes.fromhex(received_data_hex)
    full_hash = hashlib.sha256(received_data_bytes).digest()
    computed_short_hash = full_hash[:8]  
    if computed_short_hash != short_hash:
        print("Short hash verification failed: Data corrupted.")
        logs.append("Short hash verification failed: Data corrupted.")
        # inject_logs(scroll,logs)
        return False
    
    if len(buffer_) != expected_packets:
        print(f"Packet count mismatch: Expected {expected_packets}, Received {len(buffer_)}.")
        logs.append(f"Packet count mismatch: Expected {expected_packets}, Received {len(buffer_)}.")
        # inject_logs(scroll,logs)
        return False
    
    print("Short hash verification succeeded: Data is intact.")
    print("Packet count verified.")
    # logs.append("Short hash verification succeeded: Data is intact.")
    # logs.append("Packet count verified.")
    # inject_logs(scroll,logs)
    return True

def packet_callback(packet):
    """Callback function for processing each received packet."""
    global alternate_packet_flag, buffer_, scroll, logs
    
    if stop_event.is_set():
        return  

    if IPv6ExtHdrDestOpt in packet:
        dst_opt_hdr = packet[IPv6ExtHdrDestOpt]
        for opt in dst_opt_hdr.options:
            if isinstance(opt, PadN):
                padn_data = opt.optdata
                
                # metadata
                if len(padn_data) == 12:
                    total_packets_binary = padn_data[:4]  # first 32 bits (4 bytes)
                    expected_packets = int.from_bytes(total_packets_binary, byteorder='big')
                    
                    short_hash = padn_data[4:]
                    
                    print(f"Metadata Packet Received: Total Packets = {expected_packets}")
                    curr_time = strftime("[%H:%M:%S]",localtime())
                    logs.append(f"{curr_time} Metadata Packet Received: Total Packets = {expected_packets}")
                    # inject_logs(scroll,logs)
                    # verify and decrypt
                    if buffer_:
                        combined_hex = "".join(buffer_)  
                        
                        # verify data integrity
                        if verify_data(combined_hex, expected_packets, short_hash):
                            try:
                                decrypted_message = decrypt_aes(combined_hex, key)
                                print(f"Decrypted Message: {decrypted_message}")
                                curr_time = strftime("[%H:%M:%S]",localtime())
                                logs.append(f"{curr_time} Decrypted Message: {decrypted_message}\n")
                                inject_logs(scroll,logs)
                                logs.clear()
                                msg.append(decrypted_message)
                            except Exception as e:
                                print(f"Decryption Failed: Invalid Key\n")
                                curr_time = strftime("[%H:%M:%S]",localtime())
                                logs.append(f"{curr_time} Decryption failed: Invalid Key\n")
                                inject_logs(scroll,logs)
                                logs.clear()
                        
                        # reset
                        buffer_.clear()
                    
                    continue
                
                # skip alternate packets if interface is 'lo'
                if interface == "lo":
                    if not alternate_packet_flag:
                        alternate_packet_flag = not alternate_packet_flag
                        continue
                
                # collect padn data
                buffer_.append(padn_data.hex())
                print(f"Collected PadN Data (Hex): {padn_data.hex()}")
                
                # toggle alternate packet flag
                if interface == "lo":
                    alternate_packet_flag = not alternate_packet_flag

def sniff_thread():
    global interface, stop_event
    # filter
    _filter = f"ip6 src host {target_ipv6}" if target_ipv6 else "ip6"

    print("Sniffing started in Background. Press Ctrl+C to stop.")
    try:
        # sniff only ipv6 packets
        sniff(
            iface=interface,  
            filter=_filter,  
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
    global key, interface,target_ipv6, scroll, logs,name 

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

    # derive 32-byte key
    key = hashlib.sha256(password.encode()).digest()

    #interface = input("Enter the network interface (e.g., lo,eth0, wlan0, Wi-Fi)[default:Wi-Fi]: ")

    sniff_thread_instance = threading.Thread(target=sniff_thread)
    sniff_thread_instance.start()

    

