from scapy.all import *
from scapy.layers.inet6 import IPv6ExtHdrDestOpt, PadN, IPv6ExtHdrHopByHop, IPv6, UDP
from datetime import datetime
from time import gmtime,strftime
import argparse
from tkinter import INSERT
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import hashlib

# interface = "Wi-Fi"
# logs = []
scroll = None

def inject_logs(scroll,log):
    scroll.configure(state ='normal')
    scroll.clipboard_clear()
    for log in logs:
        scroll.insert(INSERT,log+'\n')
    scroll.configure(state ='disabled')
    logs.clear()

def ascii_to_binary(ascii_string):
    """Convert an ASCII string to a binary string."""
    binary_string = ''.join(format(ord(char), '08b') for char in ascii_string)
    return binary_string

def pad_binary_to_32bit(binary_string):
    """Pad the binary string to ensure its length is a multiple of 32."""
    padding_length = (32 - len(binary_string) % 32) % 32
    return binary_string + '0' * padding_length

def split_into_32bit_chunks(binary_string):
    """Split the binary string into 32-bit chunks."""
    return [binary_string[i:i+32] for i in range(0, len(binary_string), 32)]

def binary_to_bytes(binary_chunk):
    """Convert a binary string to bytes."""
    return int(binary_chunk, 2).to_bytes(len(binary_chunk) // 8, byteorder='big')

def encrypt_aes(message, key):
    """Encrypt a message using AES-256-CBC."""
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext

def create_and_send_packet(secret_message, src_ip, dst_ip):
    #check if secret message is a multiple of 32 bits
    if len(secret_message) % 32 != 0:
        raise ValueError("Secret message must be a multiple of 32 bits long.")
    
    #split 32-bit chunks
    chunks = split_into_32bit_chunks(secret_message)
    
    # Create IPv6 base header
    ipv6_packet = IPv6(src=src_ip, dst=dst_ip)
    
    #add Destination Options Header
    _options = []
    for chunk in chunks:
        padding_data = binary_to_bytes(chunk)
        _options.append(PadN(optdata=padding_data))
    
    ipv6_packet /= IPv6ExtHdrDestOpt(options=_options)
    ipv6_packet /= UDP(sport=53, dport=53)
    
    #MTU
    packet_size = len(ipv6_packet)
    mtu = 1500
    if packet_size > mtu:
        print(f"Warning: Packet size ({packet_size} bytes) exceeds MTU ({mtu} bytes).")
        curr_time = strftime("[%H:%M:%S]",gmtime())
        logs.append(f"{curr_time} Warning: Packet size ({packet_size} bytes) exceeds MTU ({mtu} bytes).")
        inject_logs(scroll,f"{curr_time} Warning: Packet size ({packet_size} bytes) exceeds MTU ({mtu} bytes).")
        return None
    
    # Send
    print(f"Sending packet for {len(chunks)} PadN options.", padding_data)
    # logs.append(f"Sending packet for {len(chunks)} PadN options. {padding_data}")
    # inject_logs(scroll,f"Sending packet for {len(chunks)} PadN options. {padding_data}")
    send(ipv6_packet, verbose=False, iface=interface)
    
    return ipv6_packet

def create_and_send_metadata_packet(total_packets, short_hash, src_ip, dst_ip):
    """Create and send a packet containing metadata (total packets and short hash)."""
    ipv6_packet = IPv6(src=src_ip, dst=dst_ip)
    
    total_packets_bytes = total_packets.to_bytes(4, byteorder='big')
    
    metadata = total_packets_bytes + short_hash
    
    ipv6_packet /= IPv6ExtHdrDestOpt(options=[PadN(optdata=metadata)])
    ipv6_packet /= UDP(sport=53, dport=53)
    
    # Send
    print("Sending metadata packet.")
    
    curr_time = strftime("[%H:%M:%S]",gmtime())
    logs.append(f"{curr_time} Sending metadata packet.")
    inject_logs(scroll,f"\n{curr_time} Sending metadata packet.")
    send(ipv6_packet, verbose=False, iface=interface)
    
    return ipv6_packet

#Main 
def sender_main(ip,user_input,password,scrl,myIP,interFace):
    global pcap_filename,scroll,interface
    global logs
    logs = []
    interface = interFace if interFace else "Wi-Fi"
    scroll= scrl
    # get the destination ip from cmdline argument
    src_ip = myIP
    dst_ip = ip
    
    # derive 32-byte key 
    key = hashlib.sha256(password.encode()).digest()
    
    #PCAP
    pcap_filename = f"sent_packets_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
    print(f"Logging sent packets to: {pcap_filename}")
    
    sent_packets = []
    
    try:
       
        encrypted_message = encrypt_aes(user_input, key)
        
        full_hash = hashlib.sha256(encrypted_message).digest()
        short_hash = full_hash[:8]  # only 8 bytes
        
        # tobinary
        binary_input = ''.join(format(byte, '08b') for byte in encrypted_message)
        
        # padding
        padded_binary = pad_binary_to_32bit(binary_input)
        
        #chunck
        thirty_two_bit_chunks = split_into_32bit_chunks(padded_binary)
        
        total_packets = len(thirty_two_bit_chunks)
        
        # sending
        for chunk in thirty_two_bit_chunks:
            packet = create_and_send_packet(chunk, src_ip, dst_ip)
            if packet:
                sent_packets.append(packet)
        
        # metadata packet check
        metadata_packet = create_and_send_metadata_packet(total_packets, short_hash, src_ip, dst_ip)
        if metadata_packet:
            sent_packets.append(metadata_packet)
        
        print(f"Encrypted message '{user_input}' sent successfully.\n")
        curr_time = strftime("[%H:%M:%S]",gmtime())
        logs.append(f"{curr_time} Encrypted message '{user_input}' sent successfully.\n")
        inject_logs(scroll,f"{curr_time} Encrypted message '{user_input}' sent successfully.\n")
    except KeyboardInterrupt:
        print("\nStopping sender...")
    
    finally:
        
        print(f"Total packets sent: {len(sent_packets)}")
        time.sleep(5)

