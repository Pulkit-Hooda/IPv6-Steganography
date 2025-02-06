from scapy.all import *
from scapy.layers.inet6 import IPv6ExtHdrDestOpt, PadN, IPv6ExtHdrHopByHop, IPv6, UDP
from datetime import datetime
import argparse
from tkinter import INSERT
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import hashlib

# interface = "Wi-Fi"
logs = []
scroll = None

def inject_logs(scroll,log):
    scroll.configure(state ='normal')
    scroll.clipboard_clear()
    for log in logs:
        scroll.insert(INSERT,log+'\n')
    scroll.configure(state ='disabled')



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
    # Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    # Encrypt the padded message
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return the IV and ciphertext (IV is needed for decryption)
    return iv + ciphertext

def create_and_send_packet(secret_message, src_ip, dst_ip):
    # Ensure the secret message is padded to a multiple of 32 bits
    if len(secret_message) % 32 != 0:
        raise ValueError("Secret message must be a multiple of 32 bits long.")
    
    # Split the secret message into 32-bit chunks
    chunks = split_into_32bit_chunks(secret_message)
    
    # Create IPv6 base header
    ipv6_packet = IPv6(src=src_ip, dst=dst_ip)
    
    # Add Destination Options Header with multiple PadN options
    _options = []
    for chunk in chunks:
        # Convert the 32-bit chunk to bytes
        padding_data = binary_to_bytes(chunk)
        _options.append(PadN(optdata=padding_data))
    
    ipv6_packet /= IPv6ExtHdrDestOpt(options=_options)
    ipv6_packet /= UDP(sport=53, dport=53)
    
    # Check packet size to avoid exceeding MTU
    packet_size = len(ipv6_packet)
    mtu = 1500
    if packet_size > mtu:
        print(f"Warning: Packet size ({packet_size} bytes) exceeds MTU ({mtu} bytes).")
        logs.append(f"Warning: Packet size ({packet_size} bytes) exceeds MTU ({mtu} bytes).")
        inject_logs(scroll,f"Warning: Packet size ({packet_size} bytes) exceeds MTU ({mtu} bytes).")
        return None
    
    # Send the packet
    print(f"Sending packet for {len(chunks)} PadN options.", padding_data)
    # logs.append(f"Sending packet for {len(chunks)} PadN options. {padding_data}")
    # inject_logs(scroll,f"Sending packet for {len(chunks)} PadN options. {padding_data}")
    send(ipv6_packet, verbose=False, iface=interface)
    
    return ipv6_packet

def create_and_send_metadata_packet(total_packets, short_hash, src_ip, dst_ip):
    """Create and send a packet containing metadata (total packets and short hash)."""
    # Create IPv6 base header
    ipv6_packet = IPv6(src=src_ip, dst=dst_ip)
    
    # Encode total packets as 4 bytes
    total_packets_bytes = total_packets.to_bytes(4, byteorder='big')
    
    # Combine total packets and short hash
    metadata = total_packets_bytes + short_hash
    
    # Add Destination Options Header with a single PadN option
    ipv6_packet /= IPv6ExtHdrDestOpt(options=[PadN(optdata=metadata)])
    ipv6_packet /= UDP(sport=53, dport=53)
    
    # Send the packet
    print("Sending metadata packet.")
    
    logs.append("Sending metadata packet.")
    inject_logs(scroll,"Sending metadata packet.")
    send(ipv6_packet, verbose=False, iface=interface)
    
    return ipv6_packet

# Main function to process command-line arguments and send packets
def sender_main(ip,user_input,password,scrl,myIP,interFace):
    global pcap_filename,scroll,interface
    interface = interFace if interFace else "Wi-Fi"
    scroll= scrl
    # Get the destination IP from the command-line argument
    src_ip = myIP if myIP else "2405:201:403f:18cd:a421:f62e:af7c:45d5"
    dst_ip = ip
    
    # Derive a 32-byte key from the password using SHA-256
    key = hashlib.sha256(password.encode()).digest()
    
    # Generate a single PCAP file name based on the current system time
    pcap_filename = f"sent_packets_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
    print(f"Logging sent packets to: {pcap_filename}")
    
    # List to store all sent packets
    sent_packets = []
    
    try:
       
        encrypted_message = encrypt_aes(user_input, key)
        
        # Compute a short hash (first 8 bytes of SHA-256)
        full_hash = hashlib.sha256(encrypted_message).digest()
        short_hash = full_hash[:8]  # Use only the first 8 bytes
        
        # Convert the encrypted message to binary
        binary_input = ''.join(format(byte, '08b') for byte in encrypted_message)
        
        # Pad the binary string to ensure its length is a multiple of 32
        padded_binary = pad_binary_to_32bit(binary_input)
        
        # Split the binary string into 32-bit chunks
        thirty_two_bit_chunks = split_into_32bit_chunks(padded_binary)
        
        # Total number of packets to send
        total_packets = len(thirty_two_bit_chunks)
        
        # Send a packet for each 32-bit chunk
        for chunk in thirty_two_bit_chunks:
            packet = create_and_send_packet(chunk, src_ip, dst_ip)
            if packet:
                sent_packets.append(packet)
        
        # Send a metadata packet containing total packets and short hash
        metadata_packet = create_and_send_metadata_packet(total_packets, short_hash, src_ip, dst_ip)
        if metadata_packet:
            sent_packets.append(metadata_packet)
        
        print(f"Encrypted message '{user_input}' sent successfully.\n")
        
        logs.append(f"Encrypted message '{user_input}' sent successfully.\n")
        inject_logs(scroll,f"Encrypted message '{user_input}' sent successfully.\n")
    except KeyboardInterrupt:
        print("\nStopping sender...")
    
    finally:
        
        print(f"Total packets sent: {len(sent_packets)}")
        time.sleep(5)

