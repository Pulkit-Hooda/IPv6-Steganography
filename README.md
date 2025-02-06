# IPv6-Steganography
This tool can send and receive messages which are encrypted using AES-256-CBC Encryption. It hides the encrypted data inside of extension headers of IPv6 packets. It is entirely built in python. It runs only on Windows for now, linux support will be added later.

# Steps to Run:
1. Run PowerShell or cmd as administrator.

2. Navigate to the directory of the extracted files.

3. Run:
	pip install -r .\requirements.txt

4. Run:
	.\main.py <interface>
				where <interface> is the interface to send and sniff packets on.

	Ex. if you are sniffing on Wi-Fi, then run it as: .\main.py Wi-Fi
