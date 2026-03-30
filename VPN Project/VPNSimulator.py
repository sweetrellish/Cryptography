"""
VPN Simulation Tool
--------------------
This program simulates a Virtual Private Network (VPN) process using AES encryption and decryption.
It provides a graphical user interface (GUI) built with tkinter to demonstrate the following steps:

1. The user enters a message to send.
2. The message is packaged into a JSON object (representing a network packet).
3. The packet is encrypted using AES encryption (CBC mode with PKCS7 padding).
4. The encrypted packet is displayed in the "VPN Tunnel (Encrypted)" section.
5. The encrypted packet is decrypted on the server side and displayed in the "Server (Decrypted Packet)" section.

Key Features:
- AES-256 encryption with a randomly generated key and IV.
- GUI with input fields and scrollable text areas for displaying the original, encrypted, and decrypted packets.
- Error handling for encryption and decryption processes.
- Simulated network latency and packet loss for a realistic VPN experience.
- Tooltips for explaining encryption modes (CBC and GCM).
- Threading for running the simulation in a separate thread to avoid blocking the GUI.
- Logging of successful encryptions and decryptions.
- Clear separation of GUI components and encryption logic for maintainability.

Dependencies:
- tkinter (for GUI)
- cryptography (for AES encryption and decryption)
- base64 (for encoding binary data)
- json (for handling JSON objects)
- os (for generating random bytes)
- socket (for getting the local IP address)
- time (for simulating network latency)
- random (for simulating packet loss)
- threading (for running the simulation in a separate thread)
- tooltip (for displaying tooltips)

Class: COSC 370 - Computer Networks
Professor: Dr. Enyue Lu
Author: Ryan Ellis
Date: April 16, 2025
"""

import tkinter as tk # Importing tkinter for GUI
from tkinter import scrolledtext    # Importing scrolledtext for scrollable text area
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes    # Importing cryptography for AES encryption
from cryptography.hazmat.primitives import padding  # Importing padding for PKCS7
from cryptography.hazmat.backends import default_backend    # Importing default backend for cryptography
from cryptography.hazmat.primitives import hashes  # Importing hashes for HMAC
from cryptography.hazmat.primitives import hmac  # Importing hmac for HMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64   # Importing base64 for encoding
import json   # Importing json for JSON handling
import os   # Importing os for random bytes generation
import socket  # Importing socket to get the local IP address
import time  # Importing time for latency simulation
import random  # Importing random for random number generation
import threading  # Importing threading for multiple client simulations
from tooltip import Tooltip  # Importing Tooltip class for tooltips

successful_encryptions = 0;  # Counter for successful encryptions
successful_decryptions = 0;  # Counter for successful decryptions

# Shared key for encryption/decryption
shared_key = os.urandom(32)  # AES-256 requires a 32-byte key

packets = []  # List to store packets

def update_status(message):
    status_label.config(text=message)  # Update the status label with the message
    root.update_idletasks()  # Update the GUI

# Function to perform Diffie-Hellman key exchange in a separate thread
def perform_key_exchange():
    global shared_key, derived_key
    try:
        # Generate Diffie-Hellman parameters and keys
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        private_key = parameters.generate_private_key() 
        peer_public_key = parameters.generate_private_key().public_key()    

        # Derive a shared key 
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        log_event("Encryption keys generated successfully.\n")  # Log the key generation
        log_event(f"Shared key: {base64.b64encode(shared_key).decode('utf-8')}\n")  # Log the shared key
        log_event(f"Derived key: {base64.b64encode(derived_key).decode('utf-8')}")  # Log the derived key
    except Exception as e:
        log_event(f"Key generation failed: {str(e)}")  # Log the error


def log_event(message):
    log_box.insert(tk.END, message + "\n")
    log_box.see(tk.END)  # Auto-scroll to the latest log

# Function to get the local IP address
def get_local_ip():  # Function to get the local IP address
    """Retrieve the local IP address of the machine."""
    try:
        # Create a socket and connect to a public server to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to Google's public DNS server
        local_ip = s.getsockname()[0]  # Get the local IP address
        s.close()
        return local_ip
    except Exception as e:
        return "127.0.0.1"  # Default to localhost if unable to determine IP
# Utility functions for AES encryption
def pad_message(message):   # Function to pad the message
    padder = padding.PKCS7(128).padder()    # Create a padder object
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()    # Pad the message
    return padded_data  # Return the padded message

def unpad_message(padded_message):  # Function to unpad the message
    unpadder = padding.PKCS7(128).unpadder()    # Create an unpadder object
    data = unpadder.update(padded_message) + unpadder.finalize()    # Unpad the message
    return data.decode('utf-8') # Return the unpadded message

def encrypt_message(message, key):  # Function to encrypt the message
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    # Create a cipher object based on the selected encryption mode
    if encryption_mode.get() == "CBC":
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()  # Create an encryptor object
        padded_message = pad_message(message)   # Pad the message
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()    # Encrypt the message
        tag = None  # Tag is not used in CBC mode
    elif encryption_mode.get() == "GCM":
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()  # Create an encryptor object
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()    # Encrypt the message
        tag = encryptor.tag  # Get the tag for GCM mode

    # Generate HMAC for CBC mode (optional for integrity)
    hmac_value = None
    if encryption_mode.get() == "CBC":
        h = hmac.HMAC(derived_key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        hmac_value = h.finalize()

    return json.dumps({
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'hmac': base64.b64encode(hmac_value).decode('utf-8') if hmac_value else None,
        'tag': base64.b64encode(tag).decode('utf-8') if tag else None
    })

def decrypt_message(enc_message, key):  # Function to decrypt the message
    try:    # Try to decrypt the message
        b64 = json.loads(enc_message)       # Load the JSON object    
        iv = base64.b64decode(b64['iv'])    # Decode the IV from base64
        ciphertext = base64.b64decode(b64['ciphertext'])    
        hmac_value = base64.b64decode(b64['hmac']) if b64['hmac'] else None   # Decode the HMAC from base64
        tag = base64.b64decode(b64['tag']) if b64['tag'] else None   # Decode the tag from base64

        if encryption_mode.get() == "CBC":
            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_message = decryptor.update(ciphertext) + decryptor.finalize()
            return unpad_message(padded_message)
        elif encryption_mode.get() == "GCM":
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption error: {str(e)}"  

# Function to simulate the VPN process
def simulate_vpn(): 
    global packets, encrypted, successful_decryptions, successful_encryptions  # Declare packet and encrypted as global variables
    # Step 1: Clear all fields and update status
    def step1():
        update_status("Processing input...")
        # Add the new packet to the list
        local_IP = get_local_ip()  # Get the local IP address
        packet = {
            "source IP address": local_IP, 
            "destination": "10.0.0.1",
            "data": user_input.get(),     
        }
        packets.append(packet)  # Append the packet to the list
        user_input.delete(0, tk.END)  # Clear the input field
        root.after(2000, step2)  # Wait 3 seconds, then move to step 2

    # Step 2: Display the original packet
    def step2():
        # Display only the last packet
        last_packet = packets[-1]  # Get the last packet
        formatted_packet = json.dumps(last_packet,indent=2)+ "\n\n"
        client_box.insert(tk.END, formatted_packet)
        update_status("Encrypting packet...")
        root.after(2000, step3)  # Wait 2 seconds, then move to step 3

    # Step 3: Encrypt the packet
    def step3():
        global successful_encryptions  # Declare successful_encryptions as a global variable
        # Simulate network latency
        start_time = time.time()  # Record the start time
        time.sleep(random.uniform(0.5, 2.0))  # Simulate network latency
        latency = time.time() - start_time  # Calculate the latency

        if(random.random() < 0.1):  # Simulate a 10% chance of packet loss
            update_status("Packet lost during transmission. Please try again.")
            log_event(f"Packet lost during transmission. Latency: {latency:.2f} seconds")  # Log the packet loss
            packets.pop()  # Remove the last packet from the list
            return
        last_packet = packets[-1]  # Get the last packet
        packet_json = json.dumps(last_packet)
        encrypted = encrypt_message(packet_json, derived_key)
        encrypted_data = json.loads(encrypted)
        iv = encrypted_data['iv']
        ciphertext = encrypted_data['ciphertext']
        
        tunnel_box.insert(tk.END, f"IV: {iv}\n")    # Display the IV (Initialization Vector)
        tunnel_box.insert(tk.END, "-" * 40 + "\n")  # Separator
        tunnel_box.insert(tk.END, f"Ciphertext: {ciphertext}\n\n")  # Display the ciphertext
        update_status("Packet encrypted. Sending to server...")
        successful_encryptions += 1  # Increment the successful encryptions counter
        log_event(f"Packet encrypted: {successful_encryptions}")  # Log the number of successful encryptions
        log_event(f"Simlated latency: {latency:.2f} seconds")  # Log the simulated latency
        root.after(2000, step4)  # Wait 2 seconds, then move to step 4

    # Step 4: Decrypt the packet
    def step4():
        global successful_decryptions  # Declare successful_decryptions as a global variable
        server_box.delete(1.0, tk.END)  # Clear the server box
        for packet in packets:  # Iterate through the packets
            packet_json = json.dumps(packet)
            encrypted = encrypt_message(packet_json, derived_key)
            decrypted_json = decrypt_message(encrypted, derived_key)
            try:
                decrypted_packet = json.loads(decrypted_json)
                server_box.insert(tk.END, json.dumps(decrypted_packet, indent=2))
                
                
            except json.JSONDecodeError as e:
                server_box.insert(tk.END, "Error decoding JSON")
        successful_decryptions += 1  # Increment the successful decryptions counter
        update_status("Packets decrypted. Ready for next input.")
        log_event(f"Packets decrypted: {successful_decryptions}")  # Log the number of decrypted packets

    # Start the simulation
    step1()
# Create the GUI
root = tk.Tk()  # Create the main window
root.title("COSC 370 - VPN Simulator")    # Set the title of the window

# Start the key exchange in a separate thread (after GUI initialization)
#threading.Thread(target=perform_key_exchange, daemon=True).start()

# Status label
status_label = tk.Label(root, text="Ready", font=("Helvetica", 18), fg="orange")   # Create a label for status
status_label.grid(row=5, column=0, columnspan=3, pady=10)   # Place the status label in the grid

# Add a loading indicator before starting the key exchange
threading.Thread(target=perform_key_exchange, daemon=True).start()

# Button to simulate VPN
simulate_btn = tk.Button(root, text="Simulate VPN Transfer", command=simulate_vpn)  # Create a button to simulate VPN transfer
simulate_btn.grid(row=2, column=0, columnspan=3, pady=10)   # Place the button in the grid

log_box = scrolledtext.ScrolledText(root, width=80, height=10, bg="black", fg="white")
log_box.grid(row=7, column=0, columnspan=3, padx=5, pady=5)

def simulate_vpn_thread():
        threading.Thread(target=simulate_vpn).start()  # Start the VPN simulation in a separate thread
simulate_btn = tk.Button(root, text="Simulate VPN Transfer", command=simulate_vpn_thread)
simulate_btn.grid(row=2, column=0, columnspan=3, pady=10)   # Button to simulate VPN transfer

encryption_mode = tk.StringVar(value="CBC")  # Variable to store the encryption mode
tk.Label(root, text= "Selct Encryption Mode: ").grid(row=6, column=0, pady=5)
tk.OptionMenu(root, encryption_mode, "CBC", "GCM").grid(row=6, column=1, pady=5)  # Dropdown menu for encryption mode
# Dropdown menu for encryption mode
encryption_mode_label = tk.Label(root, text="Select Encryption Mode:")
encryption_mode_label.grid(row=6, column=0, pady=5)
encryption_mode_menu = tk.OptionMenu(root, encryption_mode, "CBC", "GCM")
encryption_mode_menu.grid(row=6, column=1, pady=5)

# Create a tooltip for the dropdown menu
encryption_tooltip = Tooltip(encryption_mode_menu, "CBC (Cipher Block Chaining):\n"
            "------------------------------------------\n"
            "- A block cipher mode of operation where each plaintext block is XORed\n"
            "  with the previous ciphertext block before being encrypted.\n"
            "- Requires an Initialization Vector (IV).\n"
            "- If a single bit of the ciphertext is altered, the corresponding plaintext block\n"
            "  will be corrupted, but the rest of the message will remain intact.\n"
            "- Provides confidentiality but not integrity.\n")

# Function to update the tooltip text based on the current mode
def update_and_show_tooltip(event):
    current_mode = encryption_mode.get()
    if current_mode == "CBC":
        encryption_tooltip.update_text(
            "CBC (Cipher Block Chaining):\n"
            "------------------------------------------\n"
            "- A block cipher mode of operation where each plaintext block is XORed\n"
            "  with the previous ciphertext block before being encrypted.\n"
            "- Requires an Initialization Vector (IV).\n"
            "- If a single bit of the ciphertext is altered, the corresponding plaintext block\n"
            "  will be corrupted, but the rest of the message will remain intact.\n"
            "- Provides confidentiality but not integrity.\n"
        )
    elif current_mode == "GCM":
        encryption_tooltip.update_text(
            "GCM (Galois/Counter Mode):\n"
            "------------------------------------------\n"
            "- A block cipher mode that combines encryption with authentication.\n"
            "- Uses a counter mode for encryption and a Galois field multiplication\n"
            "  for authentication.\n"
            "- Provides both confidentiality and integrity.\n"
            "- Suitable for secure communication protocols like TLS.\n"
        )
    encryption_tooltip.show_tooltip(event)  # Show the tooltip with the updated text

# Bind hover events to the dropdown menu
encryption_mode_menu.bind("<Enter>", update_and_show_tooltip)  # Update tooltip text on hover
encryption_mode_menu.bind("<Leave>", encryption_tooltip.hide_tooltip)  # Hide the tooltip

# Input field for user message
tk.Label(root, text="Enter Message to Send:").grid(row=0, column=0, columnspan=3, pady=5)   # Label for input field
user_input = tk.Entry(root, width=60)   # Create an entry field for user input
user_input.grid(row=1, column=0, columnspan=3, padx=10)  # Place the entry field in the grid

# Labels for text areas
tk.Label(root, text="Client (Original Packet)").grid(row=3, column=0)   # Label for client box
tk.Label(root, text="VPN Tunnel (Encrypted)").grid(row=3, column=1)  # Label for tunnel box
tk.Label(root, text="Server (Decrypted Packet)").grid(row=3, column=2)  # Label for server box

# Text areas for displaying packets
client_box = scrolledtext.ScrolledText(root, width=60, height=40, bg="white", fg="black")   # Create a scrolled text area for client box
tunnel_box = scrolledtext.ScrolledText(root, width=70, height=40, bg="white", fg="black")   # Create a scrolled text area for tunnel box
server_box = scrolledtext.ScrolledText(root, width=60, height=40, bg="white", fg="black")   # Create a scrolled text area for server box

client_box.grid(row=4, column=0, padx=5)    # Place the client box in the grid
tunnel_box.grid(row=4, column=1, padx=5)    # Place the tunnel box in the grid
server_box.grid(row=4, column=2, padx=5)    # Place the server box in the grid

status_label = tk.Label(root, text="Ready", font=("Helvetica", 18), fg = "orange")   # Create a label for status
status_label.grid(row=5, column=0, columnspan=3, pady=10)   # Place the status label in the grid
# Run the GUI
root.mainloop() # Start the main loop