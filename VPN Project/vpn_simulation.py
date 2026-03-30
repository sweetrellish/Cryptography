# vpn_simulation.py

import time

def encrypt(data):
    return f"encrypted({data})"

def decrypt(data):
    return data.replace("encrypted(", "").replace(")", "")

def send_data_over_vpn(source, destination, message):
    print(f"[{source}] Preparing to send message to [{destination}]...")
    encrypted_msg = encrypt(message)
    print(f"[{source}] Encrypted message: {encrypted_msg}")
    time.sleep(1)
    print(f"[VPN Tunnel] Routing message...")
    time.sleep(1)
    print(f"[{destination}] Received encrypted message: {encrypted_msg}")
    decrypted_msg = decrypt(encrypted_msg)
    print(f"[{destination}] Decrypted message: {decrypted_msg}")

# Example usage
if __name__ == "__main__":
    send_data_over_vpn("Client_A", "Server_B", "Hello over VPN!")
