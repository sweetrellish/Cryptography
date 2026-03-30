import socket
import ssl
import threading

# Server-side code
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server listening on port 12345...")

    # Wrap the socket with SSL
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")  # Use your own certificate and key
    secure_socket = context.wrap_socket(server_socket, server_side=True)

    conn, addr = secure_socket.accept()
    print(f"Connection established with {addr}")

    # Receive and decrypt data
    data = conn.recv(1024).decode('utf-8')
    print(f"Server received: {data}")
    conn.send("Data received securely!".encode('utf-8'))
    conn.close()

# Client-side code
def start_client():
    context = ssl.create_default_context()
    context.load_verify_locations('server.crt')  # Use your own certificate
    secure_socket = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname='localhost')
    secure_socket.connect(('localhost', 12345))

    # Send encrypted data
    secure_socket.send("Hello, secure server!".encode('utf-8'))
    response = secure_socket.recv(1024).decode('utf-8')
    print(f"Client received: {response}")
    secure_socket.close()

# Run server and client in separate threads
server_thread = threading.Thread(target=start_server)
server_thread.start()

client_thread = threading.Thread(target=start_client)
client_thread.start()