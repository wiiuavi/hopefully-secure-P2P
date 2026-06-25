import socket
import struct
import os

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)

# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.bind(("0.0.0.0", 6767))
# server.listen(1)
# print("listening on port 6767")
# client_socket, client_address = server.accept()
# print(f"connected to {client_address}")
# incoming_data = client_socket.recv(4096)
# recieved_message = incoming_data.encode("utf-8")
# print(f"got response from {client_address}")
# response_message = "message"
# client_socket.send(response_message.encode("utf-8"))
# client_socket.close()
# server.close()

