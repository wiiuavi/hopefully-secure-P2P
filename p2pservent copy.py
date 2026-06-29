import socket
import struct
import threading
import secrets
from keymaker import generatePrivateKey, generatePublicKey
from encryptionengine import encryptionToggleMessage

mySecretNumber = secrets.randbits(256)
thePrivateKey = None  
secureSocket = None    
p2pPort = 5001
myLocalIP = socket.gethostbyname(socket.gethostname())

def listenForPeers():
    global secureSocket, thePrivateKey
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        serverSocket.bind(("0.0.0.0", p2pPort))
        serverSocket.listen(1)
        conn, addr = serverSocket.accept()
        if secureSocket is None:
            print(f"\n[System] Inbound connection accepted from {addr}!")
            secureSocket = conn
            header = conn.recv(5)
            opcode, length = struct.unpack("!BI", header)
            payload = conn.recv(length)
            if opcode == 0x02:
                theirPub = int.from_bytes(payload, byteorder="big")
                myPub = generatePublicKey(mySecretNumber).to_bytes(256, byteorder="big")
                conn.send(struct.pack("!BI256s", 0x02, 256, myPub))
                thePrivateKey = generatePrivateKey(mySecretNumber, theirPub)
                threading.Thread(target=receiveMessages, args=(conn,), daemon=True).start()
    except Exception:
        pass

def receiveMessages(sock):
    global thePrivateKey
    while True:
        try:
            header = sock.recv(5)
            if not header:
                break
            opcode, length = struct.unpack("!BI", header)
            payload = sock.recv(length)
            if opcode == 0x03:
                decrypted = encryptionToggleMessage(payload, thePrivateKey)
                print(f"\nPeer: {decrypted.decode('utf-8')}")
                print("You: ", end="", flush=True)
        except Exception:
            break
    print("\n[System] Peer disconnected.")

def connectToPeer(targetIp):
    global secureSocket, thePrivateKey
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        clientSocket.connect((targetIp, p2pPort))
        secureSocket = clientSocket
        myPub = generatePublicKey(mySecretNumber).to_bytes(256, byteorder="big")
        clientSocket.send(struct.pack("!BI256s", 0x02, 256, myPub))
        header = clientSocket.recv(5)
        opcode, length = struct.unpack("!BI", header)
        payload = clientSocket.recv(length)
        if opcode == 0x02:
            theirPub = int.from_bytes(payload, byteorder="big")
            thePrivateKey = generatePrivateKey(mySecretNumber, theirPub)
            print(f"[System] Connected and securely linked to {targetIp}!")
            threading.Thread(target=receiveMessages, args=(clientSocket,), daemon=True).start()
            return True
    except Exception as e:
        print(f"[System] Could not connect to {targetIp}: {e}")
        secureSocket = None
        return False

threading.Thread(target=listenForPeers, daemon=True).start()
print("--- P2P Secure Node Initialized ---")
print("Listening for incoming connections on port 5001...")
print(f"Your IP is {myLocalIP}.")

while True:
    if secureSocket is None:
        userChoice = input("\nOptions: [1] Connect to a peer, [2] Keep waiting for inbound, [3] Exit\nChoice: ")
        if userChoice == "1":
            targetIpInput = input("Enter Peer IP address: ")
            connectToPeer(targetIpInput)
        elif userChoice == "3":
            break
    else:
        userMessage = input("You: ")
        if userMessage == "end":
            secureSocket.close()
            secureSocket = None
            thePrivateKey = None
            threading.Thread(target=listenForPeers, daemon=True).start()
        elif userMessage.strip():
            encryptedMessageBytes = encryptionToggleMessage(userMessage.encode('utf-8'), thePrivateKey)
            messageLength = len(encryptedMessageBytes)
            packetData = struct.pack(f"!BI{messageLength}s", 0x03, messageLength, encryptedMessageBytes)
            try:
                secureSocket.send(packetData)
            except Exception:
                print("[System] Failed to send message. Connection broken.")
                secureSocket = None