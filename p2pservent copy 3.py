import socket
import struct
import threading
import secrets
import customtkinter as ctk
from keymaker import generatePrivateKey, generatePublicKey
from encryptionengine import encryptionToggleMessage

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

mySecretNumber = secrets.randbits(256)
thePrivateKey = None  
secureSocket = None    
p2pPort = 5001

def logToGui(message):
    def update():
        chatBox.configure(state="normal")
        chatBox.insert("end", message + "\n")
        chatBox.see("end")
        chatBox.configure(state="disabled")
    appRoot.after(0, update)

def listenForPeers():
    global secureSocket, thePrivateKey
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        serverSocket.bind(("0.0.0.0", p2pPort))
        serverSocket.listen(1)
        conn, addr = serverSocket.accept()
        if secureSocket is None:
            logToGui(f"[System] Inbound connection accepted from {addr[0]}!")
            secureSocket = conn
            header = conn.recv(5)
            opcode, length = struct.unpack("!BI", header)
            payload = conn.recv(length)
            if opcode == 0x02:
                theirPub = int.from_bytes(payload, byteorder="big")
                myPub = generatePublicKey(mySecretNumber).to_bytes(256, byteorder="big")
                conn.send(struct.pack("!BI256s", 0x02, 256, myPub))
                thePrivateKey = generatePrivateKey(mySecretNumber, theirPub)
                logToGui("[System] Secure link established. Ready to chat.")
                threading.Thread(target=receiveMessages, args=(conn,), daemon=True).start()
    except Exception:
        pass

def receiveMessages(sock):
    global thePrivateKey, secureSocket
    while True:
        try:
            header = sock.recv(5)
            if not header:
                break
            opcode, length = struct.unpack("!BI", header)
            payload = sock.recv(length)
            if opcode == 0x03:
                decrypted = encryptionToggleMessage(payload, thePrivateKey)
                logToGui(f"Peer: {decrypted.decode('utf-8')}")
        except Exception:
            break
    logToGui("[System] Peer disconnected.")
    secureSocket = None
    thePrivateKey = None
    threading.Thread(target=listenForPeers, daemon=True).start()

def connectToPeer():
    global secureSocket, thePrivateKey
    targetIp = ipEntry.get().strip()
    if not targetIp:
        logToGui("[Error] Please enter an IP address first.")
        return
        
    logToGui(f"[System] Attempting to connect to {targetIp}...")
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
            logToGui(f"[System] Connected and securely linked to {targetIp}!")
            threading.Thread(target=receiveMessages, args=(clientSocket,), daemon=True).start()
    except Exception as e:
        logToGui(f"[System] Could not connect: {e}")
        secureSocket = None

def sendMessage(event=None):
    global secureSocket, thePrivateKey
    msgText = messageEntry.get().strip()
    if not msgText:
        return
        
    messageEntry.delete(0, "end")
    
    if secureSocket is None:
        logToGui("[System] You are not connected to a peer.")
        return
        
    if msgText == "end":
        secureSocket.close()
        secureSocket = None
        thePrivateKey = None
        logToGui("[System] You disconnected.")
        threading.Thread(target=listenForPeers, daemon=True).start()
        return

    try:
        encryptedMessageBytes = encryptionToggleMessage(msgText.encode('utf-8'), thePrivateKey)
        messageLength = len(encryptedMessageBytes)
        packetData = struct.pack(f"!BI{messageLength}s", 0x03, messageLength, encryptedMessageBytes)
        secureSocket.send(packetData)
        logToGui(f"You: {msgText}")
    except Exception:
        logToGui("[System] Failed to send message. Connection broken.")
        secureSocket = None

appRoot = ctk.CTk()
appRoot.title("Secure P2P Chat")
appRoot.geometry("600x450")

topFrame = ctk.CTkFrame(appRoot, fg_color="transparent")
topFrame.pack(fill="x", padx=10, pady=10)

ipLabel = ctk.CTkLabel(topFrame, text="Peer IP:")
ipLabel.pack(side="left", padx=(0, 5))

ipEntry = ctk.CTkEntry(topFrame, width=200)
ipEntry.pack(side="left", padx=5)

connectBtn = ctk.CTkButton(topFrame, text="Connect", command=connectToPeer, width=100)
connectBtn.pack(side="left", padx=5)

chatBox = ctk.CTkTextbox(appRoot, state="disabled", wrap="word", font=("Consolas", 12))
chatBox.pack(fill="both", expand=True, padx=10, pady=(0, 10))

bottomFrame = ctk.CTkFrame(appRoot, fg_color="transparent")
bottomFrame.pack(fill="x", padx=10, pady=(0, 10))

messageEntry = ctk.CTkEntry(bottomFrame, height=35)
messageEntry.pack(side="left", fill="x", expand=True, padx=(0, 10))
messageEntry.bind("<Return>", sendMessage)

sendBtn = ctk.CTkButton(bottomFrame, text="Send", command=sendMessage, width=100, height=35)
sendBtn.pack(side="right")

myLocalIp = socket.gethostbyname(socket.gethostname())
logToGui("--- P2P Secure Node Initialized ---")
logToGui(f"Your IP Address is: {myLocalIp}")
logToGui("Listening for incoming connections on port 5001...")

threading.Thread(target=listenForPeers, daemon=True).start()

appRoot.mainloop()