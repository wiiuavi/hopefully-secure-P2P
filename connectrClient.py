import socket
import struct
import os
from keymaker import generatePrivateKey, generatePublicKey
from encryptionengine import encryptionToggleMessage
import secrets

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect(("127.0.0.1", 5001))
mySecretNumber = secrets.randbits(256)

def doSomethingWithKey(opcode, socket): #0x02 -> sending public key
    myPublicKey = generatePublicKey(mySecretNumber)
    myPublicKeyBytes = myPublicKey.to_bytes(256, byteorder="big")
    payloadLength = 256
    packet = struct.packet("!BI256s", opcode, payloadLength, myPublicKeyBytes)
    socket.send(packet)


doSomethingWithKey(0x02, clientSocket)

headerBytes = clientSocket.recv(5)
opcode, payloadLength = struct.unpack("!BI", headerBytes)
payloadBytes = clientSocket.recv(payloadLength)
if opcode == 0x02:
    theirPublicKey = int.from_bytes(payloadBytes, byteorder="big")
    doSomethingWithKey(0x02, clientSocket)
    thePrivateKey = generatePrivateKey(mySecretNumber, theirPublicKey)
########################################handshake done
while True:
    message = input("Enter message: ")
    if message == "end":
        break
    messageBytes = message.encode("utf-8")
    encryptedMessage = encryptionToggleMessage(messageBytes, thePrivateKey)
    payloadLength = len(encryptedMessage)
    packet = struct.pack(f"!BI{payloadLength}s", 0x03, payloadLength, encryptedMessage)
    clientSocket.send(packet)





