import socket
import struct
import os
from keymaker import generatePrivateKey, generatePublicKey
from encryptionengine import encryptionToggleMessage
import secrets

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 5001))
mySecretNumber = secrets.randbits(256)

def searchForClient():
    server.listen(1)
    print("listening 5001")
    clientSocket, clientAddress = server.accept()
    print(f"connected to {clientAddress}")
    return clientSocket, clientAddress

def doSomethingWithKey(opcode, socket): #0x02 -> sending public key
    myPublicKey = generatePublicKey(mySecretNumber)
    myPublicKeyBytes = myPublicKey.to_bytes(256, byteorder="big")
    payloadLength = 256
    packet = struct.pack("!BI256s", opcode, payloadLength, myPublicKeyBytes)
    socket.send(packet)



connectedClient, clientIp = searchForClient()
headerBytes = connectedClient.recv(5)
opcode, payloadLength = struct.unpack("!BI", headerBytes)
payloadBytes = connectedClient.recv(payloadLength)
if opcode == 0x02:
    theirPublicKey = int.from_bytes(payloadBytes, byteorder="big")
    doSomethingWithKey(0x02, connectedClient)
    thePrivateKey = generatePrivateKey(mySecretNumber, theirPublicKey)

##################################Handshake done

while True:
    try:
        headerBytes = connectedClient.recv(5)
        if not headerBytes:
            break
        opcode, payloadLength = struct.unpack("!BI", headerBytes)
        payloadBytes = connectedClient.recv(payloadLength)
        if opcode == 0x03:
            decryptedBytes = encryptionToggleMessage(payloadBytes, thePrivateKey)
            responseMessage = decryptedBytes.decode("utf-8")
            print(f"recieved: {responseMessage}")
    except ConnectionResetError:
        break
print("client disconnected.")
connectedClient.close()
server.close()







