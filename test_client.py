import socket

DISCONN_MSG = "fuckoff"
FORMAT = "utf-8"
HEADER = 64
PORT = 8888
SERVER = "192.168.1.183"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

def send(msg):
    message = msg.encode(FORMAT)
    msgLen = len(message)
    sendLen = str(msgLen).encode(FORMAT)
    sendLen += b' ' * (HEADER - len(sendLen))
    client.send(sendLen)
    client.send(message)
    print(client.recv(64).decode(FORMAT))

send("this is a test")
send(DISCONN_MSG)  