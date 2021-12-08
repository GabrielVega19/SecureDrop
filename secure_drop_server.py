import socket 
import threading

DISCONN_MSG = "fuckoff"
FORMAT = "utf-8"
HEADER = 64
PORT = 8888
st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
st.connect(('10.255.255.255', 1))
SERVER = st.getsockname()[0]
st.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER, PORT))

def handleClient(conn, addr):
    print(f"New Connection: {addr} connected")

    while True:
        msgLength = conn.recv(HEADER).decode(FORMAT)
        if msgLength:
            msgLength = int(msgLength)
            msg = conn.recv(msgLength).decode(FORMAT)
            if msg == DISCONN_MSG:
                break
            print(f"{addr} sent: {msg}")
            conn.send("message sent".encode(FORMAT))

    conn.close()
        

def start():
    server.listen()
    print(f"Server is running on {SERVER} {PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handleClient, args=(conn, addr))
        thread.start()
        print(f"Active Connections: {threading.activeCount() - 1}")


print("Starting server....")
start()