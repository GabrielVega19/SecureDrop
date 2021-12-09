import socket 
import threading
import json

DISCONN_MSG = "!DISCONNECT"
TEST_MSG = "!TEST"
REQ_MSG = "!REQUEST"
ADD_MSG = "!ADD"
REM_MSG = "!REMOVE"
FORMAT = "utf-8"
HEADER = 128
PORT = 8021
PUBKEY = ""
PRIVKEY = ""
st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
st.connect(('10.255.255.255', 1))
SERVER = st.getsockname()[0]
st.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER, PORT))

lock = threading.Lock()
onlineUsers = {}


def handleClient(conn, addr):
    print(f"New Connection: {addr} connected")

    while True:
        msgLength = conn.recv(HEADER).decode(FORMAT)
        if msgLength:
            msgLength = int(msgLength)
            msg = conn.recv(msgLength).decode(FORMAT)
            if msg == TEST_MSG:
                conn.send("Connection successful!".encode(FORMAT))
            elif msg == DISCONN_MSG:
                print(f"{addr} sent: {msg}")
                break
            elif msg == REQ_MSG:
                sendData = json.dumps(onlineUsers).encode(FORMAT)
                dataLen = str(len(sendData)).encode(FORMAT)
                dataLen += b' ' * (HEADER - len(dataLen))
                conn.send(dataLen)
                conn.send(sendData)
            elif msg == ADD_MSG:
                lock.acquire()
                leng = int(conn.recv(HEADER).decode(FORMAT))
                cnt = int(conn.recv(leng).decode(FORMAT))
                emailList = []
                for i in range(cnt):
                    emlen = int(conn.recv(HEADER).decode(FORMAT))
                    email = conn.recv(emlen).decode(FORMAT)
                    emailList.append(email)
                onlineUsers[addr[0]] = emailList
                lock.release()
            elif msg == REM_MSG:
                lock.acquire()
                del onlineUsers[addr[0]] 
                lock.release()


            print(f"{addr} sent: {msg}")

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