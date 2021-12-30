# This bitch about to be lit. 
import socket
import threading
import json

#global variables for the different kinds of requests you can send to the server
DISCONN_MSG = "!DISCONNECT"
TEST_MSG = "!TEST"
REQ_MSG = "!REQUEST"
ADD_MSG = "!ADD"
REM_MSG = "!REMOVE"
#global variable that holds the encoding type 
FORMAT = "utf-8"
#global variable that holds the size for the initial int that then holds the size of the incoming message
HEADER = 128
#global variable for the port that the server runs on
PORT = 8888
#global variables for the asymetric encryption for communicating over the LAN
PUBKEY = ""
PRIVKEY = ""
#global variable that retrives the priv ip address of the computer the server is running on
st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
st.connect(('10.255.255.255', 1))
SERVER = st.getsockname()[0]
st.close()

#global variable that creates and binds the socket for the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER, PORT))

#global variable that holds the dictionary for the online users that connect to the server and a threading lock to make sure the different threads dont try to write at the same time
lock = threading.Lock()
onlineUsers = {}


#This is the function that handles each client that connects to the server it opens a new thread to handle each one
def handleClient(conn, addr):
    #prints the info about the clint that connected
    print(f"New Connection: {addr} connected")

    #main loop for the program that checks for the requests sent to the server 
    while True:
        #the first part of sending anything to the server is sending an int with the size of the actual message then requesting the actual message 
        msgLength = conn.recv(HEADER).decode(FORMAT)
        if msgLength:
            msgLength = int(msgLength)
            msg = conn.recv(msgLength).decode(FORMAT)
            #this is the if else statement that checks which request type the client is requesting
            #tests for successful connection to the server from a client by sending back a message
            if msg == TEST_MSG:
                conn.send("Connection successful!".encode(FORMAT))
            #checks for a dissconect so it can cleanly close the connection to the clint down
            elif msg == DISCONN_MSG:
                print(f"{addr} sent: {msg}")
                break
            #for the list command on the client the server sends back the information of clients that are online for discovery 
            elif msg == REQ_MSG:
                sendData = json.dumps(onlineUsers).encode(FORMAT)
                dataLen = str(len(sendData)).encode(FORMAT)
                dataLen += b' ' * (HEADER - len(dataLen))
                conn.send(dataLen)
                conn.send(sendData)
            #for when a client first connects it adds itself to the dictionary with of online users
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
            #checks for remove message which removes a client from the online dictionary so they dont pop up when a client does list
            elif msg == REM_MSG:
                lock.acquire()
                del onlineUsers[addr[0]] 
                lock.release()

            #prints the info if the client and what they requested 
            print(f"{addr} sent: {msg}")

    #closes the connection to the client when done and prints exit
    conn.close()

#this is the main function that listens for clients to connect and then opens a new thread to run the function that handles a client
def start():
    server.listen()
    #prints out which server and port the server is running on 
    print(f"Server is running on {SERVER} {PORT}")
    #the main loop that listens for a client to connect and then opens the thread and prints out how many threads are running 
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handleClient, args=(conn, addr))
        thread.start()
        print(f"Active Connections: {threading.activeCount() - 1}")


#starts the server by running the start function
print("Starting server....")
start()