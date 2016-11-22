from socket import *

def server(addr, port):
    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    s.bind((addr, port))
    s.listen(10)
    while 1:
        conn,addr = s.accept()
        conn.send("hello world");
        print("client says:{}".format(conn.recv(1024)))
        conn.close()

def client(addr, port):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((addr, port))
    print("server says:{}".format(s.recv(1024)))
    s.send("fuck you")
