import socket 
HOST = '127.0.0.1'
PORT = 5000

password = 'password'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("connected!")
    #can send using s.sendall and receive using s.recv
