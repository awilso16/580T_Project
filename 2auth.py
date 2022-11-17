import socket 

HOST = '127.0.0.1'
PORT = 5000

password = 'password'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("listening on port #",PORT)
    conn, addr = s.accept()
    #can send using conn.sendall
    with conn:
        while True:
            buf = b''
            #receive using conn.recv

            break
    s.close()