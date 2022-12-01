import socket 
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 5000

password = "password"
STA_MAC = 'E8:61:09:B9:75:60'
AP_MAC = '48:C9:4D:AA:31:47'

gtk = int('26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6', 16)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("listening on port #",PORT)
    conn, addr = s.accept()
    anonce = int('A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377', 16) #random 32 byte number
    anonce_bytes = anonce.to_bytes(32,byteorder='big')
    conn.sendall(anonce_bytes)
    #can send using conn.sendall
    with conn:
        while True:
            buf = b''
            buf += conn.recv(32)
            snonce = int.from_bytes(buf,'big')
            str_anonce = str(anonce)
            str_snonce = str(snonce)
            ptk = password + str_anonce + str_snonce + AP_MAC + STA_MAC
            print(ptk, gtk)
            conn.sendall(gtk.to_bytes(32, byteorder='big'))
            break
    s.close()