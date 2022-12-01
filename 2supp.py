import socket 
from cryptography.fernet import Fernet
HOST = '127.0.0.1'
PORT = 5000

password = "password"
STA_MAC = 'E8:61:09:B9:75:60'
AP_MAC = '48:C9:4D:AA:31:47'

snonce = int('7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9', 16) #random 32 byte int
str_snonce = str(snonce)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("connected!")
    buf = b''
    buf += s.recv(64)
    anonce = int.from_bytes(buf, 'big')
    #PTK = PMK + ANONCE + SNONCE + MAC(AA) + MAC(SA)
    str_anonce = str(anonce)
    ptk = password + str_anonce + str_snonce + AP_MAC + STA_MAC
    s.sendall(snonce.to_bytes(32,byteorder='big'))
    buf2 = b''
    buf2 += s.recv(64)
    gtk = int.from_bytes(buf2,'big')
    print(ptk, gtk)
    #can send using s.sendall and receive using s.recv
