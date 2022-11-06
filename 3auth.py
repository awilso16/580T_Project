import socket
import random
import hashlib
import sys
import libnum
import struct
import time
from curve import Curve
from peer import Peer
from collections import namedtuple

Point = namedtuple("Point", "x y")
# The point at infinity (origin for the group law).
O = 'Origin'

HOST = '127.0.0.1'
PORT = 5000

p = int('A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377', 16)
a = int('7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9', 16)
b = int('26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6', 16)
q = int('A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7', 16)
curve = Curve(a, b, p)

password = 'password'
other_mac, my_mac = '44:67:2D:2C:91:A6', '44:37:2C:2F:91:36'
my_name = 'AP'

ap = Peer(password, my_mac, my_name)

ap.initiate(other_mac)

scalar_ap, element_ap = ap.commit_exchange()
element_ap_x = element_ap.x
element_ap_y = element_ap.y
scalar_sta = None
element_sta = None
sta_token = None

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("listening on port #",PORT)
    conn, addr = s.accept()
    val = scalar_ap.to_bytes(32, byteorder='big')
    conn.sendall(val)
    val2 = element_ap_x.to_bytes(32, byteorder='big')
    conn.sendall(val2)
    val3 = element_ap_y.to_bytes(32, byteorder='big')
    conn.sendall(val3)
    with conn:
        while True:
            buf = b''
            #while len(buf) < 4:
            buf += conn.recv(32)
            scalar_sta = int.from_bytes(buf, 'big')

            bufx = b''
            bufx += conn.recv(32)
            element_sta_x = int.from_bytes(bufx, 'big')

            bufy = b''
            bufy += conn.recv(32)
            element_sta_y = int.from_bytes(bufy, 'big')

            element_sta = Point(element_sta_x, element_sta_y)
            ap_token = ap.compute_shared_secret(element_sta, scalar_sta, other_mac)
            #TRANSMIT AP TOKEN
            #ap_token_packed = ap_token.to_bytes(32, byteorder='big')
            #conn.sendall(ap_token_packed)
            conn.sendall(bytes(ap_token,encoding='utf-8'))
            #RECEIVE STA TOKEN
            buf3 = b''
            buf3 += conn.recv(32)
            #sta_token = int.from_bytes(buf3, 'big')
            sta_token = buf3.decode('utf-8')
            break
    #s.shutdown(socket.SHUT_RDWR)
    s.close()

ap.confirm_exchange(sta_token)



