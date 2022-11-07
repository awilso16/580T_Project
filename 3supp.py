#CODE BORROWS FROM HERE: https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwiimfOIhJv7AhWXD1kFHWY2DJQQFnoECA8QAQ&url=https%3A%2F%2Fgithub.com%2FNikolaiT%2FDragonfly-SAE%2Fblob%2Fmaster%2Fdragonfly_implementation.py&usg=AOvVaw0tr58RWYVbIB3P9fZIpCD4

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

password = 'passwor'
my_mac, other_mac = '44:67:2D:2C:91:A6', '44:37:2C:2F:91:36'
my_name = 'STA'

sta = Peer(password, my_mac, my_name)

sta.initiate(other_mac)

scalar_sta, element_sta = sta.commit_exchange()
element_sta_x = element_sta.x
element_sta_y = element_sta.y
element_ap = None
scalar_ap = None
ap_token = None

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("connected!")
    val = scalar_sta.to_bytes(32, byteorder='big')
    s.sendall(val)
    val2 = element_sta_x.to_bytes(32, byteorder='big')
    s.sendall(val2)
    val3 = element_sta_y.to_bytes(32, byteorder='big')
    s.sendall(val3)
    buf = b''
    #while len(buf) < 4:
    buf += s.recv(32)
    scalar_ap = int.from_bytes(buf, 'big')
    print(f'Received scalar_ap {scalar_ap}')

    bufx = b''
    bufx += s.recv(32)
    element_ap_x = int.from_bytes(bufx, 'big')

    bufy = b''
    bufy += s.recv(32)
    element_ap_y = int.from_bytes(bufy, 'big')
    element_ap = Point(element_ap_x,element_ap_y)
    print(f'Received element_ap x={element_ap_x} y={element_ap_y}')

    sta_token = sta.compute_shared_secret(element_ap, scalar_ap, other_mac)
    print(f'Generated sta_token {sta_token}')
    #TRANSMIT STA TOKEN
    #sta_token_packed = sta_token.to_bytes(32, byteorder='big')
    #s.sendall(sta_token_packed)
    s.sendall(bytes(sta_token,encoding='utf-8'))
    #RECEIVE AP TOKEN
    buf2 = b''
    buf2 += s.recv(32)
    #ap_token = int.from_bytes(buf2, 'big')
    ap_token = buf2.decode('utf-8')
    print(f'Received ap_token {ap_token}')
    #END CONNECTION?
sta.confirm_exchange(ap_token)
    

