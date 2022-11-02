import socket
import random
import hashlib
import sys
import libnum
import struct

pw = "password"

HOST = "127.0.0.1"
PORT = 5000
q = 131

b = random.randrange(0,1000000)
B = random.randrange(0,1000000)

sB = b + B

PE = int(hashlib.md5(pw.encode()).hexdigest()[:8], 16)

elementB = libnum.invmod(pow(PE, B), q)

PEsB = pow(PE, sB, q)
print("My PEsB is ", PEsB)
print("My elementB is ", elementB)

#transmit this, then calculate ss2

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("listening on port #",PORT)
    conn, addr = s.accept()
    val = struct.pack('!i', PEsB)
    conn.sendall(val)
    val2 = struct.pack('!i', elementB)
    conn.sendall(val2)
    ss2 = 0
    with conn:
        while True:
            buf = b''
            #while len(buf) < 4:
            buf += conn.recv(4)
            PEsA = struct.unpack('!i', buf[:4])[0]
            print("Supp's PEsA is:",PEsA)

            buf2 = b''
            #while len(buf2) < 4:
            buf2 += conn.recv(4)
            elementA = struct.unpack('!i', buf2[:4])[0]
            print("Supp's elementA is:", elementA)

            ss2 = pow(PEsA * elementA,b,q)
            break
    print("ss2 is", ss2)
