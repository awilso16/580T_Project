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

a = random.randrange(0,1000000)
A = random.randrange(0,1000000)

sA = a + A

PE = int(hashlib.md5(pw.encode()).hexdigest()[:8], 16)

elementA = libnum.invmod(pow(PE, A), q)

PEsA = pow(PE, sA, q)
print("My PEsA is ",PEsA)
print("My elementA is",elementA)

#transmit this, then calculate ss1

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("connected!")
    val = struct.pack('!i', PEsA)
    s.sendall(val)
    val2 = struct.pack('!i', elementA)
    s.sendall(val2)
    buf = b''
    #while len(buf) < 4:
    buf += s.recv(4)
    PEsB = struct.unpack('!i', buf[:4])[0]
    print("Auth's PEsB is:",PEsB)

    buf2 = b''
    #while len(buf2) < 4:
    buf2 += s.recv(4)
    elementB = struct.unpack('!i', buf2[:4])[0]
    #s.close()
    print("Auth's elementB is:",elementB)
    ss1 = pow(PEsB * elementB,a,q)
    print("ss1 is", ss1)