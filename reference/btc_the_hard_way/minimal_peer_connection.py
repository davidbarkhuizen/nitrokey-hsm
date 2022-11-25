import struct
import socket

import utils
import msg_utils


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("184.155.9.47", 8333))

sock.send(msg_utils.getVersionMsg())

while 1:
    sock.recv(1000) # Throw away data
    print('got packet')
    
