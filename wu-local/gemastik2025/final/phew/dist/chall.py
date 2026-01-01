#!/usr/bin/env python3

import signal
from Pailier import *
from Crypto.Util.number import *
signal.alarm(50)
with open("/flag.txt", "rb") as f:
    flag = f.read()
flag = bytes_to_long(flag)
cipher = pailier()
while True:
    print("1. encrypt")
    print("2. bingo")
    print("3. decrypt")
    print("4. exit")
    inp = int(input("> "))
    if inp==1:
        print("pt (hex)")
        inp = input("> ")
        ct = cipher.encrypt(int(inp,16))
        print('ct : ','{0:x}'.format(ct))
    elif inp==2:
        ct = cipher.encrypt(flag)
        print('ct : ','{0:x}'.format(ct))
    elif inp==3:
        print("ct (hex)")
        inp = input("> ")
        pt = cipher.decrypt(int(inp,16))
        print('pt : ','{0:x}'.format(pt))
    else:
        exit()
