1. vuln함수

중간:
```
read(0, buf, 400); //bof 
// 1) saved ebp를 stage_addr로, saved ret를 read@plt로 변경
// 2) leave_ret 가젯
// 3) read@plt의 인자(0, stage_addr, 0x800) 세팅
```

스택 프레임
```
[높은주소]
saved ret: read@plt
saved ebp: stage_addr <- ebp(vuln의 base)
...
buf
[낮은주소]
```

에필로그:
```
leave 
// mov esp, ebp -> esp = vuln의 base
// pop ebp -> ebp = stage_addr
ret 
// pop eip -> eip = read@plt
// jmp eip -> read@plt로 이동
```
따라서 vuln 직후: ebp = stage_addr, esp = vuln의 ebp(이후 libc read의 스택 프레임으로 이동함)

---

2. read@plt
```
[높은주소]
arg3: 0x800
arg2: stage_addr
arg1: 0
saved ret: leave_ret
(libc read의 스택 프레임)
[낮은주소]
```
stage에 ROP 체인 입력:
```
+0x00 fake_ebp        ← pop ebp 용
+0x04 gadget_addr     ← ret이 점프할 곳
+0x08 다음 값
...
```

libc read 종료:
```
ret // eip = leave_ret
```
따라서 read 직후: 
- eip = leave_ret
- ebp는 vuln 직후로 복구됨 = stage_addr
- esp는 read의 base(추정)

---

3. leave_ret
```
[높은주소]
...
[stage_addr + 8]
[stage_addr + 4]
[stage_addr] <- ebp
[낮은주소]
```

```
leave 
// mov esp, ebp -> esp = ebp = stage_addr
// pop ebp -> ebp = *(stage_addr)
ret 
// pop eip = stage = *(stage_addr + 4)
```

따라서 ebp = *(stage_addr) , eip = *(age_addr + 4), esp = stage_addr + 8

이때 stage 상태
```
[높은주소]
...
[stage_addr + 8] : gadget이 pop할 값들 <- esp
[stage_addr + 4] : gadget_addr = eip
[stage_addr] : fake ebp = ebp
[낮은주소]
```
