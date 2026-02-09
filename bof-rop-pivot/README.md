# bof-rop-pivot

## 1. 개요

이 실습은 **Stack Buffer Overflow**를 이용해
**stack pivot 이후 syscall ROP 체인으로 flag 파일을 출력**하는 것을 목표로 한다.

* 쉘 획득 X
* libc 함수 호출 X
* syscall만 사용한 ORW(Open–Read–Write) ROP
* 권한 설정(setregid) 역시 syscall을 사용


---

## 2. 실습 환경

* Architecture: x86 (32-bit)
* OS: Linux
* NX: Enabled
* PIE: Disabled
* ASLR: Enabled
* RELRO: Full
* Stack Canary: Disabled
* Binary: setgid

---

## 3. 취약 코드

```c
void vuln() {
    char buf[64];
    puts("input:");
    read(0, buf, 400);   // stack buffer overflow
}
```

* `read`로 인해 **saved EBP / saved RET overwrite 가능**
* NX가 켜져 있어 **쉘코드 주입 불가**
* 스택 공간이 제한적이므로 **긴 ROP 체인을 직접 쌓기 어려움**

---

## 4. 공격 전체 흐름 요약

1. **BOF로 saved EBP / RET 덮기**
2. `leave; ret`를 이용해 **stack pivot**
3. `.bss(stage)` 영역을 **가짜 스택(fake stack)** 으로 사용
4. syscall ROP로:
   * 권한 정렬 (`getegid → setregid`)
   * ORW (`open → read → write`)
5. flag 출력

---

## 5. 왜 Stack Pivot이 필요한가?

기존 스택에는 다음과 같은 문제가 있다.

* ROP 체인이 길어짐 (권한 세팅 + ORW)
* saved RET 이후 공간이 충분하지 않음
* 상위 스택 프레임(main 등)을 침범할 위험

따라서 :

* **saved EBP를 `.bss(stage)` 주소로 덮고**
* `leave; ret`를 실행시켜
* **ESP를 stage로 이동**

이렇게 stage 영역을 **스택처럼 사용**한다.

---

## 6. Stage 구조

```
stage:
+0x00  fake EBP
+0x04  첫 ROP gadget
+0x08  다음 gadget
...
+0x300 "/tmp/bof-rop-pivot/flag\x00"
+0x400 read buffer
```

* 코드(ROP 체인)와 데이터(flag 문자열, buffer)를 분리
* ORW 중 주소 계산이 단순해짐

---

## 7. 권한 세팅이 필요한 이유

flag 파일의 권한은 다음과 같다.

```
-rw-r-----  root root flag
```

바이너리는 `setgid`이므로:

* `egid = root`
* `rgid = 사용자 그룹`

이 상태에서는 `open(flag)`가 실패할 수 있다.

따라서 syscall ROP로 다음을 수행한다.

```c
egid = getegid();
setregid(egid, egid);
```

### 사용한 syscall 번호 (x86 32bit)

| syscall  | 번호 |
| -------- | -- |
| getegid  | 50 |
| setregid | 71 |
| open     | 5  |
| read     | 3  |
| write    | 4  |

---

## 8. ORW syscall ROP

### open

```c
fd = open("/tmp/bof-rop-pivot/flag", O_RDONLY, 0);
```

### read

```c
read(fd, BUF, 0x40);
```

### write

```c
write(1, BUF, 0x40);
```

* `open`의 리턴값(fd)을 `eax`에서 `ebx`로 전달
* libc 함수 호출 없이 `int 0x80`만 사용

---

## 9. 익스플로잇 결과

```bash
$ (python3 payload.py) | ./vuln
input:
flag{cat_can_do_ROP^._.^}
Segmentation fault
```

* flag 출력 성공
* 이후 ROP 체인 종료로 인한 segfault는 정상적인 동작

---

## 10. 정리

이 실습을 통해 다음을 학습할 수 있다.

* stack pivot의 필요성과 동작 원리
* fake stack 구성 방법
* syscall 기반 ROP 체인 설계
* 권한 문제를 고려한 실제 공격 흐름
* ORW(Open–Read–Write)의 정확한 의미

> **이 문제는 ROP 가젯 퍼즐이 아니라,
> 공격 흐름과 메모리 모델을 이해하는 데 초점을 둔다.**






## 부록 : pivot 흐름

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
