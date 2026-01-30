# fsb-canary-leak

## 1. 개요

Stack Canary는 스택 버퍼 오버플로우로 saved RET이 덮이는 것을 감지해 프로그램을 종료시키는 보호기법이다.</br>
이번 실습에서는 canary 값을 leak한 뒤, overflow payload에 canary를 복원하여 RET overwrite를 성공시키는 것이 목표다.

이를 위해 우선 canary가 무엇이며, 어디에 저장되고 어떻게 검사되는지 알아본다.

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

---

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

## 5. FSB를 통한 Canary Leak
