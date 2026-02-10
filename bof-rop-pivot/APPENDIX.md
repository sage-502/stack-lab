# 부록 : pivot 흐름, ORW 실제 레지스터 값 확인

이 부록은 stack pivot과 syscall ROP의 실제 동작을 
GDB를 통해 단계별로 확인한 기록이다.</br>
개념 설명은 README 본문을 참고한다.

---

## 1. vuln함수

### 1.1 vuln 실행 중간

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

### 1.2 vuln 에필로그

#### leave

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

#### ret

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

---

## 2. read@plt : 스택으로 사용할 곳에 값 입력

### 2.1 read 중간

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


### 2.2 read 종료

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

---

## 3. leave;ret gadget : pivot 핵심

여기에서 esp를 stage로 이동시킴.

#### leave

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

#### ret

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

---

## 4. GDB로 ORW 레지스터 확인

### 4.1 setregid(getregid(), getregid())

```
(gdb) info reg
eax            0x47                71
ecx            0x3e8               1000  //setgid 비트가 무시되어 0 외의 값이 egid 로 나옴
edx            0x800               2048
ebx            0x3e8               1000
esp            0x804c064           0x804c064 <stage+36>
ebp            0xdeadbeef          0xdeadbeef
eip            0x8049190           0x8049190 <syscall_gadget+10>
```

### 4.2 open("/tmp/bof-rop-pivot/flag", O_RDONLY, 0);

```asm
eax = 5
ebx = &"/tmp/bof-rop-pivot/flag"
ecx = 0
edx = 0
int 0x80
# eax = fd
```

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

### 4.3 read(fd, BUF, 0x40);

```asm
eax = 3
ebx = fd
ecx = BUF
edx = 0x40
int 0x80
```

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

권한 문제로 실패, fd(ebx)로 음수가 반환됨.
