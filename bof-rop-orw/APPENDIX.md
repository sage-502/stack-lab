# Debugging Note

gdb에서 syscall orw의 동작을 확인한다.

이를 위해 `vuln()` 의 ret와  `syscall_gadget()`의 int 0x80에 break point를 걸었다.

---

### payload 입력 시 vuln() 리턴 직후:
```
Breakpoint 1, 0x08049210 in vuln ()
(gdb) ni
0x080491c3 in ROP_bank ()      // ROP 체인의 첫 번째 gadget이 실행됨.
```

### syscall open 직전:
```
(gdb) c
Continuing.

Breakpoint 2, 0x080491b0 in syscall_gadget ()
(gdb) info reg
eax            0x5                 5
ecx            0x0                 0
edx            0x0                 0
ebx            0x804c008           134529032
esp            0xffe7a230          0xffe7a230
ebp            0x41414141          0x41414141
eip            0x80491b0           0x80491b0 <syscall_gadget+10>
```

### syscall open 직후:
```
(gdb) ni
0x080491b2 in syscall_gadget ()
(gdb) info reg
eax            0xfffffff3          -13        // gdb 내에서는 setgid bit 가 무시되어 flag를 읽을 수 없음
ecx            0x0                 0
edx            0x0                 0
ebx            0x804c008           134529032
esp            0xff9064f0          0xff9064f0
ebp            0x41414141          0x41414141
eip            0x80491b2           0x80491b2 <syscall_gadget+12>
```

### syscall read 직전:
```
(gdb) c
Continuing.

Breakpoint 2, 0x080491b0 in syscall_gadget ()
(gdb) info reg
eax            0x3                 3
ecx            0x804c040           134529088
edx            0x28                40
ebx            0xfffffff3          -13
esp            0xffe7a250          0xffe7a250
ebp            0x41414141          0x41414141
eip            0x80491b0           0x80491b0 <syscall_gadget+10>
```

### syscall write 이후:
```
(gdb) c
Continuing.

Breakpoint 2, 0x080491b0 in syscall_gadget ()
(gdb) info reg
eax            0x4                 4
ecx            0x804c040           134529088
edx            0x28                40
ebx            0x1                 1
esp            0xffe7a274          0xffe7a274
ebp            0x41414141          0x41414141
eip            0x80491b0           0x80491b0 <syscall_gadget+10>
```

### syscall write 직후:
```
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x278ddcd1 in ?? ()
```
마지막 gadget 이후 스택의 쓰레기 값을 읽어 segmentation fault로 종료됨. 
