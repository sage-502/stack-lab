# Debugging Note

gdb에서 syscall orw의 동작을 확인한다.

이를 위해 `vuln()` 의 ret와  `syscall_gadget ()`의 int 0x80에 break point를 걸었다.

---

payload 입력 시 vuln() 리턴 후 gadget으로 이동:
```
Breakpoint 1, 0x08049210 in vuln ()
(gdb) ni
0x080491c3 in ROP_bank ()
```

syscall open 직전:
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

# 여기서부터

```
Breakpoint 2, 0x080491b0 in syscall_gadget ()
(gdb) ni
0x080491b2 in syscall_gadget ()
(gdb) info reg
eax            0xfffffff3          -13
ecx            0x0                 0
edx            0x0                 0
ebx            0x804c008           134529032
esp            0xff9064f0          0xff9064f0
ebp            0x41414141          0x41414141
esi            0x3e8               1000
edi            0xee6ceb60          -294851744
eip            0x80491b2           0x80491b2 <syscall_gadget+12>
eflags         0x282               [ SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) 
```

syscall read 직전:
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
esi            0x3e8               1000
edi            0xf0bc7b60          -256083104
eip            0x80491b0           0x80491b0 <syscall_gadget+10>
eflags         0x286               [ PF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
```

```
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x278ddcd1 in ?? ()
```

---

